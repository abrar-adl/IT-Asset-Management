# IT-Asset-Management/assets/views.py

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Asset, ScanLog, RiskScanResult
# CORRECTED IMPORT: Import NetworkScanner class and save_asset_data function
from .network_scanner import NetworkScanner, save_asset_data, scan_host_services 

from .risk_assessment import assess_all_assets
from .reports import generate_asset_report
from datetime import date
from django.contrib.auth.decorators import login_required
from .forms import CustomUserCreationForm
from django.contrib.auth import login
from django.contrib.auth.views import LoginView
import threading
from django.utils.timesince import timesince


@login_required
def dashboard(request):
    selected_network = request.GET.get('network_range')
    if request.user.is_staff:
        networks = Asset.objects.values_list('network_range', flat=True).distinct()
    else:
        networks = []    
    
    # CORRECTED CALL: Use NetworkScanner.get_available_networks()
    # This returns a list, so we take the first one or default to an empty string.
    all_available_networks = NetworkScanner.get_available_networks()
    current_subnet = all_available_networks[0] if all_available_networks else ''


    if selected_network:
        assets = Asset.objects.filter(network_range=selected_network)
    else:
        assets = Asset.objects.all()

    asset_types = {}
    for asset in assets:
        asset_types[asset.asset_type] = asset_types.get(asset.asset_type, 0) + 1

    return render(request, 'assets/dashboard.html', {
        'assets': assets,
        'asset_types': asset_types,
        'asset_count': assets.count(),
        'networks': networks,
        'selected_network': selected_network,
        'current_subnet': current_subnet, # Pass the adjusted subnet
        
    })


def start_background_risk_assessment():
    def run():
        assess_all_assets(store=True)
    threading.Thread(target=run).start()


def run_risk_scan(request):
    if request.method == 'POST':
        start_background_risk_assessment()
        messages.success(request, "✅ Background risk scan started. Please refresh later.")
    return redirect('risk_dashboard')


@login_required
def run_scan(request):
    if request.method == 'POST':
        network_range = request.POST.get('network_range', '').strip()
        scan_type = request.POST.get('scan_type', 'quick')
        
        try:
            discovered_assets_for_saving = [] # Initialize a list to hold all discovered assets
            saved_count = 0 # Initialize a counter for saved assets

            if scan_type == 'multi':
                # Multiple networks from textarea
                networks = [n.strip() for n in network_range.split('\n') if n.strip()]
                if not networks:
                    messages.error(request, 'Please provide at least one network range')
                    return redirect('/')
                
                # CORRECTED CALL: Use NetworkScanner.parallel_network_scan()
                discovered_assets_for_saving = NetworkScanner.parallel_network_scan(networks) 
                
                # NOW SAVE THE DISCOVERED ASSETS
                saved_count = save_asset_data(discovered_assets_for_saving)
                
                messages.success(request, f'Multi-network scan completed! Found and saved {saved_count} devices across {len(networks)} networks.')
            
            else:
                # Single network (quick scan)
                if not network_range:
                    # CORRECTED CALL: Use NetworkScanner.get_available_networks() if auto-detect
                    all_available_networks = NetworkScanner.get_available_networks()
                    network_range = all_available_networks[0] if all_available_networks else "192.168.1.0/24" # Provide a default fallback


                # CORRECTED CALL: Use NetworkScanner.scan_network()
                discovered_assets_for_saving = NetworkScanner.scan_network(network_range)
                
                # NOW SAVE THE DISCOVERED ASSETS
                saved_count = save_asset_data(discovered_assets_for_saving)

                network_display = network_range or "auto-detected network"
                messages.success(request, f'Network scan completed on {network_display}! Found and saved {saved_count} devices.')
            
            # Log the scan AFTER saving the assets
            ScanLog.objects.create(
                network_range=network_range if scan_type != 'multi' else "multiple networks", # Adjust for multi-network display
                found_devices=saved_count # Log the number of assets actually saved
            )

        except Exception as e:
            messages.error(request, f'Scan failed: {str(e)}')
    
    return redirect('/')

@login_required
def network_management(request):
    """New view for managing multiple networks"""
    networks = Asset.objects.values_list('network_range', flat=True).distinct()
    network_stats = []
    
    for network in networks:
        if network:
            asset_count = Asset.objects.filter(network_range=network).count()
            latest_scan = ScanLog.objects.filter(network_range=network).order_by('-timestamp').first()
            network_stats.append({
                'network': network,
                'asset_count': asset_count,
                'last_scan': latest_scan.timestamp if latest_scan else None
            })
    
    return render(request, 'assets/network_management.html', {
        'network_stats': network_stats,
        'total_networks': len(networks)
    })

@login_required
def risk_dashboard(request):
    # Load all existing risk results
    scan_results = RiskScanResult.objects.select_related('asset').all()

    if not scan_results:
        messages.info(request, "No risk results yet. Run a scan or refresh later.")
    
    # Count risk levels
    risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for r in scan_results:
        risk_counts[r.risk_level] += 1

    # Get the latest scan time (added part)
    latest_scan = RiskScanResult.objects.order_by('-scanned_at').first()
    last_scan_time = timesince(latest_scan.scanned_at) if latest_scan else None


    # Render with context
    return render(request, 'assets/risk_dashboard.html', {
        'risk_results': scan_results,
        'risk_counts': risk_counts,
        'high_risk_assets': [r for r in scan_results if r.risk_level == 'HIGH'],
        'last_scan_time': last_scan_time    # pass to template
    })

@login_required
def reports(request):
    report_data = generate_asset_report()
    return render(request, 'assets/reports.html', report_data)

@login_required
def lifecycle_dashboard(request):
    today = date.today()
    expiring_soon = Asset.objects.filter(warranty_expiration__isnull=False, warranty_expiration__lte=today.replace(year=today.year + 1))
    overdue_replacement = Asset.objects.filter(replacement_due__isnull=False, replacement_due__lte=today)

    context = {
        'expiring_warranties': expiring_soon,
        'overdue_replacements': overdue_replacement,
    }
    return render(request, 'assets/lifecycle.html', context)

def scan_history(request):
    logs = ScanLog.objects.order_by('-timestamp')
    return render(request, 'assets/scan_history.html', {'logs': logs})


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)    # 🔐 Auto-login
            messages.success(request, "✅ Account created and you're now logged in!")
            return redirect('risk_dashboard')   # Or whatever page you prefer
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})


class CustomLoginView(LoginView):
    """
    Custom login view that supports a 'remember me' option.
    If 'remember me' is checked, the session persists for 2 weeks; otherwise, it expires on browser close.
    """
    template_name = 'login.html'

    def form_valid(self, form):
        remember_me = self.request.POST.get('remember_me', '').strip().lower()

        if remember_me != 'on':
            self.request.session.set_expiry(0)    # Session expires when browser closes (Django default behavior)
        else:
            self.request.session.set_expiry(1209600)    # 2 weeks

        return super().form_valid(form)


# Simple background wrapper
def start_background_risk_assessment():
    def run():
        assess_all_assets(store=True)    # We'll modify assess_all_assets to store instead of return
    threading.Thread(target=run).start()