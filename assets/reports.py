# IT-Asset-Management/assets/reports.py
from django.http import HttpResponse
from django.template.loader import render_to_string
from .risk_assessment import assess_all_assets
import json
from .models import Asset, RiskScanResult

def generate_asset_report():
    """Generate comprehensive asset report using stored scan results (no live scanning)"""
    assets = Asset.objects.all()
    risk_results_qs = RiskScanResult.objects.select_related('asset').all()

    # Build a list of dicts similar to what was returned by assess_all_assets
    risk_results = []
    for rr in risk_results_qs:
        risk_results.append({
            'asset': rr.asset,
            'risk_score': rr.risk_score,
            'risk_level': rr.risk_level,
            'vulnerabilities': rr.vulnerabilities,
        })
    # Asset statistics
    total_assets = assets.count()
    asset_types = {}
    for asset_type, _ in Asset.ASSET_TYPES:
        asset_types[asset_type] = assets.filter(asset_type=asset_type).count()
    
    # Risk statistics
    risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for result in risk_results:
        risk_counts[result['risk_level']] += 1
    
    # Top vulnerabilities
    all_vulns = []
    for result in risk_results:
        all_vulns.extend(result['vulnerabilities'])
    
    from collections import Counter
    top_vulns = Counter(all_vulns).most_common(5)
    
    report_data = {
        'total_assets': total_assets,
        'asset_types': asset_types,
        'risk_counts': risk_counts,
        'top_vulnerabilities': top_vulns,
        'high_risk_assets': [r for r in risk_results if r['risk_level'] == 'HIGH'],
        'assets': assets,
        'risk_results': risk_results
    }
    
    return report_data


def export_json_report(request):
    """Export report as JSON"""
    report_data = generate_asset_report()
    
    # Convert to JSON-serializable format
    json_data = {
        'total_assets': report_data['total_assets'],
        'asset_types': report_data['asset_types'],
        'risk_counts': report_data['risk_counts'],
        'top_vulnerabilities': report_data['top_vulnerabilities'],
        'assets': [
            {
                'name': asset.name,
                'type': asset.asset_type,
                'ip': asset.ip_address,
                'manufacturer': asset.manufacturer,
                'status': asset.status
            } for asset in report_data['assets']
        ]
    }
    
    response = HttpResponse(
        json.dumps(json_data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = 'attachment; filename="asset_report.json"'
    return response
