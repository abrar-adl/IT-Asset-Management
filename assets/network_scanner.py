# IT-Asset-Management/assets/network_scanner.py

from django.utils import timezone # Crucial: Ensure this is 'django.utils.timezone'
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import os
from contextlib import closing
from typing import List, Tuple, Optional

import nmap
from .models import Asset, DetectedService, ScanLog # Ensure this is uncommented

class NetworkScanner:
    _cached_local_subnet = None # Cache for efficiency

    @classmethod
    def get_local_ip(cls) -> Optional[str]:
        """Attempt to find the local machine's primary IPv4 address."""
        # This is a simplified approach; in complex networks, it might need refinement.
        try:
            # Create a socket and connect to an external address
            # (doesn't actually send data, just finds the interface IP)
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
                s.connect(("8.8.8.8", 80)) # Google's DNS server
                return s.getsockname()[0]
        except socket.error:
            # Fallback for systems where connecting to external IP isn't suitable or fails
            # This is a very basic fallback for common local IPs
            try:
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                if ip_address.startswith(('192.168.', '10.', '172.16.')):
                    return ip_address
            except Exception as e:
                print(f"Error getting local IP via hostname: {e}")
            return None

    @classmethod
    def get_available_networks(cls) -> List[str]:
        """
        Attempts to find available local network ranges (e.g., 192.168.1.0/24)
        by inspecting local IP addresses.
        """
        local_networks = []
        try:
            local_ip = cls.get_local_ip()
            if local_ip:
                # Use a common subnet mask (/24) for simplicity with local IP
                # This might need refinement for different network configurations
                try:
                    network_obj = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                    local_networks.append(str(network_obj))
                except ValueError:
                    print(f"Could not derive /24 network from {local_ip}")

            # Add common private IP ranges as potential defaults if no local IP found
            # or if more options are desired. Remove duplicates by converting to set then list.
            common_private_ranges = [
                "192.168.1.0/24", "192.168.0.0/24",
                "10.0.0.0/24", "172.16.0.0/24",
                "192.168.56.0/24" # From your ipconfig output
            ]
            
            # Combine and remove duplicates
            local_networks.extend(common_private_ranges)
            local_networks = list(dict.fromkeys(local_networks)) # Python 3.7+ preserves order while removing duplicates

        except Exception as e:
            print(f"Error detecting local networks: {e}")
        return local_networks


    @classmethod
    def scan_network(cls, network_range: Optional[str] = None) -> List[dict]:
        """
        Performs a network scan using nmap and returns a list of dictionaries
        representing discovered devices. This is the primary function for host discovery.
        """
        if not network_range:
            # Attempt to auto-detect if no network range is provided
            available_networks = cls.get_available_networks()
            if available_networks:
                network_range = available_networks[0] # Use the first detected network
            else:
                # Fallback to a default if no networks are detected
                network_range = "192.168.1.0/24"
                print("Warning: No network range provided and auto-detection failed. Defaulting to 192.168.1.0/24")

        print(f"Starting network scan on {network_range}...")
        nm = nmap.PortScanner()
        discovered_devices = []

        try:
            # -sn: Ping scan - disable port scan, just host discovery
            # -T4: Faster execution
            # -n: No DNS resolution (faster)
            nm.scan(hosts=network_range, arguments='-sn -T4 -n')

            for host in nm.all_hosts():
                # Ensure it has an IPv4 address, which it should if it's in all_hosts() from -sn
                if 'ipv4' in nm[host]['addresses']:
                    ip_address = nm[host]['addresses']['ipv4']
                    
                    # Get MAC address, default to empty string if not found
                    mac_address = nm[host]['addresses'].get('mac', '') 

                    # Get hostname, default to empty string
                    hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else ''
                    
                    # Get manufacturer - only if MAC exists and vendor info is available
                    manufacturer = 'Unknown'
                    if mac_address and 'vendor' in nm[host] and mac_address in nm[host]['vendor']:
                        manufacturer = nm[host]['vendor'][mac_address]

                    # Services are typically not discovered with -sn scan.
                    # This list will be empty for this type of scan.
                    services = [] 

                    # Log what we found for debugging
                    if mac_address:
                        print(f"✅ Found {ip_address} with MAC {mac_address} ({manufacturer})")
                    else:
                        print(f"✅ Found {ip_address} (no MAC address - likely router/gateway/VM)")

                    discovered_devices.append({
                        'name': hostname or f'Device-{ip_address}', # Use hostname if available, else generic name
                        'ip_address': ip_address,
                        'mac_address': mac_address,
                        'manufacturer': manufacturer,
                        'network_range': network_range, # Add network_range to asset data
                        'asset_type': 'workstation', # Default, can be refined later if needed
                        'status': 'active', # Default, can be refined
                        'discovered_date': timezone.now(), # Use Django's timezone
                        'services': services # Will be empty for -sn scan, but needed for save_asset_data
                    })
            print(f"Network scan found {len(discovered_devices)} devices.")
            return discovered_devices

        except nmap.PortScannerError as e:
            print(f"Nmap scan error: {e}")
            return []
        except Exception as e:
            print(f"An unexpected error occurred during scan: {e}")
            return []

    # Keeping scan_services_aggressive and parallel_network_scan within the class
    # as they were in your provided snippet, though their interaction with save_asset_data
    # might need separate consideration if they are meant to save assets directly.
    # For now, scan_network is the primary asset discovery method.

    @staticmethod
    def check_host_connectivity(ip: str, timeout: int = 2) -> Tuple[bool, str]:
        """Quick connectivity check before detailed scanning."""
        try:
            # Method 1: TCP connect to common ports
            common_ports = [80, 443, 22, 135, 139, 445, 3389]
            for port in common_ports:
                try:
                    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                        sock.settimeout(timeout)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            return True, f"Port {port} open"
                except:
                    continue
            
            # Method 2: Ping if TCP fails (using platform-specific commands)
            ping_cmd = ['ping', '-n', '1', '-w', '1000', ip] if os.name == 'nt' else ['ping', '-c', '1', '-W', '1', ip]
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                return True, "Ping successful"
                
            return False, "No response"
            
        except Exception as e:
            return False, f"Check failed: {e}"

    @staticmethod
    def scan_services_aggressive(ip: str, quick_mode: bool = False) -> List[dict]: # Changed return type to List[dict] for consistency
        """
        Performs an Nmap-based service scan on a single IP address.
        Returns a list of dictionaries for discovered services.
        """
        print(f"🔍 Scanning {ip} for services...")
        
        is_up, status = NetworkScanner.check_host_connectivity(ip)
        if not is_up:
            print(f"⚠️ {ip} appears down: {status}")
            return []
        
        print(f"✅ {ip} is reachable: {status}")
        
        # Choose scan intensity based on mode
        if quick_mode:
            # Increased version intensity for quick_mode to get more accurate product/version
            nmap_args = ['-Pn', '-sV', '-sC', '--top-ports', '100', '--version-intensity', '7']
        else:
            nmap_args = ['-Pn', '-sV', '-sC', '--top-ports', '1000', '--version-intensity', '9', '-A'] # -A for aggressive features
        
        try:
            cmd = ['nmap'] + nmap_args + ['-oX', '-', ip] # -oX - outputs XML to stdout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90) # Increased timeout
            
            if result.returncode != 0:
                print(f"⚠️ Nmap returned error code {result.returncode}. Stderr: {result.stderr.strip()}")
                if "nmap: command not found" in result.stderr.lower():
                    print("Hint: Nmap is not installed or not in your PATH. Please install Nmap.")
                return []
            
            # Use the existing parse_nmap_xml but ensure it returns dicts
            services = NetworkScanner.parse_nmap_xml_to_dicts(result.stdout, ip) # Use new parsing method
            
            if not services and not quick_mode: # Only try UDP fallback if not in quick_mode and no TCP services found
                print(f"🔄 No TCP services found for {ip}, trying UDP scan...")
                udp_cmd = ['nmap', '-Pn', '-sU', '--top-ports', '20', '-oX', '-', ip]
                udp_result = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=45)
                if udp_result.returncode == 0:
                    udp_services = NetworkScanner.parse_nmap_xml_to_dicts(udp_result.stdout, ip) # Use new parsing method
                    services.extend(udp_services)
            
            return services
            
        except subprocess.TimeoutExpired:
            print(f"⏰ Scan timeout for {ip}. Consider increasing timeout.")
            return []
        except FileNotFoundError:
            print(f"❌ Nmap not found. Please ensure Nmap is installed and accessible in your system's PATH.")
            return []
        except Exception as e:
            print(f"❌ Scan error for {ip}: {e}")
            return []

    @staticmethod
    def parse_nmap_xml_to_dicts(xml_output: str, ip: str) -> List[dict]: # New parsing method, returns list of dicts
        """Parses Nmap XML output to extract service details as dictionaries."""
        services = []
        
        try:
            if not xml_output or not xml_output.strip():
                print(f"⚠️ Empty or invalid Nmap XML output for {ip}. Check Nmap installation and permissions.")
                return []
            
            root = ET.fromstring(xml_output)
            
            for host in root.findall('host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'down':
                    print(f"⚠️ Host {ip} reported as down by Nmap during XML parsing. No services extracted.")
                    continue
                
                ports = host.find('ports')
                if ports is not None:
                    for port_elem in ports.findall('port'): # Renamed to avoid conflict with 'port' in service_info
                        state = port_elem.find('state')
                        if state is not None and state.get('state') in ['open', 'open|filtered']:
                            service_elem = port_elem.find('service')
                            if service_elem is not None:
                                product = service_elem.get('product', service_elem.get('name', 'Unknown'))
                                version = service_elem.get('version', '')
                                portid = port_elem.get('portid')
                                protocol = port_elem.get('protocol', 'tcp')
                                
                                services.append({
                                    'product': product,
                                    'version': version,
                                    'port': portid,
                                    'protocol': protocol
                                })
                                print(f"  ✅ Detected: {product} {version} on port {portid}/{protocol}")
            
            return services
            
        except ET.ParseError as e:
            print(f"⚠️ XML parsing error for {ip}: {e}. Raw XML may be malformed.")
            return []
        except Exception as e:
            print(f"⚠️ Unexpected parsing error for {ip}: {e}. Ensure XML structure is valid.")
            return []

    @classmethod
    def parallel_network_scan(cls, network_ranges: List[str], max_workers: int = 10) -> List[dict]: # Changed return type to List[dict]
        """
        Scans multiple network ranges for active hosts and their services in parallel.
        This function now aggregates results from scan_network, not scan_services_aggressive.
        """
        all_discovered_devices = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_range = {executor.submit(cls.scan_network, nr): nr for nr in network_ranges}
            
            for future in as_completed(future_to_range):
                nr = future_to_range[future]
                try:
                    results = future.result()
                    all_discovered_devices.extend(results)
                    print(f"Scan for {nr} completed. Found {len(results)} devices.")
                except Exception as e:
                    print(f"Scan for {nr} failed: {e}")
        
        return all_discovered_devices

# --- Global functions for saving and single host service scanning ---
# These remain outside the class as they interact directly with Django models
# or are wrappers for class methods.

def save_asset_data(discovered_assets: List[dict]) -> int:
    """
    Saves or updates Asset models based on discovered network devices.
    Now handles assets without MAC addresses properly.
    """
    saved_count = 0
    for device_data in discovered_assets:
        ip_address = device_data.get('ip_address')
        if not ip_address:
            print(f"Skipping device due to missing IP address: {device_data}")
            continue

        # Set a default name if hostname is not available
        name = device_data.get('name', f"Device-{ip_address}") # Use 'name' from device_data, fallback to hostname, then generic
        
        # Handle empty MAC addresses
        mac_address = device_data.get('mac_address', '')
        
        # Infer asset type based on IP and MAC presence (simplified for initial discovery)
        asset_type = device_data.get('asset_type', 'workstation') # Use asset_type from scan_network, fallback
        if not mac_address:
            # Refine asset_type inference if MAC is missing (e.g., router/gateway)
            if ip_address.endswith('.1') or ip_address.endswith('.254'): # Common gateway IPs
                asset_type = 'network_device' 
            elif device_data.get('asset_type') == 'workstation': # Only change if default, not if specifically set
                asset_type = 'server_or_vm' # More generic if not workstation/network_device
        
        try:
            asset, created = Asset.objects.update_or_create(
                ip_address=ip_address,
                defaults={
                    'name': name,
                    'mac_address': mac_address,
                    'manufacturer': device_data.get('manufacturer', 'Unknown'),
                    'network_range': device_data.get('network_range', 'unknown'), # Ensure this is passed
                    'asset_type': asset_type,
                    'status': device_data.get('status', 'active'),
                    'discovered_date': device_data.get('discovered_date', timezone.now()),
                    'model': device_data.get('model', ''),
                    'serial_number': device_data.get('serial_number', ''),
                    'location': device_data.get('location', ''),
                }
            )
            
            if created:
                saved_count += 1
                if mac_address:
                    print(f"✅ New asset discovered and saved: {asset.name} ({asset.ip_address}) MAC: {mac_address}")
                else:
                    print(f"✅ New asset discovered and saved: {asset.name} ({asset.ip_address}) [No MAC - inferred as {asset_type}]")
            else:
                print(f"🔄 Existing asset updated: {asset.name} ({asset.ip_address})")

            # Save detected services for the asset (if any were discovered by service scan)
            for service_data in device_data.get('services', []):
                DetectedService.objects.update_or_create(
                    asset=asset,
                    product=service_data.get('product', 'Unknown'),
                    version=service_data.get('version', ''),
                    port=service_data.get('port'),
                    protocol=service_data.get('protocol'),
                    defaults={
                        'scanned_at': timezone.now() # Update timestamp on save
                    }
                )

        except Exception as e:
            print(f"Error saving asset {ip_address}: {e}")
    return saved_count


def scan_host_services(ip: str, quick_mode: bool = False) -> List[dict]:
    """
    A convenient wrapper to perform detailed service scanning on a single host.
    This is the function that risk_assessment.py should import and call.
    """
    return NetworkScanner.scan_services_aggressive(ip, quick_mode)