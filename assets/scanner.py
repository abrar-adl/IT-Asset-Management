import subprocess
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import subprocess
import socket
import netiface
import ipaddress
from typing import Optional

def get_local_subnet() -> str:
    """
    Automatically detect the local subnet range
    Returns the network range in CIDR notation (e.g., '192.168.1.0/24')
    """
    try:
        # Method 1: Use netifaces to get network interfaces
        try:
            
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            
            # Get IP and netmask for this interface
            addrs = netifaces.ifaddresses(default_interface)
            ip_info = addrs[netifaces.AF_INET][0]
            
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Convert to network range
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
            
        except (ImportError, KeyError, IndexError):
            # Method 2: Use socket to get local IP, assume /24
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Assume /24 subnet (most common)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)
            
    except Exception as e:
        print(f"⚠️ Could not auto-detect subnet: {e}")
        # Fallback to common private ranges
        return "192.168.1.0/24"

def quick_scan(network_range: str = None, max_hosts: int = 50) -> list:
    """
    Quick network scan - lighter version of the full adaptive scan
    """
    if not network_range:
        network_range = get_local_subnet()
    
    print(f"🔍 Quick scan of {network_range}")
    
    # Use simplified TCP connect scan for speed
    network = ipaddress.IPv4Network(network_range, strict=False)
    host_ips = [str(ip) for ip in network.hosts()][:max_hosts]
    
    # Common ports for quick detection
    quick_ports = [22, 80, 443, 135, 139, 445, 3389]
    
    results = []
    
    def check_host(ip: str) -> dict:
        """Quick check if host is alive"""
        open_ports = []
        
        for port in quick_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        if open_ports:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = f"Device-{ip}"
                
            return {
                'ip': ip,
                'hostname': hostname,
                'open_ports': open_ports,
                'status': 'active'
            }
        return None
    
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_host, ip) for ip in host_ips]
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except:
                pass
    
    print(f"✅ Quick scan found {len(results)} active hosts")
    return results


@dataclass
class DiscoveredHost:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    open_ports: List[int] = None
    services: List[Tuple[str, str]] = None
    response_methods: List[str] = None
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = []
        if self.response_methods is None:
            self.response_methods = []

class AdaptiveNetworkScanner:
    """Multi-vector network discovery that adapts when traditional methods fail"""
    
    def __init__(self, max_threads=50, timeout=5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.discovered_hosts = {}
        
    def discover_network(self, network_range: str) -> List[DiscoveredHost]:
        """Main discovery method using multiple parallel approaches"""
        print(f"🔍 Starting adaptive discovery of {network_range}")
        
        network = ipaddress.IPv4Network(network_range, strict=False)
        host_ips = [str(ip) for ip in network.hosts()]
        
        # Limit scan size for performance
        if len(host_ips) > 254:
            print(f"⚠️ Large network detected ({len(host_ips)} hosts), limiting to first 254")
            host_ips = host_ips[:254]
        
        # Run multiple discovery methods in parallel
        discovery_methods = [
            self._tcp_connect_sweep,
            self._arp_discovery,
            self._ping_variants,
            self._common_port_knock
        ]
        
        with ThreadPoolExecutor(max_workers=len(discovery_methods)) as executor:
            futures = [executor.submit(method, host_ips) for method in discovery_methods]
            
            for future in as_completed(futures):
                try:
                    method_results = future.result()
                    self._merge_results(method_results)
                except Exception as e:
                    print(f"⚠️ Discovery method failed: {e}")
        
        # Convert to list and enrich with additional data
        hosts = list(self.discovered_hosts.values())
        self._enrich_host_data(hosts)
        
        print(f"✅ Discovery complete: {len(hosts)} hosts found")
        return hosts
    
    def _tcp_connect_sweep(self, host_ips: List[str]) -> Dict[str, DiscoveredHost]:
        """TCP connect scan to common ports - works even when ICMP is blocked"""
        print("🔗 Running TCP connect sweep...")
        results = {}
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5432, 3306]
        
        def check_tcp_port(ip: str, port: int) -> bool:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                return result == 0
            except:
                return False
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip_port = {
                executor.submit(check_tcp_port, ip, port): (ip, port)
                for ip in host_ips for port in common_ports
            }
            
            for future in as_completed(future_to_ip_port):
                ip, port = future_to_ip_port[future]
                try:
                    if future.result():
                        if ip not in results:
                            results[ip] = DiscoveredHost(ip=ip)
                        results[ip].open_ports.append(port)
                        results[ip].response_methods.append('tcp_connect')
                except:
                    pass
        
        print(f"📊 TCP sweep found {len(results)} responsive hosts")
        return results
    
    def _arp_discovery(self, host_ips: List[str]) -> Dict[str, DiscoveredHost]:
        """ARP table inspection - finds hosts that communicated recently"""
        print("🔍 Checking ARP table...")
        results = {}
        
        try:
            # Try different ARP command formats
            arp_commands = [
                ['arp', '-a'],
                ['ip', 'neigh', 'show'],
                ['cat', '/proc/net/arp']
            ]
            
            for cmd in arp_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        arp_output = result.stdout
                        break
                except:
                    continue
            else:
                return results
            
            # Parse ARP entries
            import re
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
            mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
            
            for line in arp_output.split('\n'):
                ip_match = re.search(ip_pattern, line)
                mac_match = re.search(mac_pattern, line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    if ip in host_ips:  # Only include IPs in our target range
                        results[ip] = DiscoveredHost(
                            ip=ip,
                            mac=mac_match.group(0) if mac_match else None
                        )
                        results[ip].response_methods.append('arp')
            
            print(f"📊 ARP discovery found {len(results)} hosts")
            
        except Exception as e:
            print(f"⚠️ ARP discovery failed: {e}")
        
        return results
    
    def _ping_variants(self, host_ips: List[str]) -> Dict[str, DiscoveredHost]:
        """Multiple ping methods for different network configurations"""
        print("🏓 Trying ping variants...")
        results = {}
        
        # Different ping strategies
        ping_methods = [
            ['ping', '-c', '1', '-W', '2'],  # Standard ping
            ['ping', '-c', '1', '-W', '2', '-t', '1'],  # Low TTL
            ['fping', '-c', '1', '-t', '2000']  # Fast ping if available
        ]
        
        def ping_host(ip: str, method: List[str]) -> bool:
            try:
                cmd = method + [ip]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                return result.returncode == 0
            except:
                return False
        
        # Try each ping method
        for method in ping_methods:
            if not results:  # Only try next method if previous found nothing
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_to_ip = {
                        executor.submit(ping_host, ip, method): ip
                        for ip in host_ips
                    }
                    
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            if future.result():
                                results[ip] = DiscoveredHost(ip=ip)
                                results[ip].response_methods.append('ping')
                        except:
                            pass
        
        print(f"📊 Ping variants found {len(results)} hosts")
        return results
    
    def _common_port_knock(self, host_ips: List[str]) -> Dict[str, DiscoveredHost]:
        """Check for common services that might respond even when ping fails"""
        print("🚪 Port knocking common services...")
        results = {}
        
        # Services that often respond uniquely
        service_ports = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            23: 'telnet',
            21: 'ftp',
            25: 'smtp',
            53: 'dns',
            139: 'netbios',
            445: 'smb',
            3389: 'rdp'
        }
        
        def check_service_banner(ip: str, port: int) -> Optional[str]:
            """Try to grab a service banner"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                
                if sock.connect_ex((ip, port)) == 0:
                    # Try to get banner
                    try:
                        if port in [80, 443]:
                            sock.send(b'GET / HTTP/1.0\r\n\r\n')
                        elif port == 22:
                            pass  # SSH sends banner automatically
                        else:
                            sock.send(b'\r\n')
                        
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        sock.close()
                        return banner.strip()[:100]  # First 100 chars
                    except:
                        sock.close()
                        return "Service detected"
                
                sock.close()
                return None
                
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip_port = {
                executor.submit(check_service_banner, ip, port): (ip, port, service)
                for ip in host_ips for port, service in service_ports.items()
            }
            
            for future in as_completed(future_to_ip_port):
                ip, port, service = future_to_ip_port[future]
                try:
                    banner = future.result()
                    if banner:
                        if ip not in results:
                            results[ip] = DiscoveredHost(ip=ip)
                        results[ip].open_ports.append(port)
                        results[ip].services.append((service, banner))
                        results[ip].response_methods.append('banner_grab')
                except:
                    pass
        
        print(f"📊 Port knocking found {len(results)} responsive services")
        return results
    
    def _merge_results(self, new_results: Dict[str, DiscoveredHost]):
        """Merge discovery results from different methods"""
        for ip, host in new_results.items():
            if ip in self.discovered_hosts:
                # Merge data
                existing = self.discovered_hosts[ip]
                existing.open_ports.extend(host.open_ports)
                existing.services.extend(host.services)
                existing.response_methods.extend(host.response_methods)
                
                # Update other fields if not set
                if not existing.hostname and host.hostname:
                    existing.hostname = host.hostname
                if not existing.mac and host.mac:
                    existing.mac = host.mac
                    
                # Remove duplicates
                existing.open_ports = list(set(existing.open_ports))
                existing.services = list(set(existing.services))
                existing.response_methods = list(set(existing.response_methods))
            else:
                self.discovered_hosts[ip] = host
    
    def _enrich_host_data(self, hosts: List[DiscoveredHost]):
        """Add hostname resolution and other enrichment"""
        print("🔍 Enriching host data...")
        
        def resolve_hostname(host: DiscoveredHost):
            if not host.hostname:
                try:
                    host.hostname = socket.gethostbyaddr(host.ip)[0]
                except:
                    pass
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(resolve_hostname, host) for host in hosts]
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

# Integration function for your Django models
def enhanced_network_scan(network_range=None, aggressive=False):
    """Enhanced scanning function that integrates with your existing code"""
    
    if not network_range:
        network_range = get_local_subnet()
    
    scanner = AdaptiveNetworkScanner(
        max_threads=100 if aggressive else 50,
        timeout=10 if aggressive else 5
    )
    
    discovered_hosts = scanner.discover_network(network_range)
    
    # Convert to your existing asset format
    results = []
    for host in discovered_hosts:
        asset_data = {
            'ip': host.ip,
            'hostname': host.hostname or f'Device-{host.ip}',
            'status': 'new',
            'open_ports': host.open_ports,
            'services': host.services,
            'discovery_methods': host.response_methods,
            'mac_address': host.mac
        }
        results.append(asset_data)
        
        # Create/update asset in Django
        try:
            from .models import Asset
            from django.utils import timezone
            import random
            
            asset, created = Asset.objects.get_or_create(
                ip_address=host.ip,
                defaults={
                    'name': asset_data['hostname'],
                    'asset_type': _guess_asset_type(host.services, host.open_ports),
                    'mac_address': host.mac or f"00:16:3e:{random.randint(10,99):02x}:{random.randint(10,99):02x}:{random.randint(10,99):02x}",
                    'location': f'Network-{network_range}',
                    'status': 'active',
                    'discovered_date': timezone.now(),
                    'network_range': network_range,
                }
            )
            
            print(f"{'✅ Created' if created else '🔄 Updated'} asset: {host.ip} ({asset_data['hostname']})")
            
        except Exception as e:
            print(f"⚠️ Failed to create asset for {host.ip}: {e}")
    
    return results

def _guess_asset_type(services, ports):
    """Guess asset type based on discovered services"""
    service_names = [s[0].lower() for s in services]
    
    if any(s in service_names for s in ['http', 'https', 'apache', 'nginx']):
        return 'server'
    elif 'ssh' in service_names:
        return 'server'
    elif any(p in ports for p in [3389, 5900]):  # RDP, VNC
        return 'workstation'
    elif any(p in ports for p in [139, 445]):  # SMB
        return 'workstation'
    elif any(s in service_names for s in ['printer', 'ipp']):
        return 'printer'
    else:
        return 'unknown'

# Usage example
if __name__ == "__main__":
    # Example usage
    results = enhanced_network_scan("192.168.1.0/24", aggressive=True)
    
    print(f"\n📊 SCAN SUMMARY:")
    print(f"Found {len(results)} devices")
    
    for result in results:
        print(f"  {result['ip']} - {result['hostname']}")
        if result['open_ports']:
            print(f"    Ports: {result['open_ports']}")
        if result['services']:
            print(f"    Services: {[s[0] for s in result['services']]}")