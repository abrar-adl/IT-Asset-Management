from datetime import datetime, timedelta
import json
import requests
import time
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import os
from contextlib import closing

# Import your models - adjust path as needed
from .models import Asset, RiskScanResult
from .network_scanner import scan_host_services


class CVELookup:
    def __init__(self):
        # Multiple CVE data sources
        self.sources = [
            {
                'name': 'NVD NIST',
                'url_template': 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage=50',
                'parser': self._parse_nvd_response
            },
            {
                'name': 'CVE Details API',
                'url_template': 'https://www.cvedetails.com/json-feed.php?vendor_id=0&product={product}&version={version}',
                'parser': self._parse_cvedetails_response
            },
            {
                'name': 'CIRCL (backup)',
                'url_template': 'https://cve.circl.lu/api/search/{product}/{version}',
                'parser': self._parse_circl_response
            }
        ]
        
        # Fallback vulnerability database (offline data)
        self.offline_vulns = {
            'mysql': {
                '8.0.42': ['CVE-2024-20963', 'CVE-2024-20964', 'CVE-2024-20965'],
                '8.0': ['CVE-2023-21980', 'CVE-2023-21982', 'CVE-2023-22005']
            },
            'microsoft': {
                'rpc': ['CVE-2023-21756', 'CVE-2023-23397'],
                'netbios': ['CVE-2023-28252', 'CVE-2023-21554'],
                'smb': ['CVE-2023-21808', 'CVE-2023-23397']
            },
            'apache': {
                '2.4': ['CVE-2023-25690', 'CVE-2023-27522']
            },
            'nginx': {
                '1.20': ['CVE-2021-23017']
            }
        }

    def get_vulnerabilities(self, product, version=""):
        """Get vulnerabilities with multiple fallback sources"""
        print(f"🔍 Looking up CVEs for {product} {version}")
        
        # Try online sources first
        for source in self.sources:
            try:
                vulnerabilities = self._try_source(source, product, version)
                if vulnerabilities:
                    print(f"✅ Found {len(vulnerabilities)} CVEs from {source['name']}")
                    return vulnerabilities
                    
            except Exception as e:
                print(f"⚠️ {source['name']} failed: {e}")
        
        # Fallback to offline database
        offline_cves = self._get_offline_vulnerabilities(product, version)
        if offline_cves:
            print(f"📚 Using offline CVE data: {len(offline_cves)} vulnerabilities")
            return offline_cves
            
        print(f"❌ No vulnerabilities found for {product} {version}")
        return []

    def _try_source(self, source, product, version):
        """Try a specific CVE source with timeout and error handling"""
        url = source['url_template'].format(product=product.lower(), version=version)
        
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'IT-Asset-Management-Tool/1.0'
        })
        
        if response.status_code == 200:
            return source['parser'](response.json(), product, version)
        elif response.status_code == 404:
            print(f"   No data found in {source['name']}")
            return []
        else:
            raise Exception(f"HTTP {response.status_code}")

    def _parse_nvd_response(self, data, product, version):
        """Parse NVD NIST API response"""
        vulnerabilities = []
        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            vulnerabilities.append(cve_id)
        return vulnerabilities[:10]  # Limit results

    def _parse_cvedetails_response(self, data, product, version):
        """Parse CVE Details API response"""
        if isinstance(data, list):
            return [item.get('cve_id', 'Unknown') for item in data[:10]]
        return []

    def _parse_circl_response(self, data, product, version):
        """Parse CIRCL API response (original format)"""
        vulnerabilities = []
        for cve in data.get("results", []):
            vulnerabilities.append(cve.get("id", "Unknown"))
        return vulnerabilities

    def _get_offline_vulnerabilities(self, product, version):
        """Get vulnerabilities from offline database"""
        product_lower = product.lower()
        
        # Direct product match
        if product_lower in self.offline_vulns:
            product_data = self.offline_vulns[product_lower]
            
            # Exact version match
            if version and version in product_data:
                return product_data[version]
            
            # Major version match (e.g., "8.0.42" matches "8.0")
            if version:
                major_version = '.'.join(version.split('.')[:2])
                if major_version in product_data:
                    return product_data[major_version]
            
            # Return any vulnerabilities for this product
            for v, cves in product_data.items():
                return cves
        
        # Product name matching (for Microsoft services)
        if 'rpc' in product_lower:
            return self.offline_vulns.get('microsoft', {}).get('rpc', [])
        elif 'netbios' in product_lower:
            return self.offline_vulns.get('microsoft', {}).get('netbios', [])
        elif 'smb' in product_lower or 'microsoft-ds' in product_lower:
            return self.offline_vulns.get('microsoft', {}).get('smb', [])
        
        return []

class RiskAssessment:
    def __init__(self):
        self.vulnerability_db = {
            'Dell': ['CVE-2023-1234', 'CVE-2023-5678'],
            'HP': ['CVE-2023-9012', 'CVE-2023-3456'],
            'Cisco': ['CVE-2023-7890', 'CVE-2023-2345'],
            'Lenovo': ['CVE-2023-6789']
        }
        self.cve_lookup = CVELookup()
    
    def calculate_risk_score(self, asset):
        """Calculate risk score for an asset (0-100)"""
        risk_score = 0
        
        # Age-based risk (older = higher risk)
        age_days = (datetime.now().date() - asset.discovered_date.date()).days
        if age_days > 365:  # Over 1 year
            risk_score += 30
        elif age_days > 180:  # Over 6 months
            risk_score += 15
        
        # Manufacturer-based vulnerabilities
        if asset.manufacturer in self.vulnerability_db:
            vuln_count = len(self.vulnerability_db[asset.manufacturer])
            risk_score += vuln_count * 10
        
        # Asset type risk
        high_risk_types = ['server', 'network']
        if asset.asset_type in high_risk_types:
            risk_score += 20
        
        # Network exposure (has IP = exposed)
        if asset.ip_address:
            risk_score += 15
        
        return min(risk_score, 100)  # Cap at 100
    
    def get_risk_level(self, score):
        """Convert risk score to level"""
        if score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'

    def get_vulnerabilities(self, asset):
        """Enhanced vulnerability lookup with multiple sources"""
        if not asset.ip_address:
            print(f"⚠️ No IP address for {asset.name}")
            return []
               
        
        #This will perform a more targeted scan suitable for vulnerability assessment.
        services = scan_host_services(asset.ip_address, quick_mode=True)

        print(f"🔍 Services for {asset.ip_address}: {services}")
        vulns = []
        
        if not services:
            print(f"⚠️ No services detected on {asset.ip_address}")
            return []
        
        all_vulnerabilities = []
        
#        for product, version in services:
        for service in services:
            product = service.get('product', '')
            version = service.get('version', '')
            clean_product = normalize_service(product)
            if not clean_product:
                continue
                
            vulnerabilities = self.cve_lookup.get_vulnerabilities(clean_product, version)
            all_vulnerabilities.extend(vulnerabilities)
            
            # Small delay to be respectful to APIs
            time.sleep(0.5)
        
        # Remove duplicates and return

        return vulns



# Utility functions
def normalize_service(product):
    """Cleans product name for CVE lookup"""
    if not product:
        return None
        
    product = product.strip().lower()

    if "microsoft" in product:
        return "Microsoft"
    elif "mysql" in product:
        return "MySQL"
    elif "httpapi" in product:
        return "Microsoft HTTPAPI"
    elif "netbios" in product or "rpc" in product or "tcpwrapped" in product:
        return None  # Skip these
    else:
        return product.split()[0].capitalize()  # Fallback cleanup


def normalize_product_name(name):
    """Legacy function for backward compatibility"""
    if not name:
        return name
        
    name = name.lower()
    if 'mysql' in name:
        return 'MySQL'
    if 'httpapi' in name or 'microsoft httpapi' in name:
        return 'Microsoft HTTPAPI'
    if 'rpc' in name:
        return 'Microsoft Windows RPC'
    if 'netbios' in name:
        return 'Microsoft Windows netbios-ssn'
    if 'microsoft-ds' in name:
        return 'Microsoft SMB'

    return name  # fallback


def assess_all_assets(store=False, aggressive_scan=False):
    """Main assessment function"""
    ra = RiskAssessment()
    results = []
    
    print(f"🔍 Starting risk assessment for {Asset.objects.count()} assets...")

    for asset in Asset.objects.all():
        print(f"\n📊 Assessing {asset.name} ({asset.ip_address})")
        
        score = ra.calculate_risk_score(asset)
        level = ra.get_risk_level(score)
        
        # Enhanced vulnerability scanning
        if asset.ip_address:
            vulnerabilities = ra.get_vulnerabilities(asset)
        else:
            print(f"⚠️ Skipping vulnerability scan for {asset.name} (no IP)")
            vulnerabilities = []

        if store:
            RiskScanResult.objects.update_or_create(
                asset=asset,
                defaults={
                    'risk_score': score,
                    'risk_level': level,
                    'vulnerabilities': vulnerabilities
                }
            )
            print(f"💾 Stored risk assessment for {asset.name}")

        results.append({
            'asset': asset,
            'risk_score': score,
            'risk_level': level,
            'vulnerabilities': vulnerabilities
        })

    print(f"✅ Risk assessment completed for {len(results)} assets")
    return results


