# test_scanner.py
from network_scanner import NetworkScanner

if __name__ == "__main__":
    print("--- Testing NetworkScanner.scan_network ---")
    # Replace with YOUR actual network range, e.g., "192.168.1.0/24"
    test_network_range = "192.168.1.0/24" 
    discovered_devices = NetworkScanner.scan_network(test_network_range)

    print(f"\n--- Scan Results for {test_network_range} ---")
    if discovered_devices:
        print(f"Discovered {len(discovered_devices)} devices:")
        for device in discovered_devices:
            print(f"  IP: {device.get('ip_address')}, MAC: {device.get('mac_address')}, Hostname: {device.get('hostname')}")
    else:
        print("No devices found by NetworkScanner.scan_network().")

    print("\n--- Testing NetworkScanner.get_available_networks ---")
    available_networks = NetworkScanner.get_available_networks()
    print(f"Available networks detected: {available_networks}")
    if available_networks:
        print(f"First available network: {available_networks[0]}")
    else:
        print("No available networks detected by get_available_networks.")