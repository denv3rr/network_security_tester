import platform
import requests
import socket
import logging
import json
import netifaces
import subprocess

def get_public_ip():
    """Retrieves the public IP address of the device."""
    try:
        response = requests.get("https://api64.ipify.org?format=json", timeout=5)
        ip_data = response.json()
        return ip_data.get("ip", "Unknown")
    except requests.RequestException as e:
        logging.error(f"Error retrieving public IP: {e}")
        return "Error retrieving IP"

def get_local_network_info():
    """Retrieves local network details including IP, MAC addresses, and default gateway."""
    network_info = {}
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            ip = addrs.get(netifaces.AF_INET, [{}])[0].get("addr", "N/A")
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr", "N/A")
            gateway = netifaces.gateways().get("default", {}).get(netifaces.AF_INET, [None])[0]
            network_info[interface] = {"IP Address": ip, "MAC Address": mac, "Gateway": gateway}
    except Exception as e:
        logging.error(f"Error retrieving local network info: {e}")
    return network_info

def get_bssid_list():
    """Scans for Wi-Fi networks and extracts BSSIDs for geolocation lookups."""
    bssid_list = []
    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = subprocess.run(["netsh", "wlan", "show", "networks", "mode=Bssid"],
                                    capture_output=True, text=True, check=True)
            for line in output.stdout.splitlines():
                if "BSSID" in line:
                    bssid_list.append(line.split(":")[1].strip())
        elif current_os == "Linux":
            output = subprocess.run(["nmcli", "-t", "-f", "BSSID", "dev", "wifi"],
                                    capture_output=True, text=True, check=True)
            bssid_list = [line.strip() for line in output.stdout.splitlines()]
        elif current_os == "Darwin":
            output = subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                                    capture_output=True, text=True, check=True)
            lines = output.stdout.split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) > 1:
                    bssid_list.append(parts[1].strip())
        else:
            logging.warning(f"BSSID scanning is not supported on this OS ({current_os}).")
            return []
    except Exception as e:
        logging.error(f"Error retrieving BSSID list: {e}")
        return []
    
    return bssid_list

def get_bssid_geolocation(bssid):
    """Retrieves geolocation data for a given BSSID using an API like Wigle.net (requires API key)."""
    api_url = f"https://api.wigle.net/api/v2/network/detail?netid={bssid}"
    headers = {"User-Agent": "NetworkSecurityTester"}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            lat = data.get("location", {}).get("latitude", "Unknown")
            lon = data.get("location", {}).get("longitude", "Unknown")
            return {"Latitude": lat, "Longitude": lon}
        else:
            logging.warning(f"Failed to retrieve BSSID location: {response.status_code}")
            return {"Latitude": "N/A", "Longitude": "N/A"}
    except requests.RequestException as e:
        logging.error(f"Error retrieving BSSID location: {e}")
        return {"Latitude": "Error", "Longitude": "Error"}

def get_ip_geolocation(ip=None):
    """Retrieves geolocation data for a given IP address using ipinfo.io."""
    if not ip:
        ip = get_public_ip()
    
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error retrieving IP geolocation: {e}")
        return {"error": "Could not retrieve location"}

def run_network_metadata_scan():
    """Runs a full network metadata scan and logs the results."""
    logging.info("=== Running Network Metadata Scan ===")

    # Get Public IP and Geolocation
    public_ip = get_public_ip()
    logging.info(f"Public IP: {public_ip}")
    
    ip_geo = get_ip_geolocation(public_ip)
    logging.info(f"IP Geolocation: {json.dumps(ip_geo, indent=2)}")

    # Get Local Network Details
    local_info = get_local_network_info()
    for interface, details in local_info.items():
        logging.info(f"Interface: {interface}")
        logging.info(f"  IP Address: {details['IP Address']}")
        logging.info(f"  MAC Address: {details['MAC Address']}")
        logging.info(f"  Gateway: {details['Gateway']}")

    # Scan for BSSIDs and Retrieve Geolocation Data
    bssids = get_bssid_list()
    if bssids:
        logging.info(f"Found {len(bssids)} BSSIDs. Attempting geolocation lookup...")
        for bssid in bssids:
            location = get_bssid_geolocation(bssid)
            logging.info(f"BSSID {bssid}: {location}")
    else:
        logging.warning("No BSSIDs detected during scan.")

    logging.info("=== Network Metadata Scan Complete ===")
    return "Network metadata scan completed."

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_network_metadata_scan()
