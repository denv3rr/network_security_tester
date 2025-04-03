import platform
import requests
import socket
import logging
import json
import netifaces
import subprocess
import shutil

def check_command_exists(cmd):
    """Check if a command is available on the system."""
    return shutil.which(cmd) is not None

def run_command(cmd_list, check=True):
    """
    Executes a system command and returns the output.
    Raises subprocess.CalledProcessError if the command fails (when check=True).
    """
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, check=check)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{' '.join(cmd_list)}' failed: {e}")
        raise  # Re-raise the exception to be handled by the caller
    except Exception as e:
        logging.error(f"Error running command '{' '.join(cmd_list)}': {e}")
        raise

def run_command_safe(cmd_list):
    """
    Executes a system command and returns the output, or an error message if it fails.
    Does not raise exceptions.
    """
    try:
        return run_command(cmd_list, check=True)
    except subprocess.CalledProcessError as e:
        return str(e)  # Return the error message
    except Exception as e:
        return str(e)

def get_public_ip():
    """Retrieves the public IP address of the device."""
    try:
        response = requests.get("https://api64.ipify.org?format=json", timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses
        ip_data = response.json()
        return ip_data.get("ip", "Unknown")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error retrieving public IP: {e}")
        return "Error retrieving IP"
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response: {e}")
        return "Error decoding IP"

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
            output = run_command_safe(["netsh", "wlan", "show", "networks", "mode=Bssid"])
            for line in output.splitlines():
                if "BSSID" in line:
                    bssid_list.append(line.split(":")[1].strip())
        elif current_os == "Linux":
            output = run_command_safe(["nmcli", "-t", "-f", "BSSID", "dev", "wifi"])
            bssid_list = [line.strip() for line in output.splitlines()]
        elif current_os == "Darwin":
            output = run_command_safe(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"])
            lines = output.split("\n")[1:]
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
    """Retrieves geolocation data for a given BSSID using an API like Wigle.net."""
    api_url = f"https://api.wigle.net/api/v2/network/detail?netid={bssid}"
    headers = {"User-Agent": "NetworkSecurityTester"}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses
        data = response.json()
        lat = data.get("location", {}).get("latitude", "Unknown")
        lon = data.get("location", {}).get("longitude", "Unknown")
        return {"Latitude": lat, "Longitude": lon}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error retrieving BSSID location: {e}")
        return {"Latitude": "Error", "Longitude": "Error"}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response: {e}")
        return {"Latitude": "Error", "Longitude": "Error"}
    except Exception as e:
        logging.error(f"Unexpected error retrieving BSSID location: {e}")
        return {"Latitude": "Error", "Longitude": "Error"}

def get_ip_geolocation(ip=None):
    """Retrieves geolocation data for a given IP address using ipinfo.io."""
    if not ip:
        ip = get_public_ip()
    
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error retrieving IP geolocation: {e}")
        return {"error": "Could not retrieve location"}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response: {e}")
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