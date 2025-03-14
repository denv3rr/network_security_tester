import socket
import logging
import subprocess
import platform
import json

# Load known device/service signatures from a local JSON file
DEVICE_SIGNATURES_FILE = "known_devices.json"

def get_network_devices():
    """Retrieves active network devices on the local network."""
    devices = []
    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True).stdout
            for line in output.split("\n"):
                parts = line.split()
                if len(parts) >= 2 and parts[0].count(".") == 3:
                    devices.append(parts[0])
        else:  # Linux/macOS
            output = subprocess.run(["ip", "neigh"], capture_output=True, text=True, check=True).stdout
            for line in output.split("\n"):
                parts = line.split()
                if len(parts) >= 1 and parts[0].count(".") == 3:
                    devices.append(parts[0])
    except Exception as e:
        logging.error(f"Error retrieving network devices: {e}")
    return list(set(devices))

def get_service_banner(ip, port):
    """Attempts to retrieve the banner of a service running on a port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode().strip()
            return banner if banner else "Unknown Service"
    except:
        return "Unknown Service"

def scan_ports(ip, start_port=1, end_port=65535):
    """Scans a given IP address for open ports (1-65535) and retrieves service banners."""
    open_ports = {}

    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)  # Reduce timeout for efficiency
                result = sock.connect_ex((ip, port))  # Attempt to connect to port
                
                if result == 0:  # Connection successful (port is open)
                    service = get_service_banner(ip, port)
                    open_ports[port] = service
                    logging.info(f"✅ Open port: {port} on {ip} | Service: {service}")

        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {e}")

    if open_ports:
        logging.info(f"Summary for {ip}: {open_ports}")

    return open_ports  # Dictionary format {port_number: service_name}

def identify_device_type(open_ports):
    """Matches open ports against known device types."""
    try:
        with open(DEVICE_SIGNATURES_FILE, "r") as file:
            known_devices = json.load(file)
    except FileNotFoundError:
        logging.warning("Device signatures file not found. Skipping device identification.")
        return {}

    detected_devices = {}
    for port, service in open_ports.items():
        if str(port) in known_devices:
            detected_devices[port] = known_devices[str(port)]
    
    return detected_devices

def run_port_scan():
    """Scans all detected network devices for open ports and identifies possible device types."""
    logging.info("=== Running Full Port Scan on Network Devices ===")
    devices = get_network_devices()
    if not devices:
        logging.warning("No devices found on the network.")
        return "No devices found"

    results = {}
    for device in devices:
        logging.info(f"Scanning {device} for all ports (1-65535)...")
        open_ports = scan_ports(device, 1, 65535)  # Scanning full range
        detected_devices = identify_device_type(open_ports)

        if open_ports:
            logging.warning(f"Device {device} has open ports: {open_ports}")
            if detected_devices:
                logging.info(f"Identified device types for {device}: {detected_devices}")
        else:
            logging.info(f"Device {device} has no open ports detected.")

        results[device] = {"open_ports": open_ports, "identified_devices": detected_devices}

    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_port_scan()
