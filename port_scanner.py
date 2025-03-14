import socket
import logging
import subprocess
import platform

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

def scan_ports(ip, start_port=1, end_port=65535):
    """Scans a given IP address for all possible ports (1-65535)."""
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)  # Timeout reduced for efficiency
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    logging.info(f"Open port detected: {port} on {ip}")
        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {e}")
    return open_ports

def get_service_banner(ip, port):
    """Attempts to retrieve the banner of a service running on a port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode().strip()
            return banner
    except:
        return "Unknown Service"

def run_port_scan():
    """Scans all detected network devices for open ports in full range."""
    logging.info("=== Running Full Port Scan on Network Devices ===")
    devices = get_network_devices()
    if not devices:
        logging.warning("No devices found on the network.")
        return "No devices found"

    results = {}
    for device in devices:
        logging.info(f"Scanning {device} for all ports (1-65535)...")
        open_ports = scan_ports(device, 1, 65535)  # Scanning full range
        if open_ports:
            logging.warning(f"Device {device} has open ports: {open_ports}")
        else:
            logging.info(f"Device {device} has no open ports detected.")
        results[device] = open_ports

    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_port_scan()
