import socket
import logging
import subprocess
import platform

# Check common open ports:
# SSH, HTTP, HTTPS, RDP, DNS, Web Proxy
COMMON_PORTS = [22, 80, 443, 3389, 53, 8080]

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

def scan_ports(ip, ports=COMMON_PORTS):
    """Scans a given IP address for open ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {e}")
    return open_ports

def run_port_scan():
    """Scans all detected network devices for open ports."""
    logging.info("=== Running Port Scan on Network Devices ===")
    devices = get_network_devices()
    if not devices:
        logging.warning("No devices found on the network.")
        return "No devices found"

    results = {}
    for device in devices:
        logging.info(f"Scanning {device}...")
        open_ports = scan_ports(device)
        if open_ports:
            logging.warning(f"Device {device} has open ports: {open_ports}")
        else:
            logging.info(f"Device {device} has no common open ports.")
        results[device] = open_ports

    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_port_scan()
