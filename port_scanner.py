import socket
import logging
import subprocess
import platform
import json
import shutil
import queue  # Import the queue module

# Load known device/service signatures from a local JSON file
DEVICE_SIGNATURES_FILE = "known_devices.json"

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

def get_network_devices(output_queue=None):
    """Retrieves active network devices on the local network."""
    devices = []
    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = run_command_safe(["arp", "-a"])
            for line in output.split("\n"):
                parts = line.split()
                if len(parts) >= 2 and parts[0].count(".") == 3:
                    device = parts[0]
                    devices.append(device)
                    if output_queue:
                        output_queue.put(f"  Device found: {device}")
        else:  # Linux/macOS
            output = run_command_safe(["ip", "neigh"])
            for line in output.split("\n"):
                parts = line.split()
                if len(parts) >= 1 and parts[0].count(".") == 3:
                    device = parts[0]
                    devices.append(device)
                    if output_queue:
                        output_queue.put(f"  Device found: {device}")
    except Exception as e:
        logging.error(f"Error retrieving network devices: {e}")
        if output_queue:
            output_queue.put("Error retrieving network devices")
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

def scan_ports(ip, start_port=1, end_port=65535, output_queue=None, progress_callback=None, total_ports=65535):
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
                    if output_queue:
                        output_queue.put(f"  ✅ Open port: {port} on {ip} | Service: {service}")
                
                if progress_callback:
                    progress = int((port / total_ports) * 100)
                    progress_callback(progress)

        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {e}")
            if output_queue:
                output_queue.put(f"  Error scanning port {port} on {ip}: {e}")

    if open_ports:
        if output_queue:
            output_queue.put(f"  Summary for {ip}: {open_ports}")

    return open_ports  # Dictionary format {port_number: service_name}

def identify_device_type(open_ports, output_queue=None):
    """Matches open ports against known device types."""
    try:
        with open(DEVICE_SIGNATURES_FILE, "r") as file:
            known_devices = json.load(file)
    except FileNotFoundError:
        logging.warning("Device signatures file not found. Skipping device identification.")
        if output_queue:
            output_queue.put("Device signatures file not found. Skipping device identification.")
        return {}

    detected_devices = {}
    for port, service in open_ports.items():
        if str(port) in known_devices:
            detected_devices[port] = known_devices[str(port)]
            if output_queue:
                output_queue.put(f"  Device type identified: {detected_devices[port]} (Port {port})")
    
    return detected_devices

def run_port_scan(start_port=1, end_port=65535, port_range="1-65535", output_queue=None, progress_callback=None):
    """Scans all detected network devices for open ports and identifies possible device types."""
    logging.info("=== Running Full Port Scan on Network Devices ===")
    if output_queue:
        output_queue.put("=== Running Full Port Scan on Network Devices ===")
    devices = get_network_devices(output_queue)
    if not devices:
        logging.warning("No devices found on the network.")
        if output_queue:
            output_queue.put("No devices found on the network.")
        return "No devices found"

    # Override start/end ports if a custom range is provided
    try:
        start_port, end_port = map(int, port_range.split("-"))
    except ValueError:
        logging.warning(f"Invalid port range '{port_range}'. Using default 1-65535.")
        if output_queue:
            output_queue.put(f"Invalid port range '{port_range}'. Using default 1-65535.")
        start_port, end_port = 1, 65535

    results = {}
    total_ports = end_port - start_port + 1
    for device in devices:
        logging.info(f"Scanning {device} for ports {start_port}-{end_port}...")
        if output_queue:
            output_queue.put(f"Scanning {device} for ports {start_port}-{end_port}...")
        open_ports = scan_ports(device, start_port, end_port, output_queue, progress_callback, total_ports)  # Scanning selected range
        detected_devices = identify_device_type(open_ports, output_queue)

        if open_ports:
            logging.warning(f"Device {device} has open ports: {open_ports}")
            if output_queue:
                output_queue.put(f"Device {device} has open ports: {open_ports}")
            if detected_devices:
                logging.info(f"Identified device types for {device}: {detected_devices}")
                if output_queue:
                    output_queue.put(f"Identified device types for {device}: {detected_devices}")
        else:
            logging.info(f"Device {device} has no open ports detected.")
            if output_queue:
                output_queue.put(f"Device {device} has no open ports detected.")

        results[device] = {"open_ports": open_ports, "identified_devices": detected_devices}

    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_port_scan()