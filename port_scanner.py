import socket
import logging
import subprocess
import platform
import json
import shutil
import queue  # Import the queue module
import texttable  # Import the texttable library

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

def get_network_devices(output_queue=None, stop_flag=False):
    """Retrieves active network devices on the local network (both IPv4 and IPv6)."""

    devices = {"IPv4": [], "IPv6": []}
    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = run_command_safe(["arp", "-a"])
            for line in output.split("\n"):
                if stop_flag:
                    return {"IPv4": [], "IPv6": []}
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    if ip.count(".") == 3:
                        devices["IPv4"].append(ip)
                    elif ip.count(":") >= 2:
                        devices["IPv6"].append(ip)
                    if output_queue:
                        output_queue.put(f"  Device found: {ip}")
        else:  # Linux/macOS
            output = run_command_safe(["ip", "neigh"])
            for line in output.split("\n"):
                if stop_flag:
                    return {"IPv4": [], "IPv6": []}
                parts = line.split()
                if len(parts) >= 1:
                    ip = parts[0]
                    if ip.count(".") == 3:
                        devices["IPv4"].append(ip)
                    elif ip.count(":") >= 2:
                        devices["IPv6"].append(ip)
                    if output_queue:
                        output_queue.put(f"  Device found: {ip}")
    except Exception as e:
        logging.error(f"Error retrieving network devices: {e}")
        if output_queue:
            output_queue.put("Error retrieving network devices")
    return {"IPv4": list(set(devices["IPv4"])), "IPv6": list(set(devices["IPv6"]))}

def get_service_banner(ip, port):
    """Attempts to retrieve the banner of a service running on a port."""

    try:
        with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode().strip()
            return banner if banner else "Unknown Service"
    except:
        return "Unknown Service"

def scan_ports(ip, start_port=1, end_port=65535, output_queue=None, progress_callback=None, total_ports=65535, stop_flag=False):
    """Scans a given IP address for open ports (1-65535) and retrieves service banners. Supports both IPv4 and IPv6."""

    open_ports = {}

    for port in range(start_port, end_port + 1):
        if stop_flag: # Check the stop flag
            return {}
        try:
            # Use AF_INET6 for IPv6, AF_INET for IPv4
            with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM) as sock:
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

    return open_ports  # Dictionary format {port_number: service_name}

def identify_device_type(open_ports, output_queue=None, stop_flag=False):
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
        if stop_flag: # Check the stop flag
            return {}
        if str(port) in known_devices:
            detected_devices[port] = known_devices[str(port)]
            if output_queue:
                output_queue.put(f"  Device type identified: {detected_devices[port]} (Port {port})")

    return detected_devices

def run_port_scan(start_port=1, end_port=65535, port_range="1-65535", output_queue=None, progress_callback=None, stop_flag=False):
    """Scans all detected network devices for open ports and identifies possible device types. Supports both IPv4 and IPv6."""

    logging.info("=== Running Full Port Scan on Network Devices ===")
    if output_queue:
        output_queue.put("=== Running Full Port Scan on Network Devices ===")
    devices = get_network_devices(output_queue, stop_flag)
    if not devices["IPv4"] and not devices["IPv6"]:
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
    for ip_type, ip_list in devices.items():
        for device in ip_list:
            if stop_flag: # Check the stop flag
                return {}
            logging.info(f"Scanning {ip_type} device {device} for ports {start_port}-{end_port}...")
            if output_queue:
                output_queue.put(f"Scanning {ip_type} device {device} for ports {start_port}-{end_port}...")
            open_ports = scan_ports(device, start_port, end_port, output_queue, progress_callback, total_ports, stop_flag)  # Scanning selected range
            detected_devices = identify_device_type(open_ports, output_queue, stop_flag)

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

    if output_queue:
        table = texttable.Texttable()
        table.header(["Port", "Service", "Device Type"])
        for device, data in results.items():
            if stop_flag: # Check the stop flag
                return {}
            output_queue.put(f"\n--- Scan results for {device} ---")
            if data["open_ports"]:
                for port, service in data["open_ports"].items():
                    device_type = data["identified_devices"].get(port, "Unknown")
                    table.add_row([port, service, device_type])
                output_queue.put(table.draw())
                table.reset()  # Clear table for next device
            else:
                output_queue.put("No open ports found.")

    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_port_scan()