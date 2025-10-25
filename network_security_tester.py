import platform
import logging
from datetime import datetime
import os
import argparse
from wifi_scan import scan_wifi
from bluetooth_scan import scan_bluetooth
from os_security import check_os_security
from network_scanner import run_network_metadata_scan
from port_scanner import run_port_scan

# Utility function to print section headers
def print_section(title):
    print()
    print("="*60)
    print(f"{title} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

# Logging setup
def setup_logging():
    """
    Configures logging to output to console and a file, with auto-cleanup of old log files.
    """
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"NST_log_{timestamp}.txt")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    # Auto-cleanup logs older than 7 days
    try:
        now = datetime.datetime.now().timestamp()
        for fname in os.listdir(log_dir):
            fpath = os.path.join(log_dir, fname)
            if os.path.isfile(fpath):
                creation_time = os.path.getctime(fpath)
                if now - creation_time > 7 * 24 * 60 * 60:
                    os.remove(fpath)
    except Exception as e:
        logging.error(f"Error during log cleanup: {e}")

class Scanner:
    """
    Manages the execution of network security scans.
    """

    # Initialize with default port range and scan functions
    def __init__(self, port_range="1-65535", output_queue=None, stop_flag=False):  # Add stop_flag
        self.port_range = port_range
        self.scan_functions = {
            "wifi": scan_wifi,
            "bluetooth": scan_bluetooth,
            "os": check_os_security,
            "network": run_network_metadata_scan,
            "ports": self._run_port_scan  # Use internal method for port scan
        }
        self.results = []
        self.output_queue = output_queue
        self.stop_flag = stop_flag  # Store the stop flag

    def _run_port_scan(self, port_range="1-65535", output_queue=None, stop_flag=False):  # Add stop_flag parameter
        """Internal method to run port scan with the instance's port range."""
        try:
            start_port, end_port = map(int, port_range.split("-"))
        except Exception:
            logging.warning("Invalid port range provided. Defaulting to 1-65535.")
            start_port, end_port = 1, 65535
        res = run_port_scan(
            start_port=start_port,
            end_port=end_port,
            output_queue=output_queue,
            stop_flag=stop_flag # Pass the stop flag
        )
        return f"Port Scan ({start_port}-{end_port}): {res}"

    def run_scan(self, selected_modules=None, **scan_options):
        # scan_options contains port_range, wifi_interface, scan_type, etc.
        """
        Executes the selected scans. If no modules are selected, runs all.
        Accepts scan_options for module-specific arguments.
        """

        # Run all if none selected
        if not selected_modules:
            selected_modules = self.scan_functions.keys()

        # Execute each selected scan
        for module in selected_modules:
            if module in self.scan_functions:
                try:
                    # Pass relevant options to each scan function
                    if module == "wifi":
                        # For Wi-Fi scan, pass wifi_interface
                        res = self.scan_functions[module](
                            wifi_interface=scan_options.get("wifi_interface"),
                            output_queue=self.output_queue,
                            stop_flag=self.stop_flag # Pass the stop flag
                            **scan_options
                        )
                    elif module == "ports":
                        # For port scan, pass port_range
                        res = self.scan_functions[module](
                            port_range=scan_options.get("port_range"),
                            output_queue=self.output_queue,
                            stop_flag=self.stop_flag # Pass the stop flag
                            **scan_options
                        )
                    else:
                        # For other modules
                        res = self.scan_functions[module](
                            output_queue=self.output_queue,
                            stop_flag=self.stop_flag # Pass the stop flag
                            **scan_options
                        )
                    self.results.append(f"{module.capitalize()} Scan: {res}")
                except Exception as e:
                    logging.error(f"Error running {module} scan: {e}")
                    self.results.append(f"{module.capitalize()} Scan: Error")  # Indicate error

    def get_results(self):
        """Returns the results of the scans."""
        return self.results

# Main CLI entry point
def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="Network Security Tester (NST) - A multi-platform tool for scanning Wi-Fi networks, Bluetooth devices, OS security settings, and network metadata, including BSSID geolocation and IP tracking. Supports both CLI and GUI modes.")

    # Available scan options
    parser.add_argument("--wifi", action="store_true", help="Run Wi-Fi scan")
    parser.add_argument("--bluetooth", action="store_true", help="Run Bluetooth scan")
    parser.add_argument("--os", action="store_true", help="Run OS security scan")
    parser.add_argument("--network", action="store_true", help="Run Network Metadata scan")
    # Single argument for BOTH DEFAULT AND CUSTOM Port Ranges to avoid conflicts in parser
    parser.add_argument(
        "--ports",
        nargs="?",
        const="1-65535",
        help="Scan network devices for open ports (default: all ports). Provide a custom range (e.g., '--ports 1-1000').",
    )
    parser.add_argument("--all", action="store_true", help="Run full scan (all modules)")
    parser.add_argument("--silent", action="store_true", help="Run scan without logging output")
    parser.add_argument("--wifi_interface", help="Specify the Wi-Fi interface to use for scanning")  # CLI option for wifi_interface

    args = parser.parse_args()

    if args.silent:
        logging.disable(logging.CRITICAL)  # Turns off all logging

    selected_modules = []
    if args.all or not any([args.wifi, args.bluetooth, args.os, args.network, args.ports]):
        selected_modules = None  # Run all modules
    else:
        if args.wifi:
            selected_modules.append("wifi")
        if args.bluetooth:
            selected_modules.append("bluetooth")
        if args.os:
            selected_modules.append("os")
        if args.network:
            selected_modules.append("network")
        if args.ports:
            selected_modules.append("ports")

        logging.info(f"Network Security Tester started on {platform.system()}")

        # Initialize and run the scanner
        scanner = Scanner(port_range=args.ports if args.ports else "1-65535")
        scan_options = {}
        if args.wifi_interface:
            scan_options["wifi_interface"] = args.wifi_interface
        scanner.run_scan(selected_modules, **scan_options)

        for result in scanner.get_results():
            logging.info(result)

        logging.info("Network Security Tester scan complete.")

if __name__ == "__main__":
    main()