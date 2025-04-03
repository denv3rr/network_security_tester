import platform
import logging
import datetime
import os
import argparse
from wifi_scan import scan_wifi
from bluetooth_scan import scan_bluetooth
from os_security import check_os_security
from network_scanner import run_network_metadata_scan
from port_scanner import run_port_scan

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

    def __init__(self, port_range="1-65535"):
        self.port_range = port_range
        self.scan_functions = {
            "wifi": scan_wifi,
            "bluetooth": scan_bluetooth,
            "os": check_os_security,
            "network": run_network_metadata_scan,
            "ports": self._run_port_scan  # Use internal method for port scan
        }
        self.results = []

    def _run_port_scan(self):
        """Internal method to run port scan with the instance's port range."""
        try:
            start_port, end_port = map(int, self.port_range.split("-"))
        except Exception:
            logging.warning("Invalid port range provided. Defaulting to 1-65535.")
            start_port, end_port = 1, 65535
        res = run_port_scan(start_port=start_port, end_port=end_port)
        return f"Port Scan ({start_port}-{end_port}): {res}"

    def run_scan(self, selected_modules=None, **scan_options):
        """
        Executes the selected scans. If no modules are selected, runs all.
        Accepts scan_options for module-specific arguments.
        """
        if not selected_modules:
            selected_modules = self.scan_functions.keys()  # Run all if none selected

        for module in selected_modules:
            if module in self.scan_functions:
                try:
                    # Pass relevant options to each scan function
                    if module == "wifi":
                        res = self.scan_functions[module](wifi_interface=scan_options.get("wifi_interface"))
                    elif module == "ports":
                        res = self.scan_functions[module](port_range=scan_options.get("port_range"))
                    else:
                        res = self.scan_functions[module]()
                    self.results.append(f"{module.capitalize()} Scan: {res}")
                except Exception as e:
                    logging.error(f"Error running {module} scan: {e}")
                    self.results.append(f"{module.capitalize()} Scan: Error")  # Indicate error

    def get_results(self):
        """Returns the results of the scans."""
        return self.results

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="Network Security Tester (NST) - A multi-platform tool for scanning Wi-Fi networks, Bluetooth devices, OS security settings, and network metadata, including BSSID geolocation and IP tracking. Supports both CLI and GUI modes.")
    
    # Available scan options
    parser.add_argument("--wifi", action="store_true", help="Run Wi-Fi scan")
    parser.add_argument("--bluetooth", action="store_true", help="Run Bluetooth scan")
    parser.add_argument("--os", action="store_true", help="Run OS security scan")
    parser.add_argument("--network", action="store_true", help="Run Network Metadata scan")
    # Single argument for BOTH DEFAULT AND CUSTOM Port Ranges to avoid conflicts in parser
    parser.add_argument("--ports", nargs="?", const="1-65535", help="Scan network devices for open ports (default: all ports). Provide a custom range (e.g., '--ports 1-1000').")    
    parser.add_argument("--all", action="store_true", help="Run full scan (all modules)")
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    parser.add_argument("--silent", action="store_true", help="Run scan without logging output")
    parser.add_argument("--wifi_interface", help="Specify the Wi-Fi interface to use for scanning") #CLI option for wifi_interface

    args = parser.parse_args()

    if args.silent:
        logging.disable(logging.CRITICAL)  # Turns off all logging

    if args.gui:
        from gui_interface import NST_GUI
        import tkinter as tk
        root = tk.Tk()
        app = NST_GUI(root)
        root.mainloop()
    else:
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
        scanner.run_scan(selected_modules, scan_options=scan_options) #Pass CLI wifi_interface option

        for result in scanner.get_results():
            logging.info(result)
        
        logging.info("Network Security Tester scan complete.")

if __name__ == "__main__":
    main()