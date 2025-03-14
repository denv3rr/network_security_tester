# MAIN

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

def run_full_scan(selected_modules=None):
    """
    Runs a full scan or selected modules and logs the results.
    selected_modules: list of module names (e.g., ['wifi', 'bluetooth', 'os', 'network']).
                    If None or empty, all modules are run.
    """
    results = []
    
    if not selected_modules or "wifi" in selected_modules:
        res = scan_wifi()
        results.append(f"Wi-Fi Scan: {res}")

    if not selected_modules or "bluetooth" in selected_modules:
        res = scan_bluetooth()
        results.append(f"Bluetooth Scan: {res}")

    if not selected_modules or "os" in selected_modules:
        res = check_os_security()
        results.append(f"OS Security Check: {res}")

    if not selected_modules or "network" in selected_modules:
        res = run_network_metadata_scan()
        results.append(f"Network Metadata Scan: {res}")

    if not selected_modules or "ports" in selected_modules:  # Run Port Scanner
        res = run_port_scan()
        results.append(f"Port Scan: {res}")

    # Log consolidated summary
    logging.info("=== Scan Summary ===")
    for line in results:
        logging.info(line)
    return "\n".join(results)

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

    if args.silent:
        logging.disable(logging.CRITICAL)  # Turns off all logging

    args = parser.parse_args()

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
        
        # Pass port range to the scanning function
        if args.ports:
            port_range = args.ports if args.ports else "1-65535"
            run_full_scan(selected_modules=selected_modules, port_range=port_range)
        else:
            run_full_scan(selected_modules=selected_modules)
        
        logging.info("Network Security Tester scan complete.")

if __name__ == "__main__":
    main()