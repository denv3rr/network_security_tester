# network_security_tester.py
# Main CLI coordinator for all scans; clean sections, ASCII-only logs,
# fixed kwargs for 'ports' (no collisions), and optional Wi-Fi geolocation.

import argparse
import logging
import os
import platform
import threading
from datetime import datetime
import sys

from wifi_scan import scan_wifi
from bluetooth_scan import scan_bluetooth
from os_security import check_os_security
from network_scanner import run_network_metadata_scan
from port_scanner import run_port_scan

# ---------- Utilities ----------

def print_section(title: str):
    """Pretty section divider with timestamp."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "=" * 64
    print(f"\n{line}\n{title} — {stamp}\n{line}")

def setup_logging():
    """
    File + console logger; auto-prunes logs older than 7 days.
    Console stays ASCII-safe (no fancy arrows) for CP1252 compatibility.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = os.path.join("logs", f"NST_{ts}.log")

    file_h = logging.FileHandler(logfile, encoding="utf-8")
    console_h = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_h.setFormatter(fmt); console_h.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(file_h); root.addHandler(console_h)

    # prune old logs
    try:
        now = datetime.now().timestamp()
        for name in os.listdir("logs"):
            path = os.path.join("logs", name)
            if os.path.isfile(path) and now - os.path.getctime(path) > 7 * 24 * 3600:
                os.remove(path)
    except Exception:
        logging.debug("log prune warn", exc_info=True)

def choose_port_scan_type(default_code="top") -> str:
    """
    Interactively ask for port-scan type. Default: 'top' for fast triage.
    """
    options = {
        "1": ("top",     "Top-ports only (fast triage)"),
        "2": ("connect", "TCP Connect scan (reliable, slower)"),
        "3": ("udp",     "UDP scan (slow, limited in this build)"),
    }
    print("Choose port scan type:")
    for k, (code, desc) in options.items():
        print(f"  {k}) {code:7s} — {desc}")
    sel = (input(f"Selection (default {default_code}): ").strip() or "").lower()
    if sel in options:
        return options[sel][0]
    for _, (code, _) in options.items():
        if sel == code:
            return code
    return default_code

# ---------- Scanner Orchestrator ----------

class Scanner:
    def __init__(self, port_range: str = "1-1024", output_queue=None, stop_flag=None):
        self.port_range = port_range
        self.output_queue = output_queue
        self.stop_flag = stop_flag or threading.Event()
        self.results = []
        self.scan_functions = {
            "wifi":     scan_wifi,
            "bluetooth":scan_bluetooth,
            "os":       check_os_security,
            "network":  run_network_metadata_scan,
            "ports":    self._run_port_scan
        }

    def _run_port_scan(self, *, port_range="1-1024", scan_type="top",
                       hosts=None, no_banner=True, timeout=0.30, workers=256,
                       **_ignored):
        """
        Wraps the concurrent port scan with safe, fast defaults.
        NOTE: kwargs are explicitly named to avoid double-passing collisions.
        """
        try:
            start_port, end_port = map(int, str(port_range).split("-"))
        except Exception:
            logging.warning("Invalid port range; fallback to 1-1024.")
            start_port, end_port = 1, 1024

        return run_port_scan(
            start_port=start_port,
            end_port=end_port,
            scan_type=scan_type,
            target_hosts=hosts,
            no_banner=no_banner,
            timeout=timeout,
            workers=workers,
            stop_flag=self.stop_flag,
            output_queue=self.output_queue
        )

    def run_scan(self, selected_modules=None, **scan_options):
        """
        Runs selected modules; if none provided, runs all.
        Always passes stop_flag and output_queue, and **avoids** double-passing
        keys that ports/_run_port_scan already receives explicitly.
        """
        if not selected_modules:
            selected_modules = list(self.scan_functions.keys())

        common = {"stop_flag": self.stop_flag, "output_queue": self.output_queue}

        for module in selected_modules:
            func = self.scan_functions.get(module)
            if not func:
                logging.warning(f"Unknown module: {module}")
                continue
            try:
                if module == "wifi":
                    # pass only what wifi cares about (plus common)
                    wifi_kwargs = dict(common)
                    wifi_kwargs["wifi_interface"] = scan_options.get("wifi_interface")
                    wifi_kwargs["do_geolocation"] = scan_options.get("geo", False)
                    result = func(**wifi_kwargs)

                elif module == "ports":
                    # EXPLICIT kwargs only — no **scan_options to avoid collisions
                    result = func(
                        port_range=scan_options.get("port_range", self.port_range),
                        scan_type=scan_options.get("scan_type", "top"),
                        hosts=scan_options.get("hosts"),
                        no_banner=scan_options.get("no_banner", True),
                        timeout=scan_options.get("timeout", 0.30),
                        workers=scan_options.get("workers", 256),
                        **common
                    )

                else:
                    # tolerant: pass only common kwargs to avoid unexpected kwarg errors
                    result = func(**common)

                self.results.append({"module": module, "result": result})

            except Exception as e:
                logging.error(f"{module} scan error: {e}")
                self.results.append({"module": module, "result": f"Error: {e}"})

    def get_results(self):
        return self.results

# ---------- CLI main ----------

def main():
    setup_logging()
    parser = argparse.ArgumentParser("Network Security Tester (CLI)")
    parser.add_argument("--wifi", action="store_true", help="Run Wi-Fi scan")
    parser.add_argument("--bluetooth", action="store_true", help="Run Bluetooth scan")
    parser.add_argument("--os", action="store_true", help="Run OS security scan")
    parser.add_argument("--network", action="store_true", help="Run Network metadata scan")
    parser.add_argument("--ports", nargs="?", const="1-1024",
                        help="Port scan range (default: 1-1024). Example: --ports 20-2000")
    parser.add_argument("--host", "--hosts", dest="hosts",
                        help="Target host(s), comma-separated (e.g., 192.168.1.1,192.168.1.41)")
    parser.add_argument("--fast", action="store_true",
                        help="Force fast mode: scan_type=top, no banners, short timeouts")
    parser.add_argument("--no-banner", action="store_true",
                        help="Skip banner grabbing (faster)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Per-port connect timeout (seconds). Default 0.30")
    parser.add_argument("--workers", type=int, default=None,
                        help="Thread pool size. Default 256")
    parser.add_argument("--geo", action="store_true",
                        help="Wi-Fi geolocation using env key MLS_API_KEY or GOOGLE_GEO_API_KEY")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--silent", action="store_true", help="Reduce console chatter")
    parser.add_argument("--wifi_interface", help="Specify Wi-Fi interface (optional)")
    args = parser.parse_args()

    if args.silent:
        logging.getLogger().setLevel(logging.WARNING)

    logging.info(f"NST started on {platform.system()}")

    # Determine selected modules
    if args.all or not any([args.wifi, args.bluetooth, args.os, args.network, args.ports]):
        selected = None  # run all
    else:
        selected = []
        if args.wifi:      selected.append("wifi")
        if args.bluetooth: selected.append("bluetooth")
        if args.os:        selected.append("os")
        if args.network:   selected.append("network")
        if args.ports:     selected.append("ports")

    # Options propagated to modules
    scan_options = {}
    if args.wifi_interface:
        scan_options["wifi_interface"] = args.wifi_interface
    if args.geo:
        scan_options["geo"] = True

    # Hosts parsing
    if args.hosts:
        scan_options["hosts"] = [h.strip() for h in args.hosts.split(",") if h.strip()]

    # Port scanning config (fast by default)
    if args.all or args.ports:
        print_section("Port Scan Configuration")
        if args.fast or args.silent:
            scan_options["scan_type"] = "top"
            scan_options["no_banner"] = True
            if args.timeout is None: scan_options["timeout"] = 0.25
            if args.workers is None: scan_options["workers"] = 300
        else:
            scan_options["scan_type"] = choose_port_scan_type(default_code="top")
            scan_options["no_banner"] = bool(args.no_banner)
        if args.ports:
            scan_options["port_range"] = args.ports
        if args.timeout is not None:
            scan_options["timeout"] = args.timeout
        if args.workers is not None:
            scan_options["workers"] = args.workers

    print_section("Running selected scans")
    scanner = Scanner(port_range=args.ports if args.ports else "1-1024")
    scanner.run_scan(selected, **scan_options)

    # ASCII-only summary (avoid Unicode arrows for CP1252 consoles)
    print_section("Summary")
    for entry in scanner.get_results():
        mod = entry["module"].capitalize()
        logging.info(f"{mod} -> {entry['result']}")

    logging.info("NST complete.")

if __name__ == "__main__":
    main()
