# network_explorer.py
# Clean CLI orchestrator with stable colors, tidy summaries, and safe kwarg passing.
# Python 3.9+ compatible

import argparse
import json
import logging
import os
import sys
import threading
from datetime import datetime

# Ensure the current directory is in path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import colorama
    colorama.init() # Initialize colorama for Windows support
except ImportError:
    pass

# Imports
from wifi_scan import scan_wifi
from bluetooth_scan import scan_bluetooth
from os_security import check_os_security
# UPDATED: Imported get_network_devices from network_scanner (the Rich version)
from network_scanner import run_network_metadata_scan, get_quick_identity, lookup_target_ip, get_network_devices
# UPDATED: Removed get_network_devices from here to avoid conflict
from port_scanner import run_port_scan 
from pentest_tools import run_pentest_suite

try:
    from texttable import Texttable
except Exception:
    Texttable = None

# ── Colors ─────────────────────────────────────────────────────────────────────

class Colors:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.RESET = "\x1b[0m" if enabled else ""
        self.HEADER = "\x1b[38;5;45m" if enabled else ""     # cyan
        self.OK = "\x1b[38;5;40m" if enabled else ""         # green
        self.WARN = "\x1b[38;5;214m" if enabled else ""      # orange
        self.BAD = "\x1b[38;5;196m" if enabled else ""       # red
        self.MUTED = "\x1b[38;5;245m" if enabled else ""     # gray
        self.HIGHLIGHT = "\x1b[38;5;226m" if enabled else "" # yellow

C = Colors(enabled=True)

# ── Console helpers ────────────────────────────────────────────────────────────

def print_section(title: str) -> None:
    """Pretty section divider with timestamp + color."""
    stamp = datetime.now().strftime("%H:%M:%S")
    line = "=" * 60
    print(f"\n{C.HEADER}{line}\n {title} — {stamp}\n{line}{C.RESET}\n")

def setup_logging(silent: bool = False) -> None:
    """
    Sets up logging handlers. Ensures we don't duplicate handlers on reload.
    """
    root = logging.getLogger()
    
    # If handlers exist, clear them to avoid duplicates
    if root.hasHandlers():
        root.handlers.clear()

    if silent:
        root.setLevel(logging.WARNING)
    else:
        root.setLevel(logging.INFO)

    # File Handler
    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = os.path.join("logs", f"NEX_{ts}.log")
    
    file_h = logging.FileHandler(logfile, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    file_h.setFormatter(fmt)
    root.addHandler(file_h)

    # Console Handler (Stream)
    console_h = logging.StreamHandler(sys.stdout)
    console_h.setFormatter(fmt)
    root.addHandler(console_h)
    
    # Prune old logs
    try:
        now = datetime.now().timestamp()
        for name in os.listdir("logs"):
            p = os.path.join("logs", name)
            if os.path.isfile(p) and now - os.path.getctime(p) > 7 * 24 * 3600:
                try:
                    os.remove(p)
                except OSError:
                    pass 
    except Exception:
        logging.debug("log prune warn", exc_info=True)


# ── Formatting helpers ─────────────────────────────────────────────────────────

def _table_or_lines(headers: list[str], rows: list[list[str]]) -> None:
    if not rows:
        print(f"  {C.MUTED}No data.{C.RESET}")
        return

    if Texttable:
        t = Texttable()
        t.header(headers)
        t.set_deco(Texttable.HEADER | Texttable.BORDER | Texttable.VLINES | Texttable.HLINES)
        for r in rows:
            t.add_row(r)
        print(t.draw())
        return

    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            w = len(str(cell))
            if i < len(widths):
                widths[i] = max(widths[i], w)
            else:
                widths.append(w)
                
    fmt = " | ".join("{:<" + str(w) + "}" for w in widths)
    div = "-+-".join("-" * w for w in widths)
    
    print(fmt.format(*headers))
    print(div)
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))
        print(div)


def print_summary(results, show_colors: bool) -> None:
    color = Colors(enabled=show_colors)
    by_mod = {e["module"]: e["result"] for e in results}

    # Wi-Fi
    if "wifi" in by_mod:
        print_section("Wi-Fi Summary")
        w = by_mod["wifi"]
        if isinstance(w, dict):
            if w.get("networks"):
                rows = []
                for n in w["networks"]:
                    ssid = n.get("ssid") or "<hidden>"
                    bcnt = len(n.get("bssids") or [])
                    sig = n.get("signal")
                    ch = n.get("channel")
                    
                    sig_str = f"{sig}%"
                    if show_colors:
                        if sig > 70: sig_str = f"{color.OK}{sig}%{color.RESET}"
                        elif sig > 40: sig_str = f"{color.WARN}{sig}%{color.RESET}"
                        else: sig_str = f"{color.BAD}{sig}%{color.RESET}"
                    
                    loc_str = "-"
                    if n.get("location"):
                        ll = n["location"]
                        lat, lng = ll.get('lat'), ll.get('lng')
                        acc = n.get('accuracy_m')
                        loc_str = f"{lat:.4f}, {lng:.4f}"
                        if acc:
                            loc_str += f" (±{int(acc)}m)"

                    rows.append([ssid, bcnt, sig_str, ch or "?", loc_str])
                _table_or_lines(["SSID", "BSSIDs", "Signal", "Ch", "Geo"], rows)
                print(f"\n  {color.MUTED}Total Networks: {len(rows)}{color.RESET}")
            else:
                note = w.get("reason") or w.get("note") or "No networks found."
                print(f"  {color.WARN}No Wi-Fi data.{color.RESET}")
                print(f"  {color.MUTED}Reason: {note}{color.RESET}")
        else:
            print(f"  {w}")

    # Host / Network
    if "network" in by_mod:
        print_section("Host / Network")
        n = by_mod["network"]
        if isinstance(n, dict):
            _table_or_lines(
                ["Hostname", "Local IP", "OS"],
                [[n.get("hostname", "?"), n.get("local_ip", "?"), n.get("os", "?")]],
            )

            if n.get("interfaces"):
                rows = []
                for iface in n["interfaces"]:
                    rows.append([
                        iface.get("name", "?"),
                        iface.get("ip", "?"),
                        iface.get("family", "?"),
                    ])
                print(f"\n  {color.HEADER}Interfaces:{color.RESET}")
                _table_or_lines(["Interface", "Address", "Family"], rows)

            if n.get("gateway"):
                print(f"\n  {color.MUTED}Default Gateway:{color.RESET} {n['gateway']}")

            if n.get("public"):
                pub = n["public"]
                line = f"  {color.MUTED}Public IP:{color.RESET}       {pub.get('ip','?')}"
                if pub.get("isp"):
                    line += f" | ISP: {pub['isp']}"
                if pub.get("asn"):
                    line += f" ({pub['asn']})"
                print(line)
                
                loc_parts = [pub.get('city'), pub.get('region'), pub.get('country')]
                loc_str = ", ".join([p for p in loc_parts if p])
                if loc_str:
                    print(f"  {color.MUTED}Location:{color.RESET}        {loc_str}")
                
                if pub.get("lat") and pub.get("lon"):
                    print(f"  {color.MUTED}Coordinates:{color.RESET}     {pub['lat']:.4f}, {pub['lon']:.4f}")
        else:
            print(f"  {n}")

    # Port scan results
    if "ports" in by_mod:
        print_section("Port Scan Results")
        p = by_mod["ports"]
        if isinstance(p, dict):
            rows = []
            for ip, info in p.items():
                ports_map = info.get("open_ports") or {}
                if not ports_map:
                    ports_str = "None"
                else:
                    ports_sorted = sorted(ports_map.keys())
                    if len(ports_sorted) > 15:
                        ports_str = ",".join(map(str, ports_sorted[:15])) + f"... (+{len(ports_sorted)-15})"
                    else:
                        ports_str = ",".join(map(str, ports_sorted))
                
                rows.append([ip, ports_str, f"{info.get('duration', 0):.1f}s"])
            _table_or_lines(["Host", "Open Ports", "Duration"], rows)
        else:
            print(f"  {p}")

    # OS Checks
    if "os" in by_mod:
        print_section("OS Security Posture")
        data = by_mod["os"].get("data", {})
        if data:
             fw = data.get("firewall", "unknown")
             av = data.get("antivirus", "unknown")
             c_fw = color.OK if "active" in fw else color.WARN
             c_av = color.OK if "detected" in av else color.WARN
             
             print(f"  Firewall: {c_fw}{fw.upper()}{color.RESET}")
             print(f"  Antivirus: {c_av}{av.upper()}{color.RESET}")
             
             if data.get("details"):
                 print("\n  Details:")
                 for d in data["details"]:
                     print(f"   - {d}")
        else:
            print(f"  {by_mod['os']}")

    # Bluetooth
    if "bluetooth" in by_mod:
        print_section("Bluetooth Devices")
        b = by_mod["bluetooth"]
        if isinstance(b, dict) and b.get("devices"):
            rows = []
            for d in b["devices"]:
                name = d.get("name", "Unknown")
                rssi = d.get("rssi", "?")
                addr = d.get("address", "?")
                rows.append([name, addr, rssi])
            _table_or_lines(["Name", "Address", "RSSI (dBm)"], rows)
        else:
            print(f"  {color.MUTED}No Bluetooth devices found or module error.{color.RESET}")


# ── Pentest / Inspector ────────────────────────────────────────────────────────

def print_pentest_results(results: dict):
    print_section("Inspector Results")
    
    # Web
    if "web" in results:
        w = results['web']
        if "error" in w:
            print(f"  {C.BAD}Web Error:{C.RESET} {w['error']}")
        else:
            print(f"  {C.HIGHLIGHT}Target:{C.RESET} {w['target']}")
            print(f"  {C.HIGHLIGHT}Server:{C.RESET} {w.get('server')}")
            
            missing = w.get('missing_security', [])
            if missing:
                print(f"  {C.WARN}Missing Security Headers:{C.RESET}")
                for m in missing:
                    print(f"   - {m}")
            else:
                print(f"  {C.OK}Basic security headers present.{C.RESET}")

    # SSL
    if "ssl" in results:
        s = results['ssl']
        if "error" in s:
             print(f"\n  {C.WARN}SSL/TLS:{C.RESET} {s['error']}")
        else:
             print(f"\n  {C.HIGHLIGHT}SSL Certificate:{C.RESET}")
             print(f"   Issuer: {s.get('issuer')}")
             print(f"   Expires: {s.get('expiry')}")
             print(f"   Valid: {C.OK}{s.get('valid')}{C.RESET}")

    # DNS
    if "dns" in results:
        d = results['dns']
        print(f"\n  {C.HIGHLIGHT}DNS Records:{C.RESET}")
        for k, v in d.items():
            print(f"   {k}: {v}")


# ── IP / Domain Lookup ─────────────────────────────────────────────────────────

def print_lookup_results(data: dict):
    print_section("IP/Domain Lookup Results")
    if "error" in data:
        print(f"  {C.BAD}Error:{C.RESET} {data['error']}")
        return 

    print("  ==========================================================")
    print(f"  {C.HIGHLIGHT}Target:{C.RESET} {data.get('target')} | {C.OK}Resolved:{C.RESET} {data.get('resolved_ip')}")
    print(f"  {C.HIGHLIGHT}ISP/Org:{C.RESET} {data.get('isp')} / {data.get('org')}")
    print(f"  {C.HIGHLIGHT}Location:{C.RESET} {data.get('city')}, {data.get('country')}")
    print(f"  {C.HIGHLIGHT}Coords:{C.RESET} {data.get('lat')}, {data.get('lon')}")
    print(f"  {C.HIGHLIGHT}Timezone:{C.RESET} {data.get('timezone')}")
    print(f"  {C.HIGHLIGHT}AS Number:{C.RESET} {data.get('as')}")
    print("  ==========================================================\n")


# ── Orchestrator ───────────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, port_range: str = "1-1024", output_queue=None, stop_flag=None):
        self.port_range = port_range
        self.output_queue = output_queue
        self.stop_flag = stop_flag or threading.Event()
        self.results = []
        self.scan_functions = {
            "wifi":      scan_wifi,
            "bluetooth": scan_bluetooth,
            "os":        check_os_security,
            "network":   run_network_metadata_scan,
            "ports":     self._run_port_scan,
        }

    def _run_port_scan(self, **kwargs):
        # Wrapper logic 
        try:
            start_port, end_port = map(int, str(kwargs.get("port_range", "1-1024")).split("-"))
        except Exception:
            start_port, end_port = 1, 1024

        return run_port_scan(
            start_port=start_port,
            end_port=end_port,
            scan_type=kwargs.get("scan_type", "top"),
            protocol=kwargs.get("protocol", "tcp"),
            target_hosts=kwargs.get("hosts"),
            no_banner=kwargs.get("no_banner", True),
            timeout=kwargs.get("timeout", 0.30),
            workers=kwargs.get("workers", 256),
            stop_flag=self.stop_flag,
            output_queue=self.output_queue,
        )

    def run_scan(self, selected_modules=None, **scan_options):
        if not selected_modules:
            selected_modules = list(self.scan_functions.keys())

        common = {"stop_flag": self.stop_flag, "output_queue": self.output_queue}
        total = len(selected_modules)

        for i, module in enumerate(selected_modules, 1):
            if not scan_options.get("silent"):
                print(f"  {C.MUTED}Step [{i}/{total}]: Running {module} scan...{C.RESET}")
            
            func = self.scan_functions.get(module)
            if func:
                try:
                    # Explicit mapping for modules that need specific args
                    if module == "wifi":
                        res = func(wifi_interface=scan_options.get("wifi_interface"), 
                                    do_geolocation=scan_options.get("geo"), 
                                    diag=scan_options.get("diag"), **common)
                    elif module == "ports":
                        res = self._run_port_scan(**scan_options) 
                    else:
                        res = func(**common)
                    
                    self.results.append({"module": module, "result": res})
                except Exception as e:
                    logging.error(f"Error in {module}: {e}")

    def get_results(self):
        return self.results


# ── CLI ────────────────────────────────────────────────────────────────────────

def choose_port_scan_type() -> tuple[str, str]:
    """Selection for scan type and protocol"""
    print(f"\n  {C.HEADER}Port Scan Configuration{C.RESET}\n")
    print(f"  {C.HIGHLIGHT}1.{C.RESET} Top TCP ports {C.MUTED}(Fast, Recommended){C.RESET}")
    print(f"  {C.HIGHLIGHT}2.{C.RESET} Full Connect TCP {C.MUTED}(Slower, more accurate){C.RESET}")
    print(f"  {C.HIGHLIGHT}3.{C.RESET} UDP Services {C.MUTED}(Payload probe){C.RESET}")
    
    sel = input(f"\n  {C.OK}>{C.RESET}  ").strip()
    
    if sel == "2": return "connect", "tcp"
    if sel == "3": return "top", "udp"
    return "top", "tcp"

def main_menu() -> tuple[list[str], bool, str]:
    """
    Interactive Main Menu. 
    Returns: (list_of_modules, auto_mode_bool, specific_action_string)
    """
    print(f"{C.HEADER}  Select Scan Mode:{C.RESET}\n")
    print(f"  {C.HIGHLIGHT}1.{C.RESET} Full Scan")
    print(f"  {C.HIGHLIGHT}2.{C.RESET} Wi-Fi Scan")
    print(f"  {C.HIGHLIGHT}3.{C.RESET} Port Scan")
    print(f"  {C.HIGHLIGHT}4.{C.RESET} LAN Device Discovery (ARP + Vendor)")
    print(f"  {C.HIGHLIGHT}5.{C.RESET} Web & DNS Inspector")
    print(f"  {C.HIGHLIGHT}6.{C.RESET} IP/Domain Lookup")
    print(f"  {C.HIGHLIGHT}7.{C.RESET} Network Metadata")
    print(f"  {C.HIGHLIGHT}8.{C.RESET} OS Security Check")
    print(f"  {C.HIGHLIGHT}9.{C.RESET} Bluetooth Scan")
    print(f"  {C.HIGHLIGHT}0.{C.RESET} Exit")
    
    choice = input(f"\n  {C.OK}>{C.RESET}  ").strip()
    
    # Returns: modules, auto_mode, special_action_key
    if choice == "1": return (["wifi", "bluetooth", "os", "network", "ports"], True, None)
    if choice == "2": return (["wifi"], True, None)
    if choice == "3": return (["ports"], False, None)
    if choice == "4": return ([], True, "lan_discovery")
    if choice == "5": return ([], True, "pentest")
    if choice == "6": return ([], True, "lookup")
    if choice == "7": return (["network"], True, None)
    if choice == "8": return (["os"], True, None)
    if choice == "9": return (["bluetooth"], True, None)
    if choice == "0": sys.exit(0)
    
    print(f"  {C.WARN}Invalid choice, running Full Scan.{C.RESET}")
    return (["wifi", "bluetooth", "os", "network", "ports"], True, None)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    # 1. Setup Arguments
    parser = argparse.ArgumentParser("Network Explorer")
    parser.add_argument("--wifi", action="store_true", help="Run Wi-Fi scan")
    parser.add_argument("--bluetooth", action="store_true", help="Run Bluetooth scan")
    parser.add_argument("--os", action="store_true", help="Run OS security scan")
    parser.add_argument("--network", action="store_true", help="Run Network metadata scan")
    parser.add_argument("--ports", nargs="?", const="1-1024", help="Port scan range")
    # Tuning
    parser.add_argument("--host", "--hosts", dest="hosts", help="Target host(s)")
    parser.add_argument("--fast", action="store_true", help="Force fast mode")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--workers", type=int, default=None)
    # Wi-Fi
    parser.add_argument("--geo", action="store_true", help="Wi-Fi geolocation")
    parser.add_argument("--wifi_interface", help="Specify Wi-Fi interface")
    parser.add_argument("--wifi-diag", action="store_true", help="Wi-Fi diagnostic dump")
    # Output
    parser.add_argument("--json", dest="json_out", help="Write full results to a JSON file")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--silent", action="store_true", help="Reduce console chatter")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    # 2. Setup Globals
    global C
    C = Colors(enabled=not args.no_color)
    
    # 3. Setup Logging ONCE
    setup_logging(silent=args.silent)

    # 4. Print Header
    print(f"{C.HEADER}")
    print(r"""
               __                      __  
   ____  ___  / /__      ______  _____/ /__
  / __ \/ _ \/ __/ | /| / / __ \/ ___/ //_/
 / / / /  __/ /_ | |/ |/ / /_/ / /  / ,<   
/_/ /_/\___/\__/ |__/|__/\____/_/  /_/|_|  
  ___  _  ______  / /___  ________  _____  
 / _ \| |/_/ __ \/ / __ \/ ___/ _ \/ ___/  
/  __/>  </ /_/ / / /_/ / /  /  __/ /      
\___/_/|_/ .___/_/\____/_/   \___/_/       
        /_/                                """)
    print("")

    # 5. One-Shot CLI Check
    any_flag = any([args.wifi, args.bluetooth, args.os, args.network, args.ports, args.all])
    
    if any_flag:
        # Non-Interactive Mode
        if args.all:
            selected = ["wifi", "bluetooth", "os", "network", "ports"]
            auto_mode = True
        else:
            selected = []
            if args.wifi:      selected.append("wifi")
            if args.bluetooth: selected.append("bluetooth")
            if args.os:        selected.append("os")
            if args.network:   selected.append("network")
            if args.ports:     selected.append("ports")
            auto_mode = False 

        # Execute Scan
        _run_scan_logic(selected, auto_mode, args)
        return # Exit after CLI scan

    # 6. Interactive Loop
    if not args.silent:
        _print_identity()

    while True:
        selected, auto_mode, special_action = main_menu()
        print("")
        
        # Handle Lookup Tool
        if special_action == "lookup":
            while True:
                print(f"\n  {C.HEADER}:: IP/Domain Lookup ::{C.RESET}")
                target = input(f"  {C.OK}Enter IP/Domain (or '1' for Menu, '0' for Exit):{C.RESET} ").strip()
                
                if target == '1': break
                if target == '0': sys.exit(0)
                if not target: continue

                res = lookup_target_ip(target)
                print_lookup_results(res)
            continue

        # Handle Pentest Tool
        if special_action == "pentest":
            while True:
                print(f"\n  {C.HEADER}:: Web & DNS Inspector ::{C.RESET}")
                target = input(f"  {C.OK}Enter Target IP/Domain (or '1' for Menu, '0' for Exit):{C.RESET} ").strip()
                
                if target == '1': break
                if target == '0': sys.exit(0)
                if not target: continue

                print(f"\n  {C.MUTED}Running checks...{C.RESET}")
                res = run_pentest_suite(target)
                print_pentest_results(res)
            continue

        # Handle LAN Discovery
        if special_action == "lan_discovery":
            while True:
                print(f"  {C.MUTED}Scanning local ARP table / Neighbors...{C.RESET}")
                devs = get_network_devices() # Now using the correct version
                print_section("LAN Discovery (ARP/Neighbor)")
                
                if devs["IPv4"]:
                    rows = []
                    for item in devs["IPv4"]:
                        rows.append([item['ip'], item['mac'], item['vendor']])
                    _table_or_lines(["IP Address", "MAC Address", "Vendor"], rows)
                else:
                    print("  No neighbors found.")
                
                choice = input(f"\n  {C.OK}[Enter] Rescan, '1' Menu, '0' Exit:{C.RESET} ").strip()
                if choice == '1': break
                if choice == '0': sys.exit(0)
            continue

        # Handle Standard Scans
        logging.info(f"{C.OK}Scan started.{C.RESET}\n")
        _run_scan_logic(selected, auto_mode, args)
        
        print("\n" + "=" * 70)
        print(f"Visit: {C.MUTED}https://seperet.com{C.RESET}")
        print(f"Repo: {C.MUTED}https://github.com/denv3rr/network-explorer{C.RESET}")
        print("=" * 70 + "\n")
        
        # Loop restarts here automatically

def _print_identity():
    try:
        ident = get_quick_identity()
        ip = ident.get("local_ip") or "?"
        host = ident.get("hostname") or "?"
        conn = ident.get("connection_type") or "Unknown"
        pub = ident.get("public") or {}
        c_conn = C.OK if conn in ["Wired", "Wi-Fi"] else C.WARN
        
        print(f"  {C.HEADER}====================================={C.RESET}")
        print(f"  Hostname    : {C.OK}{host}{C.RESET}")
        print(f"  Address     : {C.OK}{ip}{C.RESET} ({c_conn}{conn}{C.RESET})")
        if pub.get('city'):
            print(f"  Location    : {C.MUTED}{pub.get('city')}, {pub.get('country')}{C.RESET}")
        if pub.get('ip'):
            print(f"  Public IP   : {C.MUTED}{pub.get('ip')}{C.RESET}")
        else:
            print(f"  Public IP   : {C.BAD}Unavailable{C.RESET}")
        print(f"  {C.HEADER}====================================={C.RESET}\n\n\n") 
    except: pass

def _run_scan_logic(selected, auto_mode, args):
    """Helper to run the actual Scanner orchestrator to avoid code duplication."""
    scan_options = {}
    if args.wifi_interface: scan_options["wifi_interface"] = args.wifi_interface
    if args.geo: scan_options["geo"] = True
    if args.wifi_diag: scan_options["diag"] = True
    if args.hosts: scan_options["hosts"] = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if args.silent: scan_options["silent"] = True

    if "ports" in selected:
        if args.fast or args.silent or auto_mode:
            scan_options["scan_type"] = "top"
            scan_options["protocol"] = "tcp"
            scan_options["no_banner"] = True
            scan_options["timeout"] = 0.15 if args.timeout is None else args.timeout
            scan_options["workers"] = 300 if args.workers is None else args.workers
            if not args.silent:
                print(f"  {C.OK}[AUTO]{C.RESET} Running Fast Port Scan (Top TCP)...")
        else:
            stype, proto = choose_port_scan_type()
            scan_options["scan_type"] = stype
            scan_options["protocol"] = proto
            scan_options["no_banner"] = bool(args.no_banner)
            
        if args.ports: scan_options["port_range"] = args.ports

    scanner = Scanner(port_range=args.ports if args.ports else "1-1024")
    scanner.run_scan(selected, **scan_options)

    print_summary(scanner.get_results(), show_colors=not args.no_color)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(scanner.get_results(), f, indent=2, default=str)
            logging.info(f"Saved JSON results -> {args.json_out}")
        except Exception as e:
            logging.error(f"Failed writing JSON: {e}")

    print("\n\n")
    logging.info(f"{C.OK}Scan completed.{C.RESET}")


if __name__ == "__main__":
    main()