# network_security_tester.py
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

from wifi_scan import scan_wifi
from bluetooth_scan import scan_bluetooth
from os_security import check_os_security
from network_scanner import run_network_metadata_scan, get_quick_identity
from port_scanner import run_port_scan

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

def setup_logging() -> None:
    if hasattr(sys.stdout, 'reconfigure'):
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
    
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    file_h.setFormatter(fmt)
    console_h.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    
    if root.hasHandlers():
        root.handlers.clear()
        
    root.addHandler(file_h)
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


def print_human_summary(results, show_colors: bool) -> None:
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

    def _run_port_scan(
        self,
        *,
        port_range="1-1024",
        scan_type="top",
        protocol="tcp",
        hosts=None,
        no_banner=True,
        timeout=0.30,
        workers=256,
        **_ignored,
    ):
        try:
            start_port, end_port = map(int, str(port_range).split("-"))
        except Exception:
            logging.warning("Invalid port range; fallback to 1-1024.")
            start_port, end_port = 1, 1024

        return run_port_scan(
            start_port=start_port,
            end_port=end_port,
            scan_type=scan_type,
            protocol=protocol,
            target_hosts=hosts,
            no_banner=no_banner,
            timeout=timeout,
            workers=workers,
            stop_flag=self.stop_flag,
            output_queue=self.output_queue,
        )

    def run_scan(self, selected_modules=None, **scan_options):
        if not selected_modules:
            selected_modules = list(self.scan_functions.keys())

        common = {"stop_flag": self.stop_flag, "output_queue": self.output_queue}
        total_steps = len(selected_modules)
        
        for i, module in enumerate(selected_modules, 1):
            # Step Indicator
            if not scan_options.get("silent", False):
                print(f"  {C.MUTED}Step [{i}/{total_steps}]: Running {module} scan...{C.RESET}")

            func = self.scan_functions.get(module)
            if not func:
                logging.warning(f"Unknown module: {module}")
                continue
            try:
                if module == "wifi":
                    result = func(
                        wifi_interface=scan_options.get("wifi_interface"),
                        do_geolocation=scan_options.get("geo", False),
                        diag=scan_options.get("diag", False),
                        **common,
                    )
                elif module == "ports":
                    result = func(
                        port_range=scan_options.get("port_range", self.port_range),
                        scan_type=scan_options.get("scan_type", "top"),
                        protocol=scan_options.get("protocol", "tcp"),
                        hosts=scan_options.get("hosts"),
                        no_banner=scan_options.get("no_banner", True),
                        timeout=scan_options.get("timeout", 0.30),
                        workers=scan_options.get("workers", 256),
                        **common,
                    )
                else:
                    result = func(**common)

                self.results.append({"module": module, "result": result})

            except Exception as e:
                logging.error(f"{module} scan error: {e}", exc_info=True)
                self.results.append({"module": module, "result": f"Error: {e}"})

    def get_results(self):
        return self.results


# ── CLI ────────────────────────────────────────────────────────────────────────

def choose_port_scan_type() -> tuple[str, str]:
    """Selection for scan type and protocol"""
    # Clearer alignment
    print(f"\n  {C.HEADER}Port Scan Configuration{C.RESET}\n")
    print(f"  {C.HIGHLIGHT}1.{C.RESET} Top TCP ports {C.MUTED}(Fast, Recommended){C.RESET}")
    print(f"  {C.HIGHLIGHT}2.{C.RESET} Full Connect TCP {C.MUTED}(Slower, more accurate){C.RESET}")
    print(f"  {C.HIGHLIGHT}3.{C.RESET} UDP Services {C.MUTED}(Payload probe){C.RESET}")
    
    sel = input(f"\n  {C.OK}>{C.RESET}  ").strip()
    
    if sel == "2": return "connect", "tcp"
    if sel == "3": return "top", "udp"
    return "top", "tcp" # Default

def main_menu() -> tuple[list[str], bool]:
    """Interactive Main Menu. Returns (modules, auto_mode_bool)"""
    print(f"{C.HEADER}  Select Scan Mode:{C.RESET}\n")
    print(f"  {C.HIGHLIGHT}1.{C.RESET} Full Scan")
    print(f"  {C.HIGHLIGHT}2.{C.RESET} Wi-Fi Scan")
    print(f"  {C.HIGHLIGHT}3.{C.RESET} Port Scan (Interactive)")
    print(f"  {C.HIGHLIGHT}4.{C.RESET} Network Metadata & Host Info")
    print(f"  {C.HIGHLIGHT}5.{C.RESET} OS Security Check")
    print(f"  {C.HIGHLIGHT}6.{C.RESET} Bluetooth Scan")
    print(f"  {C.HIGHLIGHT}0.{C.RESET} Exit")
    
    choice = input(f"\n  {C.OK}>{C.RESET}  ").strip()
    
    if choice == "1": return (["wifi", "bluetooth", "os", "network", "ports"], True) # Auto True
    if choice == "2": return (["wifi"], True)
    if choice == "3": return (["ports"], False) # Auto False (Ask me!)
    if choice == "4": return (["network"], True)
    if choice == "5": return (["os"], True)
    if choice == "6": return (["bluetooth"], True)
    if choice == "0": sys.exit(0)
    
    print(f"  {C.WARN}Invalid choice, running Full Scan by default.{C.RESET}")
    return (["wifi", "bluetooth", "os", "network", "ports"], True)

def main():
    setup_logging()

    parser = argparse.ArgumentParser("Network Explorer")
    # module toggles
    parser.add_argument("--wifi", action="store_true", help="Run Wi-Fi scan")
    parser.add_argument("--wifi-diag", action="store_true", help="Wi-Fi diagnostic dump")
    parser.add_argument("--bluetooth", action="store_true", help="Run Bluetooth scan")
    parser.add_argument("--os", action="store_true", help="Run OS security scan")
    parser.add_argument("--network", action="store_true", help="Run Network metadata scan")
    parser.add_argument("--ports", nargs="?", const="1-1024", help="Port scan range")

    # tuning
    parser.add_argument("--host", "--hosts", dest="hosts", help="Target host(s)")
    parser.add_argument("--fast", action="store_true", help="Force fast mode")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--workers", type=int, default=None)

    # Wi-Fi options
    parser.add_argument("--geo", action="store_true", help="Wi-Fi geolocation")
    parser.add_argument("--wifi_interface", help="Specify Wi-Fi interface")

    # output & run style
    parser.add_argument("--json", dest="json_out", help="Write full results to a JSON file")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--silent", action="store_true", help="Reduce console chatter")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    global C
    C = Colors(enabled=not args.no_color)

    if args.silent:
        logging.getLogger().setLevel(logging.WARNING)

    # Header
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

    # --- IDENTITY BLOCK ---
    if not args.silent:
        try:
            ident = get_quick_identity()
            ip = ident.get("local_ip") or "?"
            host = ident.get("hostname") or "?"
            conn = ident.get("connection_type") or "Unknown"
            
            pub = ident.get("public") or {}
            city = pub.get("city") or ""
            country = pub.get("country") or ""
            
            c_conn = C.OK if conn in ["Wired", "Wi-Fi"] else C.WARN
            
            print(f"  {C.HEADER}====================================={C.RESET}")
            print(f"  {C.HIGHLIGHT}[ CURRENT ]{C.RESET}")
            print(f"  Hostname    : {C.OK}{host}{C.RESET}")
            print(f"  Address     : {C.OK}{ip}{C.RESET} ({c_conn}{conn}{C.RESET})")
            if city or country:
                print(f"  Location    : {C.MUTED}{city}, {country}{C.RESET}")
            if pub.get('ip'):
                print(f"  Public IP   : {C.MUTED}{pub.get('ip')}{C.RESET}")
            print(f"  {C.HEADER}====================================={C.RESET}\n\n\n") 
        except Exception: pass

    # Check for any command line flags
    any_flag = any([args.wifi, args.bluetooth, args.os, args.network, args.ports, args.all])
    auto_mode = False

    if any_flag:
        # CLI usage
        if args.all:
             selected = ["wifi", "bluetooth", "os", "network", "ports"]
             auto_mode = True # Assume auto if --all is passed
        else:
            selected = []
            if args.wifi:      selected.append("wifi")
            if args.bluetooth: selected.append("bluetooth")
            if args.os:        selected.append("os")
            if args.network:   selected.append("network")
            if args.ports:     selected.append("ports")
    else:
        # Interactive Menu usage
        selected, auto_mode = main_menu()
        print("")
        logging.info(f"{C.OK}Scan started.{C.RESET}\n")

    # options to propagate
    scan_options = {}
    if args.wifi_interface: scan_options["wifi_interface"] = args.wifi_interface
    if args.geo: scan_options["geo"] = True
    if args.wifi_diag: scan_options["diag"] = True
    if args.hosts: scan_options["hosts"] = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if args.silent: scan_options["silent"] = True

    # port scan configuration
    if "ports" in selected:
        # If auto_mode is True (Full Scan selected), skip the prompt
        if args.fast or args.silent or auto_mode:
            scan_options["scan_type"] = "top"
            scan_options["protocol"] = "tcp"
            scan_options["no_banner"] = True
            if args.timeout is None: scan_options["timeout"] = 0.15
            if args.workers is None: scan_options["workers"] = 300
            
            # Only print if it's not silent and we are in auto mode
            if not args.silent:
                print(f"  {C.OK}[AUTO]{C.RESET} Running Fast Port Scan (Top TCP)...")
        else:
            # Interactive Choice for UDP/TCP
            stype, proto = choose_port_scan_type()
            scan_options["scan_type"] = stype
            scan_options["protocol"] = proto
            scan_options["no_banner"] = bool(args.no_banner)
        
        if args.ports: scan_options["port_range"] = args.ports
        if args.timeout is not None: scan_options["timeout"] = args.timeout
        if args.workers is not None: scan_options["workers"] = args.workers

    scanner = Scanner(port_range=args.ports if args.ports else "1-1024")
    scanner.run_scan(selected, **scan_options)

    # grouped readable summary
    print_human_summary(scanner.get_results(), show_colors=not args.no_color)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(scanner.get_results(), f, indent=2, default=str)
            logging.info(f"Saved JSON results -> {args.json_out}")
        except Exception as e:
            logging.error(f"Failed writing JSON: {e}")

    print("\n" + "=" * 70)
    print(f"{C.MUTED} Visit: https://seperet.com{C.RESET}")
    print(f"{C.MUTED} Repo: https://github.com/denv3rr/network-explorer{C.RESET}")
    print("=" * 70 + "\n")
    logging.info(f"{C.OK}Scan completed.{C.RESET}")


if __name__ == "__main__":
    main()