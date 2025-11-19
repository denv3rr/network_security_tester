# network_security_tester.py
# Clean CLI orchestrator with stable colors, tidy summaries, and safe kwarg passing.

import argparse
import json
import logging
import os
import sys
import threading
from datetime import datetime

from wifi_scan import scan_wifi
from bluetooth_scan import scan_bluetooth
from os_security import check_os_security
from network_scanner import run_network_metadata_scan
from port_scanner import run_port_scan

try:
    from texttable import Texttable
except Exception:
    Texttable = None


# ── Colors (stable; disable with --no-color) ───────────────────────────────────

class Colors:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.RESET = "\x1b[0m" if enabled else ""
        self.HEADER = "\x1b[38;5;45m" if enabled else ""     # cyan
        self.OK = "\x1b[38;5;40m" if enabled else ""         # green
        self.WARN = "\x1b[38;5;214m" if enabled else ""      # orange
        self.BAD = "\x1b[38;5;196m" if enabled else ""       # red
        self.MUTED = "\x1b[38;5;245m" if enabled else ""     # gray

C = Colors(enabled=True)


# ── Console helpers ────────────────────────────────────────────────────────────

def print_section(title: str) -> None:
    """Pretty section divider with timestamp + color."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "=" * 66
    print(f"\n{C.HEADER}{line}\n{title} — {stamp}\n{line}{C.RESET}\n")

def setup_logging() -> None:
    """
    File + console logger. Console uses UTF-8 with replacement so odd glyphs
    never crash CP1252 terminals. Old logs are pruned (7 days).
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
    file_h.setFormatter(fmt)
    console_h.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(file_h)
    root.addHandler(console_h)

    # prune old logs
    try:
        now = datetime.now().timestamp()
        for name in os.listdir("logs"):
            p = os.path.join("logs", name)
            if os.path.isfile(p) and now - os.path.getctime(p) > 7 * 24 * 3600:
                os.remove(p)
    except Exception:
        logging.debug("log prune warn", exc_info=True)


# ── Formatting helpers ─────────────────────────────────────────────────────────

def _table_or_lines(headers, rows) -> None:
    """
    Print a nice table if texttable is available; otherwise, aligned plain text.
    """
    if Texttable:
        t = Texttable()
        t.header(headers)
        for r in rows:
            t.add_row(r)
        print(t.draw())
        return

    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    fmt = "  " + "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))


def print_human_summary(results, show_colors: bool) -> None:
    """
    results: list of {"module": str, "result": any}
    Render grouped, readable summary with tables.
    """
    color = Colors(enabled=show_colors)
    by_mod = {e["module"]: e["result"] for e in results}

    # Wi-Fi
    if "wifi" in by_mod:
        print_section("Wi-Fi Summary")
        w = by_mod["wifi"]
        if isinstance(w, dict) and w.get("networks"):
            rows = []
            for n in w["networks"]:
                ssid = n.get("ssid") or "<hidden>"
                bcnt = len(n.get("bssids") or [])
                sig = n.get("signal")
                ch = n.get("channel")
                loc = ""
                if n.get("location"):
                    ll = n["location"]
                    acc = n.get("accuracy_m")
                    loc = f"{ll.get('lat'):.5f},{ll.get('lng'):.5f}" + (f" ±{int(acc)}m" if acc else "")
                rows.append([ssid, bcnt, f"{sig if sig is not None else '?'}%", ch or "?", loc or "-"])
            _table_or_lines(["SSID", "BSSIDs", "Signal", "Channel", "Geo"], rows)
        else:
            note = ""
            if isinstance(w, dict):
                note = w.get("note") or w.get("reason") or ""
            print(f"  {color.MUTED}No Wi-Fi data.{(' '+note) if note else ''}{color.RESET}")

    # Host / OS / Public IP & Geo (from network_scanner)
    if "network" in by_mod:
        print_section("Host / Network")
        n = by_mod["network"]
        if isinstance(n, dict):
            # A) Host row
            _table_or_lines(
                ["Hostname", "Local IP", "OS"],
                [[n.get("hostname", "?"), n.get("local_ip", "?"), n.get("os", "?")]],
            )

            # B) Interfaces
            if n.get("interfaces"):
                rows = []
                for iface in n["interfaces"]:
                    rows.append([
                        iface.get("name", "?"),
                        iface.get("ip", "?"),
                        iface.get("family", "?"),
                    ])
                print()
                _table_or_lines(["Interface", "Address", "Family"], rows)

            # C) Gateway
            if n.get("gateway"):
                print(f"\n  {color.MUTED}Default Gateway:{color.RESET} {n['gateway']}")

            # D) Public IP + Geo
            if n.get("public"):
                pub = n["public"]
                line = f"  {color.MUTED}Public:{color.RESET} {pub.get('ip','?')}  {pub.get('isp','')}"
                if pub.get("asn"):
                    line += f"  ({pub['asn']})"
                print(line)
                if pub.get("city") or pub.get("country"):
                    print(f"  {color.MUTED}Location:{color.RESET} {pub.get('city','?')}, {pub.get('region','?')}, {pub.get('country','?')}")
                if pub.get("lat") and pub.get("lon"):
                    print(f"  {color.MUTED}Coordinates:{color.RESET} {pub['lat']:.5f},{pub['lon']:.5f}")
        else:
            print(f"  {n}")

    # Port scan results
    if "ports" in by_mod:
        print_section("Port Scan Results")
        p = by_mod["ports"]
        if isinstance(p, dict):
            rows = []
            for ip, info in p.items():
                ports = ",".join(map(str, sorted((info.get("open_ports") or {}).keys())))
                rows.append([ip, ports or "None", f"{info.get('duration', 0):.1f}s"])
            _table_or_lines(["Host", "Open Ports", "Duration"], rows)
        else:
            print(f"  {p}")

    # OS & Bluetooth quick notes
    if "os" in by_mod:
        print_section("OS Security")
        print(f"  {by_mod['os']}")
    if "bluetooth" in by_mod:
        print_section("Bluetooth")
        print(f"  {by_mod['bluetooth']}")


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
        hosts=None,
        no_banner=True,
        timeout=0.30,
        workers=256,
        **_ignored,
    ):
        """
        Wrap the concurrent port scan with safe, fast defaults.
        Explicit keyword signature prevents double-passing collisions.
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
            output_queue=self.output_queue,
        )

    def run_scan(self, selected_modules=None, **scan_options):
        """Execute modules, passing only the kwargs they expect."""
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
                logging.error(f"{module} scan error: {e}")
                self.results.append({"module": module, "result": f"Error: {e}"})

    def get_results(self):
        return self.results


# ── CLI ────────────────────────────────────────────────────────────────────────

def choose_port_scan_type(default_code="top") -> str:
    """Selection for scan type"""
    opts = {
        "1": ("top",     "Top-ports only (fastest, limited)"),
        "2": ("connect", "TCP Connect scan (reliable, slower)"),
        "3": ("udp",     "UDP scan (limited in this build)"),
    }
    
    print("Choose port scan type:\n")
    
    for k, (code, desc) in opts.items():
        print(f"  {k}) {code:7s} — {desc}")
    sel = (input(f"\n  {C.OK}[Enter]{C.RESET}    — default top-ports scan.\n\nSelection: ").strip() or "").lower()
    if sel in opts:
        return opts[sel][0]
    for _, (code, _) in opts.items():
        if sel == code:
            return code
    return default_code


def main():
    setup_logging()

    parser = argparse.ArgumentParser("Network Explorer")
    # module toggles
    parser.add_argument("--wifi", action="store_true", help="Run Wi-Fi scan")
    parser.add_argument("--wifi-diag", action="store_true", help="Wi-Fi diagnostic dump (module may print raw outputs)")
    parser.add_argument("--bluetooth", action="store_true", help="Run Bluetooth scan")
    parser.add_argument("--os", action="store_true", help="Run OS security scan")
    parser.add_argument("--network", action="store_true", help="Run Network metadata scan")
    parser.add_argument("--ports", nargs="?", const="1-1024",
                        help="Port scan range (default: 1-1024). Example: --ports 20-2000")

    # tuning
    parser.add_argument("--host", "--hosts", dest="hosts",
                        help="Target host(s), comma-separated (e.g., 192.168.1.1,192.168.1.41)")
    parser.add_argument("--fast", action="store_true",
                        help="Force fast mode: scan_type=top, no banners, short timeouts")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing (faster)")
    parser.add_argument("--timeout", type=float, default=None, help="Per-port connect timeout (seconds). Default 0.30")
    parser.add_argument("--workers", type=int, default=None, help="Thread pool size. Default 256")

    # Wi-Fi options
    parser.add_argument("--geo", action="store_true",
                        help="Wi-Fi geolocation (BSSID DB if keys present; else IP-geo fallback)")
    parser.add_argument("--wifi_interface", help="Specify Wi-Fi interface (optional)")

    # output & run style
    parser.add_argument("--json", dest="json_out", help="Write full results to a JSON file")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--silent", action="store_true", help="Reduce console chatter")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    # Colors on/off
    global C
    C = Colors(enabled=not args.no_color)

    if args.silent:
        logging.getLogger().setLevel(logging.WARNING)

    logging.info(f"{C.OK}Scan started.{C.RESET}")

    # decide which modules to run
    any_flag = any([args.wifi, args.bluetooth, args.os, args.network, args.ports])
    if args.all or not any_flag:
        selected = ["wifi", "bluetooth", "os", "network", "ports"]
    else:
        selected = []
        if args.wifi:      selected.append("wifi")
        if args.bluetooth: selected.append("bluetooth")
        if args.os:        selected.append("os")
        if args.network:   selected.append("network")
        if args.ports:     selected.append("ports")

    # options to propagate
    scan_options = {}
    if args.wifi_interface:
        scan_options["wifi_interface"] = args.wifi_interface
    if args.geo:
        scan_options["geo"] = True
    if args.wifi_diag:
        scan_options["diag"] = True

    # hosts
    if args.hosts:
        scan_options["hosts"] = [h.strip() for h in args.hosts.split(",") if h.strip()]

    # port scan configuration
    if "ports" in selected:
        print_section("Port Scan Configuration")
        if args.fast or args.silent:
            scan_options["scan_type"] = "top"
            scan_options["no_banner"] = True
            if args.timeout is None:
                scan_options["timeout"] = 0.25
            if args.workers is None:
                scan_options["workers"] = 300
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

    # grouped readable summary
    print_human_summary(scanner.get_results(), show_colors=not args.no_color)

    # optional JSON
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(scanner.get_results(), f, indent=2)
            logging.info(f"Saved JSON results -> {args.json_out}")
        except Exception as e:
            logging.error(f"Failed writing JSON: {e}")

    print("\n\n\n\n\n\n" + "=" * 70)
    print(" Network Explorer \n")
    print(" Visit: https://seperet.com ")
    print(" Repo: https://github.com/denv3rr/network-explorer ")
    print("=" * 70 + "\n")
    logging.info(f"{C.OK}Scan completed.{C.RESET}\n")
    logging.info(f"Check the {C.OK}logs{C.RESET} folder for more details on scans.\n")


if __name__ == "__main__":
    main()
