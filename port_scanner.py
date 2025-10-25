# port_scanner.py
# Concurrent TCP connect scanner with Unicode block progress + ETA,
# tunable timeout/workers, optional banner grabbing, optional target hosts.

import socket
import logging
import platform
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from texttable import Texttable
except Exception:
    Texttable = None

# ---------- Discovery ----------

def _run_safe(cmd):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout
    except Exception as e:
        logging.debug(f"cmd fail {' '.join(cmd)}: {e}")
        return ""

def _is_junk_ip(ip: str) -> bool:
    """Skip multicast/broadcast/loopback/APIPA noise."""
    if ip.startswith("127.") or ip == "0.0.0.0": return True
    if ip.startswith("169.254."): return True
    if ip.startswith("224.") or ip.startswith("239."): return True
    if ip.endswith(".255"): return True
    if ":" in ip and ip.lower().startswith("ff"): return True
    return False

def get_network_devices(output_queue=None, stop_flag=None):
    """
    Heuristic LAN peer discovery via ARP/neighbor tables.
    Good enough for quick triage; not exhaustive.
    """
    devices = {"IPv4": set(), "IPv6": set()}
    osname = platform.system()
    text = ""
    if osname == "Windows":
        text = _run_safe(["arp", "-a"])
        for line in text.splitlines():
            parts = line.split()
            if parts:
                ip = parts[0]
                if ip.count(".") == 3 and not _is_junk_ip(ip):
                    devices["IPv4"].add(ip)
    else:
        text = _run_safe(["ip", "neigh"])
        for line in text.splitlines():
            parts = line.split()
            if parts:
                ip = parts[0]
                if ip.count(".") == 3 and not _is_junk_ip(ip):
                    devices["IPv4"].add(ip)
                elif ":" in ip and not _is_junk_ip(ip):
                    devices["IPv6"].add(ip)

    if output_queue:
        for ip in sorted(devices["IPv4"]):
            output_queue.put(f"  Device found: {ip}")
        for ip in sorted(devices["IPv6"]):
            output_queue.put(f"  Device found: {ip}")
    return {"IPv4": sorted(devices["IPv4"]), "IPv6": sorted(devices["IPv6"])}

# ---------- Ports & tuning ----------

TOP_PORTS = [
    # ~73 common ports
    21,22,23,25,53,67,68,80,110,123,135,137,138,139,143,161,162,389,443,445,465,
    514,587,631,993,995,1025,1433,1521,2049,2375,2376,2483,2484,3128,3306,3389,
    3478,3690,4000,5000,5060,5432,5671,5672,5900,5985,5986,6379,6443,7001,7002,
    7071,7199,8000,8008,8080,8081,8088,8140,8443,8888,9000,9042,9092,9200,9300,
    9418,11211,15672,27017,27018,27019
]

# Defaults will be overridden by CLI when --fast is used
DEFAULT_TIMEOUT = 0.30
DEFAULT_WORKERS = 256

# ---------- Helpers ----------

def _scan_one(ip: str, port: int, timeout: float):
    """Return port if open; else None. TCP connect (no raw sockets)."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            res = sock.connect_ex((ip, port))
            return port if res == 0 else None
        except Exception:
            return None

def _progress_bar(done: int, total: int, start_time: float) -> str:
    """Unicode block progress bar (works fine on modern Windows terminals)."""
    total = max(total, 1)
    pct = done / total
    width = 26
    filled = int(pct * width)
    bar = "█" * filled + "░" * (width - filled)
    elapsed = max(time.time() - start_time, 0.001)
    rate = done / elapsed
    remaining = (total - done) / rate if rate > 0 else 0
    return f"[{bar}] {pct:6.1%} | {done}/{total} | ETA {remaining:5.1f}s"

def _banner(ip: str, port: int, timeout: float = 0.45) -> str:
    """Best-effort banner (optional; keep short to stay fast)."""
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                data = s.recv(256)
                if data:
                    return data.decode(errors="replace").strip()
            except Exception:
                pass
    except Exception:
        pass
    return "Unknown"

# ---------- Public API ----------

def scan_ports(ip: str,
               start_port: int,
               end_port: int,
               *,
               output_queue=None,
               stop_flag=None,
               scan_type: str = "top",
               no_banner: bool = True,
               timeout: float = DEFAULT_TIMEOUT,
               workers: int = DEFAULT_WORKERS):
    """
    Concurrent TCP port scan for one host.
    Returns dict: {ip, open_ports{port:banner|True}, duration}.
    """
    if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
        return {"ip": ip, "open_ports": {}, "duration": 0.0}

    if scan_type == "top":
        port_list = TOP_PORTS
    else:
        port_list = list(range(start_port, end_port + 1))

    total = len(port_list)
    open_ports = {}
    start_time = time.time()
    workers = max(4, workers)
    timeout = max(0.05, timeout)

    # live progress
    last_line = ""
    def _print_progress(done):
        nonlocal last_line
        msg = _progress_bar(done, total, start_time)
        if msg != last_line:
            print("\r" + msg, end="", flush=True)
            last_line = msg

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_scan_one, ip, p, timeout): p for p in port_list}
        for fut in as_completed(futs):
            if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
                break
            port = futs[fut]
            try:
                res = fut.result()
                if res:
                    open_ports[res] = True if no_banner else _banner(ip, res, 0.45)
                    if output_queue:
                        output_queue.put(f"  [OPEN] {ip}:{res}")
            except Exception:
                pass
            done += 1
            _print_progress(done)

    print()  # finish progress line
    duration = time.time() - start_time
    return {"ip": ip, "open_ports": open_ports, "duration": duration}

def run_port_scan(start_port: int = 1,
                  end_port: int = 1024,
                  *,
                  scan_type: str = "top",
                  target_hosts=None,
                  no_banner: bool = True,
                  timeout: float = DEFAULT_TIMEOUT,
                  workers: int = DEFAULT_WORKERS,
                  output_queue=None,
                  stop_flag=None):
    """
    Scans target hosts (if given) or discovered LAN devices.
    - scan_type: 'top' (fast) by default
    - no_banner: True to skip banner grabs (faster)
    - timeout/workers: tune performance
    """
    title = f"=== Port Scan ({scan_type}) {start_port}-{end_port if scan_type!='top' else '*TOP*'} ==="
    logging.info(title)
    if output_queue: output_queue.put(title)

    if target_hosts:
        hosts = [h for h in target_hosts if h and not _is_junk_ip(h)]
    else:
        devices = get_network_devices(output_queue, stop_flag)
        hosts = devices["IPv4"] or []

    if not hosts:
        msg = "No IPv4 hosts provided/discovered."
        logging.warning(msg)
        if output_queue: output_queue.put(msg)
        return "No devices found"

    results = {}
    for ip in hosts:
        if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
            break
        logging.info(f"Scanning {ip}...")
        if output_queue: output_queue.put(f"Scanning {ip}...")
        res = scan_ports(
            ip, start_port, end_port,
            output_queue=output_queue,
            stop_flag=stop_flag,
            scan_type=scan_type,
            no_banner=no_banner,
            timeout=timeout,
            workers=workers
        )
        results[ip] = res

    # summary table
    if Texttable and results:
        t = Texttable()
        t.header(["Host", "Open Ports", "Duration (s)"])
        for ip, r in results.items():
            ports = ",".join(map(str, sorted(r["open_ports"].keys())))
            t.add_row([ip, ports or "None", f"{r['duration']:.1f}"])
        print(t.draw())

    return results
