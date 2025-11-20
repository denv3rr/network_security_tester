# port_scanner.py
# Concurrent TCP connect scanner with Unicode block progress + ETA,
# tunable timeout/workers, optional banner grabbing, optional target hosts.

import socket
import logging
import platform
import subprocess
import time
import re
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
    if ip.startswith("127.") or ip == "0.0.0.0": return True
    if ip.startswith("169.254."): return True
    if ip.startswith("224.") or ip.startswith("239."): return True
    if ip.endswith(".255"): return True
    if "ff02" in ip.lower(): return True
    return False

def get_network_devices(output_queue=None, stop_flag=None):
    devices = {"IPv4": set(), "IPv6": set()}
    osname = platform.system()
    text = ""
    ip4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    if osname == "Windows":
        text = _run_safe(["arp", "-a"])
    else:
        text = _run_safe(["ip", "neigh"])

    for line in text.splitlines():
        found = ip4_pattern.findall(line)
        for ip in found:
            if not _is_junk_ip(ip):
                devices["IPv4"].add(ip)

    if output_queue:
        for ip in sorted(devices["IPv4"]):
            output_queue.put(f"  Device found: {ip}")

    return {"IPv4": sorted(devices["IPv4"]), "IPv6": sorted(devices["IPv6"])}

# ---------- Ports & tuning ----------

# Top common ports (approx 73) from various sources
# Renamed to match the function call that caused your error
TOP_TCP_PORTS = [
    1,7,9,21,22,23,25,53,67,68,80,110,123,135,137,138,139,143,161,162,389,443,
    445,465,514,587,631,993,995,1025,1433,1521,2049,2375,2376,2483,2484,3128,
    3306,3389,3478,3690,4000,5000,5060,5432,5671,5672,5900,5985,5986,6379,6443,
    7001,7002,7071,7199,8000,8008,8080,8081,8088,8140,8443,8888,9000,9042,9092,
    9200,9300,9418,11211,15672,27017,27018,27019
]

# Common UDP services that usually respond to packets
UDP_PAYLOADS = {
    53:  b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01', # DNS Query A record
    123: b'\x1b' + 47 * b'\0', # NTP v3 client
    137: b'\x80\x92\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01', # NetBIOS status
    161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00', # SNMP v2c public
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n', # SSDP
}

# Defaults will be overridden by CLI when --fast is used
DEFAULT_TIMEOUT = 0.30
DEFAULT_WORKERS = 256

# ---------- Helpers ----------

def _scan_one_tcp(ip: str, port: int, timeout: float):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return port
        except: pass
    return None

def _scan_one_udp(ip: str, port: int, timeout: float):
    """Send a payload if we have one, else send empty bytes and hope for error/reply."""
    payload = UDP_PAYLOADS.get(port, b'\x00'*8)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(1024)
            if data:
                return port
        except socket.timeout:
            pass # UDP timeout usually means open|filtered or lost
        except Exception:
            pass
    return None

def _progress_bar(done: int, total: int, start_time: float) -> str:
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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = s.recv(128)
                if data: return data.decode(errors="replace").strip().split('\n')[0]
            except: pass
    except: pass
    return "Unknown"

# ---------- Public API ----------

def scan_ports(ip: str,
               start_port: int,
               end_port: int,
               *,
               output_queue=None,
               stop_flag=None,
               scan_type: str = "top",
               protocol: str = "tcp",
               no_banner: bool = True,
               timeout: float = DEFAULT_TIMEOUT,
               workers: int = DEFAULT_WORKERS):
    """
    Concurrent TCP port scan for one host.
    Returns dict: {ip, open_ports{port:banner|True}, duration}.
    """
    if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
        return {"ip": ip, "open_ports": {}, "duration": 0.0}

    # Determine port list
    port_list = []
    if scan_type == "top":
        if protocol == "tcp":
            port_list = TOP_TCP_PORTS
        else:
            port_list = list(UDP_PAYLOADS.keys())
    else:
        port_list = list(range(start_port, end_port + 1))

    total = len(port_list)
    open_ports = {}
    start_time = time.time()
    workers = max(4, workers)

    # UDP needs slightly longer timeout for round trip
    if protocol == "udp": timeout = max(1.0, timeout * 3)
    else: timeout = max(0.05, timeout)

    # live progress
    last_line = ""
    def _print_progress(done):
        nonlocal last_line
        msg = _progress_bar(done, total, start_time)
        if msg != last_line:
            print("\r" + msg, end="", flush=True)
            last_line = msg

    done = 0
    scan_func = _scan_one_udp if protocol == "udp" else _scan_one_tcp

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_func, ip, p, timeout): p for p in port_list}
        for fut in as_completed(futs):
            if stop_flag and getattr(stop_flag, "is_set", lambda: False)(): break
            port = futs[fut]
            try:
                res = fut.result()
                if res:
                    banner_txt = True
                    if not no_banner and protocol == "tcp":
                        banner_txt = _banner(ip, res, 0.5)
                    open_ports[res] = banner_txt
                    if output_queue: output_queue.put(f"  [OPEN] {ip}:{res}")
            except: pass
            done += 1
            _print_progress(done)

    print() 
    duration = time.time() - start_time
    return {"ip": ip, "open_ports": open_ports, "duration": duration}

def run_port_scan(start_port: int = 1,
                  end_port: int = 1024,
                  *,
                  scan_type: str = "top",
                  protocol: str = "tcp",
                  target_hosts=None,
                  no_banner: bool = True,
                  timeout: float = DEFAULT_TIMEOUT,
                  workers: int = DEFAULT_WORKERS,
                  output_queue=None,
                  stop_flag=None):
    
    title = f"=== {protocol.upper()} Port Scan ({scan_type}) ==="
    logging.info(title)
    if output_queue: output_queue.put(title)

    if target_hosts:
        hosts = [h for h in target_hosts if h and not _is_junk_ip(h)]
    else:
        if output_queue: output_queue.put("Identifying network devices...")
        devices = get_network_devices(output_queue, stop_flag)
        hosts = devices["IPv4"] or []

    if not hosts:
        return "No devices found"

    results = {}
    for ip in hosts:
        if stop_flag and getattr(stop_flag, "is_set", lambda: False)(): break
        logging.info(f"Scanning {ip}...")
        if output_queue: output_queue.put(f"Scanning {ip}...")
        res = scan_ports(
            ip, start_port, end_port,
            output_queue=output_queue,
            stop_flag=stop_flag,
            scan_type=scan_type,
            protocol=protocol,
            no_banner=no_banner,
            timeout=timeout,
            workers=workers
        )
        results[ip] = res

    # summary table
    if Texttable and results:
        t = Texttable()
        t.header(["Host", "Open Ports", "Duration (s)"])
        t.set_deco(Texttable.HEADER | Texttable.BORDER | Texttable.VLINES | Texttable.HLINES)
        for ip, r in results.items():
            ports = ",".join(map(str, sorted(r["open_ports"].keys())))
            t.add_row([ip, ports or "None", f"{r['duration']:.1f}"])
        print(t.draw())

    return results