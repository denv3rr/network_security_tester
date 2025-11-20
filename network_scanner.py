# network_scanner.py
# Wired-friendly metadata with added heuristic connection type detection.
# Python 3.9+

import logging
import platform
import socket
import subprocess
from typing import Dict, Any, List, Optional

import requests
import ifaddr

def _best_local_ipv4() -> Optional[str]:
    """Return a non-loopback IPv4 by opening a UDP socket to a public IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        # fallback
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return None

def _detect_connection_type(iface_name: str) -> str:
    """Heuristic to guess connection type based on interface name."""
    name = iface_name.lower()
    if any(x in name for x in ["wi-fi", "wlan", "wireless", "air"]):
        return "Wi-Fi"
    if any(x in name for x in ["eth", "en", "ethernet", "lan"]):
        return "Wired"
    if "tun" in name or "tap" in name:
        return "VPN/Tunnel"
    return "Unknown"

def _list_interfaces() -> List[Dict[str, Any]]:
    """List adapters and their IPs via ifaddr."""
    out: List[Dict[str, Any]] = []
    try:
        for ad in ifaddr.get_adapters():
            for ip in ad.ips:
                addr = ip.ip
                fam = "IPv6" if ":" in str(addr) else "IPv4"
                out.append({
                    "name": ad.nice_name or ad.name, 
                    "ip": str(addr), 
                    "family": fam
                })
    except Exception as e:
        logging.debug(f"ifaddr error: {e}")
    return out

def _gateway_windows() -> Optional[str]:
    try:
        text = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True, encoding='utf-8', errors='replace').stdout
        for line in text.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[1].strip()
                    if val and val != "0.0.0.0":
                        return val
        return None
    except Exception:
        return None

def _gateway_unix() -> Optional[str]:
    for cmd in (["ip", "route"], ["route", "-n"], ["netstat", "-rn"]):
        try:
            text = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace').stdout
            for line in text.splitlines():
                line = line.strip()
                if not line: continue
                if "default via" in line:
                    try:
                        parts = line.split()
                        idx = parts.index("via")
                        return parts[idx + 1]
                    except Exception:
                        continue
                if line.startswith("default") or line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        except Exception:
            continue
    return None

def _default_gateway() -> Optional[str]:
    if platform.system() == "Windows":
        return _gateway_windows()
    return _gateway_unix()

def _public_ip_geo() -> Optional[Dict[str, Any]]:
    """Use ip-api.com (fast, rich) or fallback."""
    try:
        r = requests.get("http://ip-api.com/json/", timeout=3)
        if r.ok:
            j = r.json()
            return {
                "ip": j.get("query"),
                "isp": j.get("isp"),
                "asn": j.get("as"),
                "city": j.get("city"),
                "region": j.get("regionName"),
                "country": j.get("country"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
            }
    except Exception:
        pass
    return None

def get_quick_identity() -> Dict[str, Any]:
    """
    Fast metadata fetch for application startup.
    """
    local_ip = _best_local_ipv4()
    public = _public_ip_geo()
    
    # Guess connection type based on the interface holding the local IP
    conn_type = "Unknown"
    if local_ip:
        try:
            for ad in ifaddr.get_adapters():
                for ip in ad.ips:
                    if str(ip.ip) == local_ip:
                        conn_type = _detect_connection_type(ad.nice_name or ad.name)
                        break
        except Exception:
            pass

    return {
        "local_ip": local_ip,
        "public": public,
        "connection_type": conn_type,
        "hostname": socket.gethostname()
    }

def run_network_metadata_scan(output_queue=None, stop_flag=None, **kwargs):
    """
    Full scan returning all interfaces and details.
    """
    try:
        if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
            return {"status": "stopped"}

        hostname = socket.gethostname()
        os_name = platform.platform()
        local_ip = _best_local_ipv4()
        interfaces = _list_interfaces()
        gateway = _default_gateway()
        public = _public_ip_geo()

        msg = f"Host: {hostname} | Local: {local_ip} | OS: {os_name}"
        logging.info(msg)
        if output_queue:
            output_queue.put(msg)

        return {
            "hostname": hostname,
            "os": os_name,
            "local_ip": local_ip,
            "interfaces": interfaces,
            "gateway": gateway,
            "public": public,
        }
    except Exception as e:
        logging.error(f"network metadata error: {e}")
        if output_queue:
            output_queue.put(f"network metadata error: {e}")
        return {"error": str(e)}