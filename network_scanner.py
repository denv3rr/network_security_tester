# network_scanner.py
# Wired-friendly metadata:
# - hostname, OS, best local IPv4
# - interfaces (name, IPv4/6)
# - best-effort default gateway
# - public IP + ISP/ASN + city/region/country + lat/lon (no API key needed)

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
    # fallback
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return None


def _list_interfaces() -> List[Dict[str, Any]]:
    """List adapters and their IPs via ifaddr (pure Python)."""
    out: List[Dict[str, Any]] = []
    try:
        for ad in ifaddr.get_adapters():
            for ip in ad.ips:
                addr = ip.ip
                fam = "IPv6" if ":" in str(addr) else "IPv4"
                out.append({"name": ad.nice_name or ad.name, "ip": str(addr), "family": fam})
    except Exception as e:
        logging.debug(f"ifaddr error: {e}")
    return out


def _gateway_windows() -> Optional[str]:
    try:
        text = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True).stdout
        gw = None
        for line in text.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    val = parts[1].strip()
                    if val and val != "0.0.0.0":
                        gw = val
                        break
        return gw
    except Exception:
        return None


def _gateway_unix() -> Optional[str]:
    # Try `ip route` then `route -n`
    for cmd in (["ip", "route"], ["route", "-n"], ["netstat", "-rn"]):
        try:
            text = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "default via" in line:
                    # ip route: "default via 192.168.1.1 dev eth0 ..."
                    try:
                        parts = line.split()
                        idx = parts.index("via")
                        return parts[idx + 1]
                    except Exception:
                        continue
                if line.startswith("default") or line.startswith("0.0.0.0"):
                    # route -n / netstat -rn style
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
    """
    Use ip-api.com first (fast, rich), then ipapi.co as fallback.
    No API keys required.
    """
    try:
        r = requests.get("http://ip-api.com/json/", timeout=4)
        if r.ok:
            j = r.json()
            # fields: query, isp, as, city, regionName, country, lat, lon
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
    try:
        r = requests.get("https://ipapi.co/json/", timeout=4)
        if r.ok:
            j = r.json()
            return {
                "ip": j.get("ip"),
                "isp": j.get("org"),
                "asn": j.get("asn"),
                "city": j.get("city"),
                "region": j.get("region"),
                "country": j.get("country_name"),
                "lat": j.get("latitude"),
                "lon": j.get("longitude"),
            }
    except Exception:
        pass
    return None


def run_network_metadata_scan(output_queue=None, stop_flag=None, **kwargs):
    """
    Returns dict with: hostname, os, local_ip, interfaces[], gateway?, public{}
    Works great on **wired** hosts (no Wi-Fi required).
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

        msg = f"Host: {hostname} | Local IP: {local_ip or '?'} | OS: {os_name}"
        logging.info(msg)
        if output_queue:
            output_queue.put(msg)
            if gateway:
                output_queue.put(f"  Gateway: {gateway}")
            if public:
                output_queue.put(f"  Public: {public.get('ip','?')}  {public.get('isp','') or ''} {public.get('asn') or ''}")

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
