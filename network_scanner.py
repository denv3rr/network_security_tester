# network_scanner.py
# Wired-friendly metadata, IP lookup, connection type detection, and LAN discovery.
# Python 3.9+

import logging
import platform
import socket
import subprocess
import re
from typing import Dict, Any, List, Optional

import requests
import ifaddr

# --- CORE HELPERS ---

def _best_local_ipv4() -> Optional[str]:
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
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return None

def _detect_connection_type(iface_name: str) -> str:
    name = iface_name.lower()
    if any(x in name for x in ["wi-fi", "wlan", "wireless", "air"]):
        return "Wi-Fi"
    if any(x in name for x in ["eth", "en", "ethernet", "lan"]):
        return "Wired"
    if "tun" in name or "tap" in name:
        return "VPN/Tunnel"
    return "Unknown"

def _list_interfaces() -> List[Dict[str, Any]]:
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

def _default_gateway() -> Optional[str]:
    try:
        if platform.system() == "Windows":
            text = subprocess.run(["ipconfig"], capture_output=True, text=True, errors='replace').stdout
            for line in text.splitlines():
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        val = parts[1].strip()
                        if val and val != "0.0.0.0": return val
        else:
            cmd = ["ip", "route"] if platform.system() == "Linux" else ["netstat", "-rn"]
            text = subprocess.run(cmd, capture_output=True, text=True, errors='replace').stdout
            for line in text.splitlines():
                if "default" in line or "0.0.0.0" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "via" and i+1 < len(parts): return parts[i+1]
                        if part == "default" and i+1 < len(parts): return parts[i+1] 
    except Exception:
        pass
    return None

# --- LAN DISCOVERY & VENDOR LOOKUP ---

def _lookup_mac_vendor(mac_address: str) -> str:
    """
    Queries macvendors.co API.
    """
    if not mac_address or len(mac_address) < 8:
        return "Unknown"
    
    try:
        # Simple API call
        url = f"https://macvendors.co/api/{mac_address}"
        r = requests.get(url, timeout=1.5) # Fast timeout
        if r.ok:
            data = r.json()
            if "result" in data and "company" in data["result"]:
                return data["result"]["company"]
    except:
        pass
    return "Unknown"

def get_network_devices() -> Dict[str, List[Dict[str, str]]]:
    """
    Reads ARP table and resolves OUI vendors.
    """
    devices = {"IPv4": [], "IPv6": []} # List of dicts now
    osname = platform.system()
    text = ""
    
    # Helpers
    def _run_safe(cmd):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.stdout
        except: return ""

    # Get ARP data
    if osname == "Windows":
        text = _run_safe(["arp", "-a"])
    else:
        text = _run_safe(["ip", "neigh"])

    # Regex for IP and MAC
    # Windows: 192.168.1.1       xx-xx-xx-xx-xx-xx     dynamic
    # Linux: 192.168.1.1 dev wlan0 lladdr xx:xx:xx:xx:xx:xx REACHABLE
    
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        
        # Basic parsing
        parts = line.split()
        if len(parts) < 2: continue
        
        ip = parts[0]
        mac = None
        
        # Try to find something that looks like a MAC
        for p in parts:
            if re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", p):
                mac = p
                break
        
        if ip and mac:
            # Filter junk
            if ip.startswith("127.") or "224." in ip or "239." in ip or ip == "0.0.0.0": continue
            
            # Lookup Vendor
            vendor = _lookup_mac_vendor(mac)
            devices["IPv4"].append({"ip": ip, "mac": mac, "vendor": vendor})

    # Sort by IP
    devices["IPv4"].sort(key=lambda x: x['ip'])
    return devices

# --- GEO LOOKUP ---

def lookup_target_ip(target: str) -> Dict[str, Any]:
    try:
        try:
            target_ip = socket.gethostbyname(target)
        except:
            return {"error": f"Could not resolve domain: {target}"}

        r = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=5)
        if r.ok:
            j = r.json()
            if j.get("status") == "fail":
                return {"error": j.get("message", "Lookup failed")}
            
            return {
                "target": target,
                "resolved_ip": target_ip,
                "isp": j.get("isp"),
                "org": j.get("org"),
                "as": j.get("as"),
                "city": j.get("city"),
                "country": j.get("country"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
                "timezone": j.get("timezone")
            }
        else:
            return {"error": f"API request failed code {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def _public_ip_geo() -> Optional[Dict[str, Any]]:
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
    local_ip = _best_local_ipv4()
    public = _public_ip_geo()
    
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