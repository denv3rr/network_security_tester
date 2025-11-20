# wifi_scan.py
# Windows: detect location permission + admin/elevation requirement and show clear guidance.
# Also supports a diagnostic mode to dump raw netsh outputs via the runner.
# Python 3.9+

import os
import re
import subprocess
import logging
import platform
import requests
import json
from typing import Optional, Any

def _run(cmd: list[str]) -> str:
    try:
        # Force utf-8 encoding to prevent cp1252 crashes on Windows
        out = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            encoding='utf-8', 
            errors='replace'
        )
        return out.stdout
    except Exception as e:
        logging.debug(f"wifi cmd fail {' '.join(cmd)}: {e}")
        try:
            # still return stderr so we can parse error strings
            return e.stderr if hasattr(e, "stderr") and e.stderr else ""
        except Exception:
            return ""

def _svc_running_windows(name: str) -> Optional[bool]:
    out = _run(["sc", "query", name])
    if not out:
        return None
    if "RUNNING" in out: return True
    if "STOPPED" in out: return False
    return None

def _is_admin_windows() -> Optional[bool]:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None

def parse_windows_interfaces(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        m = re.match(r"^\s*Name\s*:\s*(.+)$", line, flags=re.I)
        if m:
            names.append(m.group(1).strip())
    return names

def parse_windows_netsh_networks(text: str) -> list[dict[str, Any]]:
    networks = []
    current = {}
    # Regex adapted for various locale outputs, but focused on English headers
    ssid_re = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.I)
    bssid_re = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", re.I)
    sig_re = re.compile(r"^\s*Signal\s*:\s*(\d+)%", re.I)
    chan_re = re.compile(r"^\s*Channel\s*:\s*(\d+)", re.I)
    auth_re = re.compile(r"^\s*Authentication\s*:\s*(.*)$", re.I)

    for line in text.splitlines():
        line = line.strip()
        if not line: continue

        m = ssid_re.match(line)
        if m:
            if current:
                networks.append(current)
            current = {"ssid": m.group(1).strip(), "bssids": []}
            continue
        m = bssid_re.match(line)
        if m:
            current.setdefault("bssids", []).append(m.group(1).lower())
            continue
        m = sig_re.match(line)
        if m:
            current["signal"] = int(m.group(1))
            continue
        m = chan_re.match(line)
        if m:
            current["channel"] = int(m.group(1))
            continue
        m = auth_re.match(line)
        if m:
            current["auth"] = m.group(1).strip()
            continue
            
    if current:
        networks.append(current)
    return networks

def parse_nmcli(text: str) -> list[dict[str, Any]]:
    nets = []
    for line in text.splitlines():
        # nmcli -t is colon separated but can escape colons. Simple split for now.
        parts = line.split(":")
        if len(parts) < 5: continue
        ssid, bssid, chan, sig, sec = parts[:5]
        
        # Clean up escaped chars if necessary
        ssid = ssid.replace("\\:", ":")
        
        n = {
            "ssid": ssid or "<hidden>", 
            "bssids": [bssid.lower()] if bssid else [],
            "channel": int(chan) if chan.isdigit() else None,
            "signal": int(sig) if sig.isdigit() else None,
            "auth": sec
        }
        nets.append(n)
    return _merge_by_ssid(nets)

def parse_airport(text: str) -> list[dict[str, Any]]:
    nets = []
    header = True
    for line in text.splitlines():
        if header: header = False; continue
        if not line.strip(): continue
        try:
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) < 2: continue
            ssid, bssid = parts[0], parts[1].lower()
            # RSSI is usually index 2
            rssi = parts[2] if len(parts) > 2 else "-90"
            chan = parts[3] if len(parts) > 3 else "0"
            
            sig = 2*(int(rssi)+100) if rssi.lstrip("-").isdigit() else 0
            sig = max(0, min(100, sig))
            
            ch = int(chan.split(",")[0]) if chan.split(",")[0].isdigit() else 0
            nets.append({"ssid": ssid or "<hidden>", "bssids": [bssid], "signal": sig, "channel": ch})
        except Exception:
            continue
    return _merge_by_ssid(nets)

def _merge_by_ssid(items: list[dict]) -> list[dict]:
    by = {}
    for n in items:
        key = n.get("ssid") or "<hidden>"
        if key not in by:
            by[key] = {**n}
            by[key]["bssids"] = list(n.get("bssids") or [])
        else:
            by[key]["bssids"].extend(n.get("bssids") or [])
            by[key]["bssids"] = sorted(list(set(by[key]["bssids"])))
        if n.get("signal") is not None:
            by[key]["signal"] = max(by[key].get("signal") or 0, n["signal"])
        if n.get("channel") and not by[key].get("channel"):
            by[key]["channel"] = n["channel"]
    return [by[k] for k in sorted(by, key=lambda x: x.lower())]

# ---- Geolocation ----

def _post_json(url, payload, timeout=5):
    try:
        return requests.post(url, json=payload, timeout=timeout)
    except Exception as e:
        logging.debug(f"HTTP POST {url} failed: {e}")
        return None

def geolocate_bssids(bssids: list[str]) -> Optional[dict]:
    if not bssids: return None
    mls = os.getenv("MLS_API_KEY")
    gkey = os.getenv("GOOGLE_GEO_API_KEY")
    
    # Mozilla Location Service
    if mls:
        url = f"https://location.services.mozilla.com/v1/geolocate?key={mls}"
        r = _post_json(url, {"wifiAccessPoints": [{"macAddress": b} for b in bssids]})
        if r and r.ok: return r.json()
        
    # Google Geolocation API
    if gkey:
        url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={gkey}"
        r = _post_json(url, {"wifiAccessPoints": [{"macAddress": b} for b in bssids]})
        if r and r.ok: return r.json()
    return None

def geolocate_ip_fallback() -> Optional[dict]:
    try:
        r = requests.get("http://ip-api.com/json/", timeout=4)
        if r.ok:
            j = r.json()
            if j.get("lat") and j.get("lon"):
                return {"location": {"lat": j["lat"], "lng": j["lon"]}, "accuracy": None}
    except Exception:
        pass
    try:
        r = requests.get("https://ipapi.co/json/", timeout=4)
        if r.ok:
            j = r.json()
            if j.get("latitude") and j.get("longitude"):
                return {"location": {"lat": j["latitude"], "lng": j["longitude"]}, "accuracy": None}
    except Exception:
        pass
    return None

# ---------------- public API ----------------

def scan_wifi(wifi_interface: Optional[str] = None,
              output_queue=None,
              stop_flag=None,
              do_geolocation: bool = False,
              diag: bool = False,
              **_ignore) -> dict[str, Any]:
    """
    Scanner Entry Point.
    """
    if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
        return {"status": "stopped"}

    osname = platform.system()
    networks: list[dict] = []
    result = {"status": "ok", "networks": networks}

    logging.info("Starting Wi-Fi scan...")
    if output_queue: output_queue.put("Scanning Wi-Fi networks...")

    try:
        if osname == "Windows":
            # Check service and admin
            lfsvc = _svc_running_windows("lfsvc")  # Geolocation Service
            wlan  = _svc_running_windows("WlanSvc")
            admin = _is_admin_windows()

            int_text = _run(["netsh", "wlan", "show", "interfaces"])
            names = parse_windows_interfaces(int_text)
            if wifi_interface:
                names = [wifi_interface]

            if diag and output_queue:
                output_queue.put("--- Wi-Fi diag (Windows) ---")
                for line in int_text.splitlines():
                    output_queue.put("  " + line)

            if not names:
                msg = "No wireless interfaces detected."
                result.update({"status": "no_adapter", "note": msg, "reason": "no_interface"})
                if output_queue: output_queue.put(msg)
                return result

            # Attempt a scan per interface
            all_errors = []
            for name in names:
                out = _run(["netsh", "wlan", "show", "networks", f"interface={name}", "mode=Bssid"])
                lower = (out or "").lower()

                if diag and output_queue:
                    output_queue.put(f"--- netsh show networks for '{name}' ---")
                    for line in (out or "").splitlines():
                        output_queue.put("  " + line)

                # Detect common permission cases
                needs_location = ("location permission" in lower) or ("ms-settings:privacy-location" in lower)
                needs_admin    = ("requires elevation" in lower) or ("access is denied" in lower)

                if needs_location or needs_admin:
                    reason = []
                    if needs_location:
                        reason.append("Location services disabled")
                    if needs_admin or admin is False:
                        reason.append("Not elevated (Run as Administrator)")
                    all_errors.append(", ".join(reason))
                    continue

                nets = parse_windows_netsh_networks(out)
                networks.extend(nets)

            if not networks:
                # No networks visible due to perms or radio state
                note_bits = []
                if wlan is False:
                    note_bits.append("WLAN AutoConfig service is STOPPED")
                if lfsvc is False:
                    note_bits.append("Geolocation service (lfsvc) is STOPPED")
                if admin is False:
                    note_bits.append("Not running elevated (Administrator)")
                if not note_bits and all_errors:
                    note_bits.append("; ".join(all_errors))
                if not note_bits and "State                  : disconnected" in int_text:
                    note_bits.append("Wi-Fi adapter is disconnected")

                reason = "; ".join(note_bits) if note_bits else "No scanable networks returned by netsh"
                msg = f"Wi-Fi scan returned no data — {reason}."
                result.update({"status": "ok_empty", "note": msg, "reason": reason, "interfaces": names})
                if output_queue: output_queue.put(msg)
                return result

        elif osname == "Linux":
            text = _run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"])
            if text.strip():
                networks = parse_nmcli(text)
            else:
                msg = "nmcli returned no data (no adapter, rfkill, or permissions)."
                result.update({"status": "no_adapter", "note": msg, "reason": "nmcli_empty"})
                if output_queue: output_queue.put(msg)
                return result

        elif osname == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            text = _run([airport, "-s"])
            if text.strip():
                networks = parse_airport(text)
            else:
                msg = "airport returned no data."
                result.update({"status": "no_adapter", "note": msg, "reason": "airport_empty"})
                if output_queue: output_queue.put(msg)
                return result

        else:
            msg = f"Wi-Fi scan not supported on {osname}."
            result.update({"status": "unsupported", "note": msg, "reason": "os_unsupported"})
            if output_queue: output_queue.put(msg)
            return result

        # Optional geolocation
        if networks:
            if do_geolocation:
                if output_queue: output_queue.put("Performing geolocation lookup...")
                all_bssids = sorted({b for n in networks for b in (n.get("bssids") or [])})
                # Prefer BSSID lookup, fallback to IP
                geo = geolocate_bssids(all_bssids) or geolocate_ip_fallback()
                
                if geo and "location" in geo:
                    for n in networks:
                        n["location"] = geo["location"]
                        n["accuracy_m"] = geo.get("accuracy")
            
            # Sort by signal
            networks.sort(key=lambda x: x.get("signal", 0), reverse=True)

            # print human lines to logs
            for n in networks:
                ssid = n.get("ssid") or "<hidden>"
                bssid_count = len(n.get("bssids") or [])
                sig = n.get("signal"); ch = n.get("channel")
                line = f"SSID='{ssid}'  BSSIDs={bssid_count}  Signal={sig if sig is not None else '?'}%  Ch={ch if ch else '?'}"
                if n.get("location"):
                    loc = n["location"]
                    line += f"  Geo={loc.get('lat'):.5f},{loc.get('lng'):.5f}"
                    if n.get("accuracy_m"):
                        line += f" ±{int(n['accuracy_m']):d}m"
                logging.info(line)
                if output_queue: output_queue.put(line)

        result["networks"] = networks
        result["status"] = "ok" if networks else "ok_empty"
        return result

    except Exception as e:
        logging.error(f"wifi scan error: {e}")
        if output_queue: output_queue.put(f"wifi scan error: {e}")
        return {"status": "error", "error": str(e), "networks": []}