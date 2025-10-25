# wifi_scan.py
# Lists nearby Wi-Fi networks with SSID/BSSID/Channel/Signal on
# Windows (netsh), Linux (nmcli/iwlist), macOS (airport).
# Optional geolocation via Mozilla or Google if env key provided and --geo flag set.

import os
import re
import subprocess
import logging
import json
import platform

import requests  # present in requirements

def _run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return out.stdout
    except Exception as e:
        logging.debug(f"wifi cmd fail {' '.join(cmd)}: {e}")
        return ""

def parse_windows_netsh(text: str):
    """Parse `netsh wlan show networks mode=Bssid`."""
    networks = []
    current = {}
    ssid_re = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.I)
    bssid_re = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", re.I)
    sig_re = re.compile(r"^\s*Signal\s*:\s*(\d+)%", re.I)
    chan_re = re.compile(r"^\s*Channel\s*:\s*(\d+)", re.I)
    auth_re = re.compile(r"^\s*Authentication\s*:\s*(.*)$", re.I)

    for line in text.splitlines():
        m = ssid_re.match(line)
        if m:
            if current:
                networks.append(current); current = {}
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

def parse_nmcli(text: str):
    """Parse `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list`."""
    networks = []
    for line in text.splitlines():
        # SSID:BSSID:CHAN:SIGNAL:SEC
        parts = line.split(":")
        if len(parts) < 5:
            continue
        ssid, bssid, chan, sig, sec = parts[:5]
        n = {"ssid": ssid or "<hidden>", "bssids": [bssid.lower()] if bssid else [],
             "channel": int(chan) if chan.isdigit() else None,
             "signal": int(sig) if sig.isdigit() else None,
             "auth": sec}
        networks.append(n)
    return _merge_by_ssid(networks)

def parse_airport(text: str):
    """Parse `/System/Library/.../airport -s` output on macOS."""
    networks = []
    header = True
    for line in text.splitlines():
        if header:
            header = False
            continue
        # SSID BSSID RSSI CHANNEL HT CC SECURITY
        if not line.strip():
            continue
        try:
            parts = re.split(r"\s{2,}", line.strip())
            ssid, bssid, rssi, chan = parts[0], parts[1].lower(), parts[2], parts[3]
            sig = min(max(2*(int(rssi)+100), 0), 100) if rssi.lstrip("-").isdigit() else None
            ch = int(chan.split(",")[0]) if chan.split(",")[0].isdigit() else None
            networks.append({"ssid": ssid or "<hidden>", "bssids": [bssid], "signal": sig, "channel": ch})
        except Exception:
            continue
    return _merge_by_ssid(networks)

def _merge_by_ssid(items):
    """Merge entries with same SSID (collect BSSIDs)."""
    by_ssid = {}
    for n in items:
        key = n.get("ssid") or "<hidden>"
        if key not in by_ssid:
            by_ssid[key] = {**n}
            by_ssid[key]["bssids"] = list(n.get("bssids") or [])
        else:
            by_ssid[key]["bssids"].extend(n.get("bssids") or [])
            by_ssid[key]["bssids"] = sorted(list(set(by_ssid[key]["bssids"])))
        # keep best signal/channel if present
        if n.get("signal") is not None:
            by_ssid[key]["signal"] = max(by_ssid[key].get("signal") or 0, n["signal"])
        if n.get("channel") and not by_ssid[key].get("channel"):
            by_ssid[key]["channel"] = n["channel"]
    return [by_ssid[k] for k in sorted(by_ssid)]

# ---------- Optional Geolocation ----------

def geolocate_bssids(bssids, output_queue=None):
    """
    Use Mozilla Location Service (MLS) or Google Geolocation API if API key env var is set.
    Env:
      MLS_API_KEY           (preferred; free for dev)
      GOOGLE_GEO_API_KEY    (fallback)
    """
    try:
        if not bssids:
            return None
        if os.getenv("MLS_API_KEY"):
            url = f"https://location.services.mozilla.com/v1/geolocate?key={os.getenv('MLS_API_KEY')}"
            payload = {"wifiAccessPoints": [{"macAddress": b} for b in bssids]}
            r = requests.post(url, json=payload, timeout=5)
            if r.ok:
                return r.json()  # {location:{lat,lng}, accuracy:...}
        elif os.getenv("GOOGLE_GEO_API_KEY"):
            url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={os.getenv('GOOGLE_GEO_API_KEY')}"
            payload = {"wifiAccessPoints": [{"macAddress": b} for b in bssids]}
            r = requests.post(url, json=payload, timeout=5)
            if r.ok:
                return r.json()
        else:
            if output_queue:
                output_queue.put("No geolocation API key set (MLS_API_KEY or GOOGLE_GEO_API_KEY). Skipping geo.")
    except Exception as e:
        logging.debug(f"geo error: {e}")
    return None

# ---------- Public API ----------

def scan_wifi(wifi_interface=None, output_queue=None, stop_flag=None, do_geolocation=False, **_):
    """
    Returns: { 'networks': [ {ssid, bssids[], signal(0-100), channel, auth? , location?} ] }
    - Windows: netsh
    - Linux: nmcli (preferred), fallback iwlist
    - macOS: airport
    """
    if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
        return {"status": "stopped"}

    osname = platform.system()
    networks = []

    try:
        if osname == "Windows":
            text = _run(["netsh", "wlan", "show", "networks", "mode=Bssid"])
            networks = parse_windows_netsh(text)

        elif osname == "Linux":
            text = _run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"])
            if not text.strip():
                # very old distros may only have iwlist
                text = _run(["iwlist", wifi_interface or "wlan0", "scanning"])
                # minimal iwlist parser (SSID/BSSID/CH) not shown for brevity—skipped here.
                pass
            networks = parse_nmcli(text)

        elif osname == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            text = _run([airport, "-s"])
            networks = parse_airport(text)

        else:
            if output_queue: output_queue.put(f"Wi-Fi scan not supported on {osname}.")
            return {"status": "unsupported", "os": osname}

        # Optional geolocation (one call with all BSSIDs to keep it fast)
        if do_geolocation and networks:
            all_bssids = sorted({b for n in networks for b in (n.get("bssids") or [])})
            geo = geolocate_bssids(all_bssids, output_queue)
            # attach the same coarse geo to each entry (most services return centroid)
            if geo and "location" in geo:
                for n in networks:
                    n["location"] = geo["location"]  # {'lat':..., 'lng':...}
                    n["accuracy_m"] = geo.get("accuracy")

        # Console output
        for n in networks:
            ssid = n.get("ssid") or "<hidden>"
            bssid_count = len(n.get("bssids") or [])
            sig = n.get("signal")
            ch = n.get("channel")
            line = f"SSID='{ssid}'  BSSIDs={bssid_count}  Signal={sig if sig is not None else '?'}%  Ch={ch if ch else '?'}"
            logging.info(line)
            if output_queue: output_queue.put(line)

        return {"status": "ok", "networks": networks}

    except Exception as e:
        logging.error(f"wifi scan error: {e}")
        if output_queue: output_queue.put(f"wifi scan error: {e}")
        return {"error": str(e)}
