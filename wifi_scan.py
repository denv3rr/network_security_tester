import platform
import logging
import subprocess

def scan_wifi():
    """
    Scans for available Wi-Fi networks using OS-specific commands.
    Returns a summary string with network count and security statuses.
    """
    logging.info("Scanning for Wi-Fi networks...")
    networks = []

    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = subprocess.run(["netsh", "wlan", "show", "networks", "mode=Bssid"],
                                    capture_output=True, text=True, check=True)
            for line in output.stdout.splitlines():
                if "SSID" in line:
                    networks.append({"ssid": line.split(":")[1].strip()})
        elif current_os == "Linux":
            output = subprocess.run(["nmcli", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"],
                                    capture_output=True, text=True, check=True)
            lines = output.stdout.split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    networks.append({"ssid": parts[0], "security": parts[1], "signal": parts[2]})
        elif current_os == "Darwin":
            output = subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
                                    capture_output=True, text=True, check=True)
            lines = output.stdout.split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    networks.append({"ssid": parts[0], "security": parts[1], "signal": parts[2]})
        else:
            logging.warning(f"Wi-Fi scanning is not supported on this OS ({current_os}).")
            return "Wi-Fi scan not supported"
    except Exception as e:
        logging.error(f"Error scanning Wi-Fi networks: {e}")
        return "Wi-Fi scan failed"

    return f"{len(networks)} networks found" if networks else "No Wi-Fi networks detected"
