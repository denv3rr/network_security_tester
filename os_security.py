# os_security.py
# Defensive OS posture checks (Firewall, Antivirus/Defender).

import logging
import platform
import subprocess
import shutil
import json

def _check_windows_security():
    """
    Checks Windows Firewall and basic Defender status via PowerShell/Netsh.
    """
    status = {"firewall": "unknown", "antivirus": "unknown", "details": []}

    # 1. Firewall Check
    try:
        # netsh advfirewall show allprofiles state
        res = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, errors="ignore"
        )
        if "ON" in res.stdout:
            status["firewall"] = "active"
            status["details"].append("Windows Firewall appears active (ON).")
        else:
            status["firewall"] = "inactive/warning"
            status["details"].append("Windows Firewall might be OFF or partial.")
    except Exception as e:
        status["details"].append(f"Firewall check failed: {e}")

    # 2. Antivirus (WMI)
    try:
        # Get-CimInstance is cleaner, but WMIC is older/compatible
        # wmic /namespace:\\root\securitycenter2 path antivirusproduct get displayname,productstate
        res = subprocess.run(
            ["wmic", "/namespace:\\\\root\\securitycenter2", "path", "antivirusproduct", "get", "displayname"],
            capture_output=True, text=True, errors="ignore"
        )
        output = res.stdout.strip()
        if len(output.splitlines()) > 1:
            avs = [line.strip() for line in output.splitlines() if line.strip() and "DisplayName" not in line]
            status["antivirus"] = "detected"
            status["details"].append(f"AV Products found: {', '.join(avs)}")
        else:
            status["antivirus"] = "not_found"
            status["details"].append("No registered Antivirus found via WMIC.")
    except Exception:
        pass

    return status

def _check_linux_security():
    status = {"firewall": "unknown", "details": []}
    
    # Check UFW
    if shutil.which("ufw"):
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "active" in res.stdout and "inactive" not in res.stdout:
                status["firewall"] = "active"
                status["details"].append("UFW is active.")
            else:
                status["firewall"] = "inactive"
                status["details"].append("UFW is installed but inactive.")
        except: pass
    # Check IPTables (simple check for rule count)
    elif shutil.which("iptables"):
        try:
            # Requires sudo usually, so this might fail
            res = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
            if len(res.stdout.splitlines()) > 8: # Empty tables have headers (~8 lines total for filter)
                status["firewall"] = "active_rules_found"
                status["details"].append("iptables has configured rules.")
            else:
                status["firewall"] = "empty?"
                status["details"].append("iptables seems empty (default accept?).")
        except: 
            status["details"].append("Could not read iptables (permission denied?).")
    
    return status

def _check_macos_security():
    status = {"firewall": "unknown", "details": []}
    try:
        # socketfilterfw
        res = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True, text=True
        )
        if "enabled" in res.stdout:
            status["firewall"] = "active"
            status["details"].append("macOS Application Firewall is enabled.")
        else:
            status["firewall"] = "inactive"
            status["details"].append("macOS Application Firewall is disabled.")
    except:
        pass
    return status

def check_os_security(output_queue=None, stop_flag=None, **kwargs):
    """
    OS security posture checks (firewall, AV).
    """
    try:
        if stop_flag and getattr(stop_flag, "is_set", lambda: False)():
            return {"status": "stopped"}
        
        os_name = platform.system()
        msg = f"Running security checks for {os_name}..."
        logging.info(msg)
        if output_queue: output_queue.put(msg)

        data = {}
        if os_name == "Windows":
            data = _check_windows_security()
        elif os_name == "Linux":
            data = _check_linux_security()
        elif os_name == "Darwin":
            data = _check_macos_security()
        else:
            data = {"note": "OS not fully supported for security checks."}

        # Formatting output for queue
        fw = data.get("firewall", "unknown")
        av = data.get("antivirus", "unknown")
        
        summary = f"  Firewall: {fw.upper()} | AV: {av.upper()}"
        logging.info(summary)
        if output_queue: output_queue.put(summary)
        
        for d in data.get("details", []):
            logging.info(f"  -> {d}")
            if output_queue: output_queue.put(f"  -> {d}")

        return {"status": "ok", "os": os_name, "data": data}
    except Exception as e:
        logging.error(f"os security error: {e}")
        if output_queue: output_queue.put(f"os security error: {e}")
        return {"error": str(e)}