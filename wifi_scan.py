import platform
import logging
import subprocess
import shutil

def check_command_exists(cmd):
    """Check if a command is available on the system."""
    return shutil.which(cmd) is not None

def run_command(cmd_list, check=True):
    """
    Executes a system command and returns the output.
    Raises subprocess.CalledProcessError if the command fails (when check=True).
    """
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, check=check)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{' '.join(cmd_list)}' failed: {e}")
        raise  # Re-raise the exception to be handled by the caller
    except Exception as e:
        logging.error(f"Error running command '{' '.join(cmd_list)}': {e}")
        raise

def run_command_safe(cmd_list):
    """
    Executes a system command and returns the output, or an error message if it fails.
    Does not raise exceptions.
    """
    try:
        return run_command(cmd_list, check=True)
    except subprocess.CalledProcessError as e:
        return str(e)  # Return the error message
    except Exception as e:
        return str(e)

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
            output = run_command_safe(["netsh", "wlan", "show", "networks", "mode=Bssid"])
            for line in output.splitlines():
                if "SSID" in line:
                    networks.append({"ssid": line.split(":")[1].strip()})
        elif current_os == "Linux":
            output = run_command_safe(["nmcli", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"])
            lines = output.split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    networks.append({"ssid": parts[0], "security": parts[1], "signal": parts[2]})
        elif current_os == "Darwin":
            output = run_command_safe(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"])
            lines = output.split("\n")[1:]
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