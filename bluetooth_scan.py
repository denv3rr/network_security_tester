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

def scan_bluetooth():
    """
    Scans for nearby Bluetooth devices using OS-specific commands.
    Returns a summary string with device count.
    """
    logging.info("Scanning for Bluetooth devices...")
    devices = []

    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = run_command_safe(["powershell", "-Command", "Get-PnpDevice | Where-Object { $_.Class -eq 'Bluetooth' }"])
            for line in output.splitlines():
                if "Bluetooth" in line:
                    devices.append(line.strip())
        elif current_os == "Linux":
            if not check_command_exists("hcitool"):
                logging.warning("hcitool is not available. Skipping Bluetooth scan.")
                return "Bluetooth scan skipped (hcitool not found)"
            output = run_command_safe(["hcitool", "scan"])
            lines = output.split("\n")[1:]
            for line in lines:
                parts = line.split("\t")
                if len(parts) >= 2:
                    devices.append(parts[1])
        elif current_os == "Darwin":
            if not check_command_exists("system_profiler"):
                logging.warning("system_profiler is not available. Skipping Bluetooth scan.")
                return "Bluetooth scan skipped (system_profiler not found)"
            output = run_command_safe(["system_profiler", "SPBluetoothDataType"])
            for line in output.split("\n"):
                if "Device Name" in line:
                    devices.append(line.split(":")[1].strip())
        else:
            logging.warning(f"Bluetooth scanning is not supported on this OS ({current_os}).")
            return "Bluetooth scan not supported"
    except Exception as e:
        logging.error(f"Error scanning Bluetooth devices: {e}")
        return "Bluetooth scan failed"

    return f"{len(devices)} devices found" if devices else "No Bluetooth devices detected"