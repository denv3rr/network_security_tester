import platform
import logging
import subprocess
import shutil
import queue  # Import the queue module
import texttable  # Import the texttable library

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

def scan_bluetooth(output_queue=None, stop_flag=False): # Add stop_flag
    """
    Scans for nearby Bluetooth devices using OS-specific commands.
    Returns a summary string with device count.
    """
    logging.info("Scanning for Bluetooth devices...")
    if output_queue:
        output_queue.put("Scanning for Bluetooth devices...")
    devices = []

    try:
        current_os = platform.system()
        if current_os == "Windows":
            output = run_command_safe(["powershell", "-Command", "Get-PnpDevice | Where-Object { $_.Class -eq 'Bluetooth' }"])
            for line in output.splitlines():
                if stop_flag: # Check the stop flag
                    return "Scan stopped by user"
                if "Bluetooth" in line:
                    device = line.strip()
                    devices.append(device)
        elif current_os == "Linux":
            if not check_command_exists("hcitool"):
                logging.warning("hcitool is not available. Skipping Bluetooth scan.")
                return "Bluetooth scan skipped (hcitool not found)"
            output = run_command_safe(["hcitool", "scan"])
            lines = output.split("\n")[1:]
            for line in lines:
                if stop_flag: # Check the stop flag
                    return "Scan stopped by user"
                parts = line.split("\t")
                if len(parts) >= 2:
                    devices.append({"mac": parts[0], "name": parts[1]})
        elif current_os == "Darwin":
            if not check_command_exists("system_profiler"):
                logging.warning("system_profiler is not available. Skipping Bluetooth scan.")
                return "Bluetooth scan skipped (system_profiler not found)"
            output = run_command_safe(["system_profiler", "SPBluetoothDataType"])
            for line in output.split("\n"):
                if stop_flag: # Check the stop flag
                    return "Scan stopped by user"
                if "Device Name" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        devices.append({"name": parts[1].strip()})
        else:
            logging.warning(f"Bluetooth scanning is not supported on this OS ({current_os}).")
            if output_queue:
                output_queue.put(f"Bluetooth scanning is not supported on this OS ({current_os}).")
            return "Bluetooth scan not supported"
    except Exception as e:
        logging.error(f"Error scanning Bluetooth devices: {e}")
        if output_queue:
            output_queue.put(f"Error scanning Bluetooth devices: {e}")
        return "Bluetooth scan failed"
    
    result = f"{len(devices)} devices found" if devices else "No Bluetooth devices detected"
    if output_queue:
        table = texttable.Texttable()
        if devices and "mac" in devices[0]:  # Linux output
            table.header(["MAC Address", "Device Name"])
            for device in devices:
                table.add_row([device["mac"], device["name"]])
        elif devices and "name" in devices[0]:  # macOS output
            table.header(["Device Name"])
            for device in devices:
                table.add_row([device["name"]])
        else:  # Windows or no devices
            table.header(["Device"])
            for device in devices:
                table.add_row([device])
        output_queue.put("Bluetooth Devices:\n" + table.draw())
    return result