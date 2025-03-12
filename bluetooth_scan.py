import platform
import logging
import subprocess

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
            output = subprocess.run(["powershell", "-Command", "Get-PnpDevice | Where-Object { $_.Class -eq 'Bluetooth' }"],
                                    capture_output=True, text=True, check=True)
            for line in output.stdout.splitlines():
                if "Bluetooth" in line:
                    devices.append(line.strip())
        elif current_os == "Linux":
            output = subprocess.run(["hcitool", "scan"],
                                    capture_output=True, text=True, check=True)
            lines = output.stdout.split("\n")[1:]
            for line in lines:
                parts = line.split("\t")
                if len(parts) >= 2:
                    devices.append(parts[1])
        elif current_os == "Darwin":
            output = subprocess.run(["system_profiler", "SPBluetoothDataType"],
                                    capture_output=True, text=True, check=True)
            for line in output.stdout.split("\n"):
                if "Device Name" in line:
                    devices.append(line.split(":")[1].strip())
        else:
            logging.warning(f"Bluetooth scanning is not supported on this OS ({current_os}).")
            return "Bluetooth scan not supported"
    except Exception as e:
        logging.error(f"Error scanning Bluetooth devices: {e}")
        return "Bluetooth scan failed"

    return f"{len(devices)} devices found" if devices else "No Bluetooth devices detected"
