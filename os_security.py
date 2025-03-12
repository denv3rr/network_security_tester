import platform
import logging
import subprocess

def check_os_security():
    """
    Checks OS security settings such as firewall status, antivirus, and updates.
    Returns a summary indicating any issues found.
    """
    current_os = platform.system()
    issues = 0

    try:
        if current_os == "Windows":
            firewall_status = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                                            capture_output=True, text=True, check=True).stdout
            av_status = subprocess.run(["powershell", "-Command", "Get-MpComputerStatus | Select-Object AMRunning"],
                                            capture_output=True, text=True, check=True).stdout
            update_status = subprocess.run(["powershell", "-Command", "Get-WindowsUpdate"],
                                            capture_output=True, text=True, check=True).stdout

            if "OFF" in firewall_status:
                logging.warning("Firewall: Disabled [!]")
                issues += 1
            else:
                logging.info("Firewall: Enabled")

            if "False" in av_status:
                logging.warning("Antivirus: Not running [!]")
                issues += 1
            else:
                logging.info("Antivirus: Running")

            if "No updates" in update_status:
                logging.info("Windows Updates: Up-to-date")
            else:
                logging.warning("Windows Updates: Available [!]")

        elif current_os == "Linux":
            firewall_status = subprocess.run(["ufw", "status"],
                                            capture_output=True, text=True, check=True).stdout
            update_status = subprocess.run(["apt", "list", "--upgradable"],
                                            capture_output=True, text=True, check=True).stdout

            if "inactive" in firewall_status:
                logging.warning("Firewall: Inactive [!]")
                issues += 1
            else:
                logging.info("Firewall: Active")

            if "upgradable" in update_status:
                logging.warning("System Updates: Available [!]")
                issues += 1
            else:
                logging.info("System Updates: Up-to-date")

        elif current_os == "Darwin":
            firewall_status = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                                            capture_output=True, text=True, check=True).stdout
            update_status = subprocess.run(["softwareupdate", "--list"],
                                            capture_output=True, text=True, check=True).stdout

            if "disabled" in firewall_status.lower():
                logging.warning("Firewall: Disabled [!]")
                issues += 1
            else:
                logging.info("Firewall: Enabled")

            if "No new software" in update_status:
                logging.info("System Updates: Up-to-date")
            else:
                logging.warning("System Updates: Available [!]")

    except Exception as e:
        logging.error(f"Error checking OS security settings: {e}")
        return "OS security check failed"

    return "All security checks passed" if issues == 0 else f"Found {issues} potential issue(s)"
