import platform
import logging
import subprocess
import shutil
import os
import queue  # Import the queue module

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

def check_os_security(output_queue=None):
    """
    Cross-platform OS security check with rich output.
    Supports Windows, Debian/Ubuntu, Fedora/RedHat, Arch, macOS.
    """

    current_os = platform.system()
    issues = 0
    if output_queue:
        output_queue.put("=== Running OS Security Check ===")

    try:
        # -----------------------
        # WINDOWS SECURITY CHECKS
        # -----------------------
        if current_os == "Windows":
            if output_queue:
                output_queue.put("--- Windows Security Checks ---")
            # Check firewall status
            firewall_status = run_command_safe(["netsh", "advfirewall", "show", "allprofiles"])
            if "OFF" in firewall_status:
                logging.warning("Firewall: Disabled [!]")
                if output_queue:
                    output_queue.put("  Firewall: Disabled [!]")
                issues += 1
            else:
                logging.info("Firewall: Enabled")
                if output_queue:
                    output_queue.put("  Firewall: Enabled")

            # Attempt Defender AV check
            av_status = run_command_safe([
                "powershell", "-Command",
                "try { Get-MpComputerStatus | Select-Object -ExpandProperty AMRunning } catch { Write-Output 'Unavailable' }"
            ])
            if "True" in av_status:
                logging.info("Antivirus (Defender): Running")
                if output_queue:
                    output_queue.put("  Antivirus (Defender): Running")
            elif "False" in av_status:
                logging.warning("Antivirus (Defender): Not running [!]")
                if output_queue:
                    output_queue.put("  Antivirus (Defender): Not running [!]")
                issues += 1
            else:
                logging.warning("Antivirus status could not be verified [!]")
                if output_queue:
                    output_queue.put("  Antivirus status could not be verified [!]")

            # Check for updates using Get-HotFix
            update_status = run_command_safe(["powershell", "-Command", "Get-HotFix"])
            if len(update_status.strip().splitlines()) >= 5:
                logging.info("Windows Updates: Installed")
                if output_queue:
                    output_queue.put("  Windows Updates: Installed")
            else:
                logging.warning("Windows Updates: Update history may be missing or limited [!]")
                if output_queue:
                    output_queue.put("  Windows Updates: Update history may be missing or limited [!]")

        # -----------------------
        # MACOS SECURITY CHECKS
        # -----------------------
        elif current_os == "Darwin":
            if output_queue:
                output_queue.put("--- macOS Security Checks ---")
            fw_status = run_command_safe(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
            if "disabled" in fw_status.lower():
                logging.warning("Firewall: Disabled [!]")
                if output_queue:
                    output_queue.put("  Firewall: Disabled [!]")
                issues += 1
            else:
                logging.info("Firewall: Enabled")
                if output_queue:
                    output_queue.put("  Firewall: Enabled")

            updates = run_command_safe(["softwareupdate", "--list"])
            if "No new software available" in updates:
                logging.info("System Updates: Up-to-date")
                if output_queue:
                    output_queue.put("  System Updates: Up-to-date")
            else:
                logging.warning("System Updates: Available [!]")
                if output_queue:
                    output_queue.put("  System Updates: Available [!]")

        # -----------------------
        # LINUX SECURITY CHECKS
        # -----------------------
        elif current_os == "Linux":
            if output_queue:
                output_queue.put("--- Linux Security Checks ---")
            # Identify Linux distribution
            distro_id = "unknown"
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            distro_id = line.strip().split("=")[1].strip('"')

            logging.info(f"Distro Detected: {distro_id}")
            if output_queue:
                output_queue.put(f"  Distro Detected: {distro_id}")

            # Firewall detection (UFW, Firewalld, iptables fallback)
            if check_command_exists("ufw"):
                fw_status = run_command_safe(["ufw", "status"])
                if "inactive" in fw_status:
                    logging.warning("Firewall (ufw): Inactive [!]")
                    if output_queue:
                        output_queue.put("  Firewall (ufw): Inactive [!]")
                    issues += 1
                else:
                    logging.info("Firewall (ufw): Active")
                    if output_queue:
                        output_queue.put("  Firewall (ufw): Active")
            elif check_command_exists("firewall-cmd"):
                fw_state = run_command_safe(["firewall-cmd", "--state"])
                if "running" in fw_state:
                    logging.info("Firewall (firewalld): Active")
                    if output_queue:
                        output_queue.put("  Firewall (firewalld): Active")
                else:
                    logging.warning("Firewall (firewalld): Inactive [!]")
                    if output_queue:
                        output_queue.put("  Firewall (firewalld): Inactive [!]")
                    issues += 1
            elif check_command_exists("iptables"):
                fw_dump = run_command_safe(["iptables", "-L"])
                if "Chain" in fw_dump:
                    logging.info("Firewall (iptables): Rules present")
                    if output_queue:
                        output_queue.put("  Firewall (iptables): Rules present")
                else:
                    logging.warning("Firewall (iptables): No rules detected [!]")
                    if output_queue:
                        output_queue.put("  Firewall (iptables): No rules detected [!]")
                    issues += 1
            else:
                logging.warning("No known firewall tool detected [!]")
                if output_queue:
                    output_queue.put("  No known firewall tool detected [!]")

            # AV detection (ClamAV)
            if check_command_exists("clamdscan"):
                logging.info("ClamAV: Installed")
                if output_queue:
                    output_queue.put("  ClamAV: Installed")
            else:
                logging.warning("ClamAV: Not installed [!]")
                if output_queue:
                    output_queue.put("  ClamAV: Not installed [!]")

            # SELinux
            if os.path.exists("/etc/selinux/config"):
                selinux_status = run_command_safe(["getenforce"])
                logging.info(f"SELinux: {selinux_status.strip()}")
                if output_queue:
                    output_queue.put(f"  SELinux: {selinux_status.strip()}")
            else:
                logging.info("SELinux: Not configured")
                if output_queue:
                    output_queue.put("  SELinux: Not configured")

            # Update manager by distro
            if distro_id in ("debian", "ubuntu"):
                updates = run_command_safe(["apt", "list", "--upgradable"])
                if "upgradable" in updates:
                    logging.warning("System Updates: Available [!]")
                    if output_queue:
                        output_queue.put("  System Updates: Available [!]")
                    issues += 1
                else:
                    logging.info("System Updates: Up-to-date")
                    if output_queue:
                        output_queue.put("  System Updates: Up-to-date")
            elif distro_id in ("rhel", "fedora", "centos"):
                updates = run_command_safe(["dnf", "check-update"])
                if "Security" in updates or updates.strip():
                    logging.warning("System Updates: Available [!]")
                    if output_queue:
                        output_queue.put("  System Updates: Available [!]")
                    issues += 1
                else:
                    logging.info("System Updates: Up-to-date")
                    if output_queue:
                        output_queue.put("  System Updates: Up-to-date")
            elif distro_id in ("arch", "manjaro"):
                updates = run_command_safe(["checkupdates"])
                if updates.strip():
                    logging.warning("System Updates: Available [!]")
                    if output_queue:
                        output_queue.put("  System Updates: Available [!]")
                    issues += 1
                else:
                    logging.info("System Updates: Up-to-date")
                    if output_queue:
                        output_queue.put("  System Updates: Up-to-date")
            else:
                logging.warning("Unknown distro: update check skipped")
                if output_queue:
                    output_queue.put("  Unknown distro: update check skipped")

    except Exception as e:
        logging.error(f"Error checking OS security settings: {e}")
        if output_queue:
            output_queue.put(f"Error checking OS security settings: {e}")
        return "OS security check failed"

    result = "All security checks passed" if issues == 0 else f"Found {issues} potential issue(s)"
    if output_queue:
        output_queue.put(result)
    return result