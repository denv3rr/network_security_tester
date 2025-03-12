# Network Security Tester (NST)

## Overview
This is a multi-platform Python tool designed for **network security assessment**.

Supports:
- **Wi-Fi scanning** (detects available networks, security types)
- **Port scanning** (checks for open ports)
  - (feel free to add other ports to check as needed at the beginning of ``port_scanner.py`` shown below):
  - ```
    # Check common open ports:
    # SSH, HTTP, HTTPS, RDP, DNS, Web Proxy
    COMMON_PORTS = [22, 80, 443, 3389, 53, 8080]
    ``` 
- **Bluetooth scanning** (detects nearby discoverable devices)
- **OS security checks** (firewall, updates, antivirus status)
- **Network metadata scanning** (retrieves local IP, MAC addresses, public IP, and geolocation via BSSID/IP lookup)
- **Full scan**

This program is for **Windows, Linux, and macOS** and supports both **CLI and GUI** modes depending on use case.

---

## Installation

### **1. Prerequisites**
- **Python 3.x** must be installed on your system.
- Required Python modules:
  - `requests` (for API calls)
  - `netifaces` (for network interface details)

To install the required packages, run:
```
pip install requests netifaces
```

### **2. Clone or Download**
```
git clone https://github.com/denv3rr/network-security-tester.git
cd network-security-tester
```

---

## Running the Program

NST supports **two execution modes**: **CLI** (command-line) and **GUI** (graphical).

### **CLI Usage**
Run the script with specific flags to select modules:

- **Full scan (all modules):**  
  ```
  python network_security_tester.py --all
  ```

- **Specific combination of scans (select modules):**  
  ```
  python network_security_tester.py --wifi --ports --bluetooth
  ```
  
- **Wi-Fi scan:**  
  ```
  python network_security_tester.py --wifi
  ```
  
- **Port scan**  
  ```
  python network_security_tester.py --ports
  ```
  
- **Bluetooth scan:**  
  ```
  python network_security_tester.py --bluetooth
  ```
  
- **OS Security scan:**  
  ```
  python network_security_tester.py --os
  ```
  
- **Network metadata scan:**  
  ```
  python network_security_tester.py --network
  ```

### **Graphical Interface Usage**
Run the GUI version using:
```
python network_security_tester.py --gui
```
A window will open, allowing you to **select scan modules** via checkboxes and run scans with a single click.

---

## Example Outputs

### **Wi-Fi Scan Output**
```
2025-03-11 12:30:01 [INFO] Scanning for Wi-Fi networks...
2025-03-11 12:30:03 [INFO] SSID: HomeNetwork, Security: WPA2-Personal, Signal: 78%
2025-03-11 12:30:03 [INFO] SSID: PublicWiFi, Security: Open, Signal: 43%
2025-03-11 12:30:03 [WARNING]   [!] Open network detected: PublicWiFi
2025-03-11 12:30:03 [INFO] 2 networks found (1 open, 0 WEP insecure)
```

### **Port Scan Output**
```
2025-03-11 13:45:00 [INFO] === Running Port Scan on Network Devices ===
2025-03-11 13:45:01 [INFO] Scanning 192.168.1.10...
2025-03-11 13:45:02 [WARNING] Device 192.168.1.10 has open ports: [22, 80, 443]
2025-03-11 13:45:03 [INFO] Scanning 192.168.1.11...
2025-03-11 13:45:04 [INFO] Device 192.168.1.11 has no common open ports.
2025-03-11 13:45:05 [INFO] === Port Scan Complete ===
```

### **Bluetooth Scan Output**
```
2025-03-11 12:32:10 [INFO] Scanning for Bluetooth devices...
2025-03-11 12:32:12 [INFO] Device: JBL Speaker (MAC: 00:1A:7D:DA:71:13), Signal: -75 dBm
2025-03-11 12:32:12 [INFO] 1 device found
```

### **OS Security Scan Output**
```
2025-03-11 12:34:30 [INFO] Checking OS security settings...
2025-03-11 12:34:32 [INFO] Firewall: Enabled
2025-03-11 12:34:32 [INFO] Antivirus: Running
2025-03-11 12:34:32 [INFO] Windows Updates: Up-to-date
2025-03-11 12:34:32 [INFO] All security checks passed
```

### **Network Metadata Scan Output**
```
2025-03-11 12:37:01 [INFO] Public IP: 192.168.1.101
2025-03-11 12:37:01 [INFO] IP Geolocation: {"city": "Los Angeles", "region": "California", "country": "US"}
2025-03-11 12:37:01 [INFO] Local Network Info:
2025-03-11 12:37:02 [INFO] Interface: wlan0 | IP: 192.168.1.2 | MAC: A4:5E:60:XX:XX:XX
2025-03-11 12:37:03 [INFO] Found 3 BSSIDs. Geolocating...
2025-03-11 12:37:04 [INFO] BSSID 00:14:22:01:23:45 | Location: 34.0522° N, 118.2437° W
```

### **Full Scan Output (All Modules - Basic Check)**
```
2025-03-11 12:40:00 [INFO] === Full Scan Started ===
2025-03-11 12:40:01 [INFO] Wi-Fi Scan: 2 networks found (1 open)
2025-03-11 12:40:02 [INFO] Bluetooth Scan: 1 device found
2025-03-11 12:40:03 [INFO] OS Security Check: All security checks passed
2025-03-11 12:40:04 [INFO] Network Metadata Scan: IP Geolocation & BSSID location retrieved
2025-03-11 12:40:05 [INFO] === Full Scan Complete ===
```

---

## Log Files
NST automatically saves **scan logs** in a `logs/` directory.
- Logs are named using a timestamp format:  
  ```
  NST_log_YYYYMMDD_HHMMSS.txt
  ```
- Old logs are **automatically deleted** after **7 days**.

---

## Troubleshooting

**Issue:** Wi-Fi scan shows no networks  
**Fix:** Ensure Wi-Fi is enabled and run as **Administrator/root** on Linux/macOS.

**Issue:** Bluetooth scan returns no devices  
**Fix:** Ensure **Bluetooth is turned on** and your device is **discoverable**.

**Issue:** GUI doesn't launch  
**Fix:** Make sure **Tkinter** is installed:
```
sudo apt-get install python3-tk  # (Linux)
```

**Issue:** Error retrieving public IP or BSSID location  
**Fix:** Check your **internet connection**. Some API requests may fail if a VPN is active.

---

## Potential Updates
- **IPv6 support** for network scanning.
- **Active connection tracking** for monitoring network activity.
- **More OS-specific security checks**.

---

## Contributing
Feel free to **fork the repository**, submit **pull requests**, or open **issues** for suggestions.

---

<img src="https://user-images.githubusercontent.com/74038190/212284100-561aa473-3905-4a80-b561-0d28506553ee.gif">
<div align="center">
  <a href="https://seperet.com">
    <img src=https://github.com/denv3rr/denv3rr/blob/main/Seperet_Slam_White.gif/>
  </a>
</div>
<img src="https://user-images.githubusercontent.com/74038190/212284100-561aa473-3905-4a80-b561-0d28506553ee.gif">
