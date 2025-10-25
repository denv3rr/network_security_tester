<div align="center">

  ![GitHub repo size](https://img.shields.io/github/repo-size/denv3rr/network_security_tester)
  ![GitHub Created At](https://img.shields.io/github/created-at/denv3rr/network_security_tester)
  ![Last Commit](https://img.shields.io/github/last-commit/denv3rr/network_security_tester)
  ![Issues](https://img.shields.io/github/issues/denv3rr/network_security_tester)
  ![License](https://img.shields.io/github/license/denv3rr/network_security_tester)
  ![Website](https://img.shields.io/website?url=https%3A%2F%2Fseperet.com&label=seperet.com)
  
</div>

Multi-platform Python tool for **network and host security assessment** and **geolocation via IP lookup**. No GUI. Works on **Windows, Linux, and macOS**.

---

## Features

- **Wi-Fi scanning**
  - Lists visible networks, channels, BSSIDs, and optional BSSID/IP geolocation.
- **Port scanning**
  - Multi-threaded, fast “top” mode and full custom ranges.
- **Bluetooth scanning**
  - Discovers nearby devices (module placeholder; extendable via `bleak`).
- **OS security checks**
  - Detects platform and basic system protection status (stub for future deep checks).
- **Network metadata scanning (wired or wireless)**
  - Reports hostname, local IPs, interfaces, gateway, public IP, ISP, ASN, and geographic info.
- **Full Scan mode**
  - Runs all modules in a single command.

---

## Quick Start Options

### Run from terminal (any OS)

```bash
python network_security_tester.py --all
```

Or for specific modules:

```bash
python network_security_tester.py --wifi --ports --network
```

---

## Installation

### **1. Requirements**

- **Python 3.8+**
- Recommended modules (auto-installed at runtime via `requirements.txt`):
  - `requests`
  - `ifaddr`
  - `texttable`

- or install manually before running:

```bash
pip install -r requirements.txt
```

### **2. Clone or Download**

```bash
git clone https://github.com/denv3rr/network_security_tester.git
cd network_security_tester
```

---

## Usage (CLI)

### **Basic commands**

| Action | Command |
|--------|----------|
| Run all modules | `python network_security_tester.py --all` |
| Wi-Fi scan only | `python network_security_tester.py --wifi` |
| Port scan (top) | `python network_security_tester.py --ports` |
| Port scan (custom range) | `python network_security_tester.py --ports 1-2000` |
| Network metadata (wired support) | `python network_security_tester.py --network` |
| OS security check | `python network_security_tester.py --os` |
| Bluetooth scan | `python network_security_tester.py --bluetooth` |
| Save JSON report | `python network_security_tester.py --all --json results.json` |
| Disable colors | `python network_security_tester.py --all --no-color` |
| Silent mode | `python network_security_tester.py --all --silent` |

---

## 🗂 Logs & Output

- Logs are automatically written to the `logs/` directory.
- Files follow timestamp format:
  ```
  NST_YYYYMMDD_HHMMSS.log
  ```
- Old logs (>7 days) are automatically pruned.

---

## ⚙️ Troubleshooting

| Issue | Fix |
|-------|-----|
| **Wi-Fi scan shows “No Wi-Fi data.”** | Ensure Wi-Fi adapter is enabled and, on Windows, run as **Administrator** with **Location Services ON**. |
| **No results on wired connection** | Use `--network` to retrieve public IP and geolocation via IP-based lookup. |
| **Bluetooth not implemented** | Placeholder module |
| **Permission errors (Linux/macOS)** | Run with `sudo` if needed for raw socket access. |

---

## To Add...

- IPv6 scanning  
- Advanced OS vulnerability checks  
- Optional Bleak-based Bluetooth discovery

---

[COMMENT]: <LOGO*****************************************>
<div align="center">
  <a href="https://seperet.com">
    <img src=https://github.com/denv3rr/denv3rr/blob/main/IMG_4225.gif/>    
  </a>
</div>
<<<<<<< HEAD
<br></br>
=======
<br></br>

>>>>>>> b2a1da4445fbc9c4494f25b6356d9ca99bf4d660
