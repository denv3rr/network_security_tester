<div align="center">

  <div>

  <!-- Shields.io Info -->
  [![Python](https://img.shields.io/badge/python-3.9+-blue)](#)
  ![GitHub repo size](https://img.shields.io/github/repo-size/denv3rr/network-explorer)
  ![GitHub Created At](https://img.shields.io/github/created-at/denv3rr/network-explorer)
  ![Last Commit](https://img.shields.io/github/last-commit/denv3rr/network-explorer)
  ![Issues](https://img.shields.io/github/issues/denv3rr/network-explorer)
  ![License](https://img.shields.io/github/license/denv3rr/network-explorer)
  ![Website](https://img.shields.io/website?url=https%3A%2F%2Fseperet.com&label=seperet.com)

  <!-- OS Icons -->
  <img width="32" alt="image" src="https://github.com/user-attachments/assets/3b32cddc-c6c6-4acc-b2de-d01b30e5613d" />
  <img width="32" alt="image" src="https://github.com/user-attachments/assets/af8dec60-cab6-4c1a-8ea3-9cb2d75e8516" />
  <img width="32" alt="image" src="https://github.com/user-attachments/assets/df923ccd-dd6a-4b86-9864-2c5d6cea4e4a" />

  </div>
  
</div>

<br><br>

<div align="center">

<div align="center">
  <a href="https://seperet.com">
    <img width="100" src=https://github.com/denv3rr/denv3rr/blob/main/IMG_4225.gif/>    
  </a>
</div>

  [About](#about) |
  [Features](#features) |
  [Quick Start](#quick-start) |
  [Manual Installation](#manual-installation) |
  [Specific Usage](#specific-usage) |
  [Logs](#logs) |
  [Troubleshooting](#troubleshooting) |
  [seperet.com](https://seperet.com)
  
</div>

---

## About

A Python tool for quick **network and host security assessment**.

---

## Features

- **Main Menu**
  - Launch without flags or arguments to access a user-friendly menu.
- **Wi-Fi scanning**
  - Lists visible networks, channels, BSSIDs, signal strength, and optional BSSID/IP geolocation.
- **Port scanning**
  - **Top TCP** (Fast), **Full Connect**, and **UDP** (Payload Probe) modes.
- **Bluetooth scanning**
  - Discovers nearby BLE devices with RSSI signal strength and metadata (using `bleak`).
- **OS security checks**
  - Detects Firewall status and Antivirus presence on Windows, Linux, and macOS.
- **Network metadata scanning**
  - Identifies connection type (Wired/Wi-Fi), local identity, public IP, ISP, ASN, and geographic info.
- **Full Scan mode**
  - One-click execution of all modules with intelligent defaults.

---

## Quick Start

Run:

```bash
git clone https://github.com/denv3rr/network-explorer.git
cd network-explorer
python run.py
```

---

## Manual Installation

### **1. Check Requirements**

- **Python 3.9+**
- Modules auto-installed at runtime via `requirements.txt`. See <a href="#quick-start">Quick Start</a> above.
  - `requests`
  - `ifaddr`
  - `texttable`
  - `bleak`
  - `colorama`

- or install with this command before running:

```bash
pip install -r requirements.txt
```

### **2. Clone or Download**

- Clone

  - ```bash
    git clone https://github.com/denv3rr/network-explorer.git
    cd network-explorer
    ```
- Download
  
    - `.zip`:  [network-explorer-main](https://github.com/denv3rr/network-explorer/archive/refs/heads/main.zip)

### **3. Run**
  
```bash
python run.py
```

---

## Specific Usage

### **Basic commands**

| Action | Command |
|--------|----------|
| Quick Start | `python run.py` |
| Run all modules | `python run.py --all` |
| Wi-Fi scan only | `python run.py --wifi` |
| Port scan (top) | `python run.py --ports` |
| Port scan (custom range) | `python run.py --ports 1-2000` |
| Network metadata (wired support) | `python run.py --network` |
| OS security check | `python run.py --os` |
| Bluetooth scan | `python run.py --bluetooth` |
| Save JSON report | `python run.py --all --json results.json` |
| Disable colors | `python run.py --all --no-color` |
| Silent mode | `python run.py --all --silent` |

---

## Logs

- Logs are automatically written to the `logs/` directory.
- Files follow timestamp format:
  ```
  NEX_YYYYMMDD_HHMMSS.log
  ```
- Old logs (>7 days) are automatically pruned.

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| **Wi-Fi scan shows “No Wi-Fi data.”** | Ensure Wi-Fi adapter is enabled and, on Windows, run as **Administrator** with **Location Services ON**. |
| **No results on wired connection** | Use `--network` to retrieve public IP and geolocation via IP-based lookup. |
| **Bluetooth not implemented** | Placeholder module |
| **Permission errors (Linux/macOS)** | Run with `sudo` if needed for raw socket access. |

---

[COMMENT]: <LOGO*****************************************>
<div align="center">
  <a href="https://seperet.com">
    <img src=https://github.com/denv3rr/denv3rr/blob/main/IMG_4225.gif/>    
  </a>
</div>

