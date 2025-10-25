# run.py
# Simple launcher: installs minimal deps, shows a header, waits for Enter, then starts main app

import os
import subprocess
import sys
import importlib.util

REQUIRED_PACKAGES = ['requests', 'ifaddr', 'texttable']

def is_installed(pkg: str) -> bool:
    return importlib.util.find_spec(pkg) is not None

def check_and_install_requirements():
    missing = [p for p in REQUIRED_PACKAGES if not is_installed(p)]
    if missing:
        print(f"[🔧] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])

if __name__ == "__main__":
    check_and_install_requirements()
    print("\n" + "="*70)
    print(" Network Security Tester — CLI")
    print(" Scans won’t start until you confirm.")
    print("="*70 + "\n")
    try:
        input("Press Enter to start (Ctrl+C to cancel)... ")
    except KeyboardInterrupt:
        sys.exit(0)
    os.execv(sys.executable, [sys.executable, "network_security_tester.py"])
