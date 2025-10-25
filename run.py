# run.py
# CLI entry point

import os, subprocess, sys, importlib.util

# Define required packages:
# Add more here if needed for personal use
REQUIRED_PACKAGES = ['requests', 'ifaddr', 'texttable']

def is_installed(package_name):
    return importlib.util.find_spec(package_name) is not None

def check_and_install_requirements():
    missing = [pkg for pkg in REQUIRED_PACKAGES if not is_installed(pkg)]
    if missing:
        print(f"[🔧] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])  # <-- no -r

if __name__ == "__main__":
    check_and_install_requirements()
    print("\n" + "="*70)
    print(" Network Security Tester — ready to run")
    print(" Scans will not start until you confirm.")
    print("="*70 + "\n")
    input("Press Enter to start the scan (Ctrl+C to cancel)...\n")
    os.system(f"{sys.executable} network_security_tester.py")
