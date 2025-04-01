# Run file intended for easy GUI launch

import os
import subprocess
import sys
import importlib.util

REQUIRED_PACKAGES = ['requests', 'netifaces']

def is_installed(package_name):
    return importlib.util.find_spec(package_name) is not None

def check_and_install_requirements():
    missing = [pkg for pkg in REQUIRED_PACKAGES if not is_installed(pkg)]
    if missing:
        print(f"[🔧] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

check_and_install_requirements()

# Launch main program (GUI by default)
os.system("python network_security_tester.py --gui")
