# Run file intended for easy GUI launch

import os
import subprocess
import sys
import pkg_resources

REQUIRED_PACKAGES = ['requests', 'netifaces']

def check_and_install_requirements():
    try:
        pkg_resources.require(REQUIRED_PACKAGES)
    except pkg_resources.DistributionNotFound:
        print("[🔧] Installing missing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except pkg_resources.VersionConflict as e:
        print(f"[⚠️] Version conflict: {e}. Reinstalling...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"])

check_and_install_requirements()

# Launch GUI
os.system("python network_security_tester.py --gui")