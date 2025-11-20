# run.py
# Simple launcher: installs minimal deps and runs main app (network_security_tester.py)

import importlib.util
import subprocess
import sys
import os

REQUIRED_PACKAGES = ['requests', 'ifaddr', 'texttable', 'bleak', 'colorama']


def is_installed(pkg: str) -> bool:
    return importlib.util.find_spec(pkg) is not None


def check_and_install_requirements():
    missing = [p for p in REQUIRED_PACKAGES if not is_installed(p)]
    if missing:
        print(f"[🔧] Installing missing packages: {', '.join(missing)}")

        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


def main():
    check_and_install_requirements()

    print("\n" + "=" * 70)
    print(" Network Explorer \n")
    print(" Visit: https://seperet.com ")
    print(" Repo: https://github.com/denv3rr/network-explorer ")
    print("=" * 70 + "\n")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    import network_security_tester  # type: ignore

    network_security_tester.main()


if __name__ == "__main__":
    main()
