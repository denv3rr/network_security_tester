from setuptools import setup, find_packages

setup(
    name="network-explorer",
    version="1.0.0",
    description="Network security and metadata explorer",
    packages=find_packages(),
    py_modules=[
        "network_explorer", 
        "wifi_scan", 
        "port_scanner", 
        "bluetooth_scan", 
        "os_security", 
        "network_scanner",
        "pentest_tools"
    ],
    install_requires=[
        "requests",
        "ifaddr",
        "texttable",
        "bleak",
        "colorama"
    ],
    entry_points={
        'console_scripts': [
            'nex=network_explorer:main',
        ],
    },
    python_requires='>=3.9',
)
