import tkinter as tk
from tkinter import ttk  # For themed widgets
import ttkbootstrap as tb  # For themes
import threading
import logging
import sys
from io import StringIO
from network_security_tester import run_full_scan
import netifaces  # For network interface selection

class TextRedirector:
    """Redirects logging output to a Tkinter Text widget."""
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)

    def flush(self):
        pass  # Required for compatibility with file-like objects

class NST_GUI:
    def __init__(self, root):
        self.root = root
        root.title("Network Security Tester")
        root.geometry("800x600")  # Increased size for better layout

        # Initialize Notebook (Tabbed Interface)
        self.notebook = tb.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Initialize variables
        self.stop_requested = False
        self.scan_thread = None
        self.output_text = None
        self.progress_bar = None

        self.create_tabs()

    def create_tabs(self):
        """Creates tabs for each scan module."""

        # Wi-Fi Scan Tab
        wifi_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(wifi_tab, text="Wi-Fi Scan")
        self.create_wifi_tab_content(wifi_tab)

        # Bluetooth Scan Tab
        bluetooth_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(bluetooth_tab, text="Bluetooth Scan")
        self.create_bluetooth_tab_content(bluetooth_tab)

        # OS Security Check Tab
        os_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(os_tab, text="OS Security")
        self.create_os_tab_content(os_tab)

        # Network Metadata Scan Tab
        network_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(network_tab, text="Network Data")
        self.create_network_tab_content(network_tab)

        # Port Scan Tab
        ports_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(ports_tab, text="Port Scan")
        self.create_ports_tab_content(ports_tab)

        # Output Tab (Common to all scans)
        output_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(output_tab, text="Output")
        self.create_output_tab_content(output_tab)

    def create_wifi_tab_content(self, tab):
        """Content for Wi-Fi Scan tab."""

        # Network Interface Selection
        interfaces = netifaces.interfaces()
        if interfaces:
            tk.Label(tab, text="Select Interface:").pack(anchor="w")
            self.wifi_interface_var = tk.StringVar(value=interfaces[0])  # Default to first interface
            tk.OptionMenu(tab, self.wifi_interface_var, *interfaces).pack(anchor="w")
        else:
            tk.Label(tab, text="No network interfaces found.").pack(anchor="w")

        # Scan Options (e.g., channels) - Placeholder for future implementation
        tk.Label(tab, text="Wi-Fi Scan Options (Coming Soon)").pack(anchor="w")

    def create_bluetooth_tab_content(self, tab):
        """Content for Bluetooth Scan tab."""
        tk.Label(tab, text="Bluetooth Scan Options (None currently)").pack(anchor="w")

    def create_os_tab_content(self, tab):
        """Content for OS Security tab."""
        tk.Label(tab, text="OS Security Options (None currently)").pack(anchor="w")

    def create_network_tab_content(self, tab):
        """Content for Network Metadata tab."""
        tk.Label(tab, text="Network Metadata Options (None currently)").pack(anchor="w")

    def create_ports_tab_content(self, tab):
        """Content for Port Scan tab."""

        # Port Range Selection
        tk.Label(tab, text="Port Range (e.g., 1-1000):").pack(anchor="w")
        self.port_range_var = tk.StringVar(value="1-1000")
        tk.Entry(tab, textvariable=self.port_range_var).pack(anchor="w")

        # Progress Bar
        self.progress_bar = ttk.Progressbar(tab, orient="horizontal", length=200, mode="determinate")
        self.progress_bar.pack(pady=10)

    def create_output_tab_content(self, tab):
        """Content for the Output tab (shared by all scans)."""

        # Frame to hold Text output with vertical scrollbar
        output_frame = tk.Frame(tab)
        output_frame.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(output_frame, orient=tk.VERTICAL)
        scrollbar.pack(side="right", fill="y")

        self.output_text = tk.Text(output_frame, height=15, width=80, yscrollcommand=scrollbar.set)
        self.output_text.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.output_text.yview)

        # Redirect stdout/stderr/logging output to GUI
        sys.stdout = TextRedirector(self.output_text)
        sys.stderr = TextRedirector(self.output_text)
        logging.getLogger().handlers.clear()
        logging.basicConfig(
            stream=sys.stdout,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s"
        )

        # Button Frame (Run/Stop/Clear)
        button_frame = tk.Frame(tab)
        button_frame.pack(pady=5)

        tk.Button(button_frame, text="▶ Run Scan", command=self.start_scan).pack(side="left", padx=10)
        tk.Button(button_frame, text="■ Stop Scan", command=self.stop_scan).pack(side="left")
        tk.Button(button_frame, text="🧹 Clear Output", command=self.clear_output).pack(side="left", padx=5)

    def start_scan(self):
        """Triggers a scan with selected modules in a background thread."""

        self.stop_requested = False
        selected_modules = self.get_selected_modules()
        print("[DEBUG] Selected modules:", selected_modules)
        print("Running selected scans...\n")
        self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(selected_modules,), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        """Sets a flag to stop the scan process (logic to be respected in modules)."""

        self.stop_requested = True
        print("⚠️ Scan stop requested by user.\n")
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(100, self.check_scan_thread)  # Check thread status after 100ms

    def check_scan_thread(self):
        """Checks if the scan thread has finished and handles cleanup."""
        if self.scan_thread.is_alive():
            self.root.after(100, self.check_scan_thread)  # Check again later
        else:
            self.scan_thread = None  # Clear the thread
            self.update_progress(0)  # Reset progress bar

    def clear_output(self):
        """Clears all output from the GUI text box."""
        self.output_text.delete(1.0, tk.END)

    def get_selected_modules(self):
        """Determines which modules are selected based on tab."""

        selected_modules = []
        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "Wi-Fi Scan":
            selected_modules.append("wifi")
        elif tab_text == "Bluetooth Scan":
            selected_modules.append("bluetooth")
        elif tab_text == "OS Security":
            selected_modules.append("os")
        elif tab_text == "Network Data":
            selected_modules.append("network")
        elif tab_text == "Port Scan":
            selected_modules.append("ports")

        return selected_modules

    def run_scan_thread(self, selected_modules):
        """Runs the selected scans in a thread-safe way."""

        if self.stop_requested:
            return

        # Pass options from GUI
        scan_options = {}
        if "wifi" in selected_modules:
            scan_options["wifi_interface"] = self.wifi_interface_var.get() if hasattr(self, "wifi_interface_var") else None
        if "ports" in selected_modules:
            scan_options["port_range"] = self.port_range_var.get() if hasattr(self, "port_range_var") else "1-65535"

        result = run_full_scan(selected_modules, **scan_options)  # Pass options to run_full_scan

        if not self.stop_requested:
            print(result + "\n")
        self.update_progress(0)  # Reset progress bar when scan finishes

    def update_progress(self, progress):
        """Updates the progress bar in the Port Scan tab."""
        if self.progress_bar:
            self.progress_bar['value'] = progress
            self.root.update_idletasks()

if __name__ == "__main__":
    root = tb.Window(themename="superhero")  # Use a modern theme
    app = NST_GUI(root)
    root.mainloop()