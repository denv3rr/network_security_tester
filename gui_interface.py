import tkinter as tk
from tkinter import ttk  # For themed widgets
import ttkbootstrap as tb  # For modern themes
import threading
import logging
import sys
from io import StringIO
from network_security_tester import Scanner  # Import the Scanner class instead of run_full_scan
import netifaces  # For network interface selection
import queue  # Import the queue module

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
        self.scanner = Scanner()  # Instantiate the Scanner class
        self.output_queue = queue.Queue()  # Initialize the output queue
        self.selected_modules = {  # Track selected modules
            "wifi": tk.BooleanVar(value=True),
            "bluetooth": tk.BooleanVar(value=True),
            "os": tk.BooleanVar(value=True),
            "network": tk.BooleanVar(value=True),
            "ports": tk.BooleanVar(value=True),
        }

        self.create_tabs()

    def create_tabs(self):
        """Creates tabs for each scan module."""

        # Run Tab (Global Scan Selection)
        run_tab = tb.Frame(self.notebook, padding=10)
        self.notebook.add(run_tab, text="Run")
        self.create_run_tab_content(run_tab)

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

    def create_run_tab_content(self, tab):
        """Content for the Run tab (global scan selection)."""

        tk.Label(tab, text="Select Scans to Run:").pack(anchor="w")

        # Create checkboxes for each module
        tk.Checkbutton(tab, text="Wi-Fi Scan", variable=self.selected_modules["wifi"]).pack(anchor="w")
        tk.Checkbutton(tab, text="Bluetooth Scan", variable=self.selected_modules["bluetooth"]).pack(anchor="w")
        tk.Checkbutton(tab, text="OS Security Scan", variable=self.selected_modules["os"]).pack(anchor="w")
        tk.Checkbutton(tab, text="Network Metadata Scan", variable=self.selected_modules["network"]).pack(anchor="w")
        tk.Checkbutton(tab, text="Port Scan", variable=self.selected_modules["ports"]).pack(anchor="w")

        tk.Button(tab, text="▶ Run All Selected Scans", command=self.start_scan).pack(pady=10)

    def create_wifi_tab_content(self, tab):
        """Content for Wi-Fi Scan tab."""

        # Module Selection Checkbox
        wifi_check = tk.Checkbutton(tab, text="Enable Wi-Fi Scan", variable=self.selected_modules["wifi"])
        wifi_check.pack(anchor="w")

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
        # Placeholder for channel selection (future)
        # tk.Label(tab, text="Select Channels:").pack(anchor="w")
        # self.wifi_channels_var = tk.StringVar(value="All")
        # tk.Entry(tab, textvariable=self.wifi_channels_var).pack(anchor="w")

        tk.Button(tab, text="▶ Run Wi-Fi Scan", command=self.run_single_wifi_scan).pack(pady=10)

    def create_bluetooth_tab_content(self, tab):
        """Content for Bluetooth Scan tab."""

        # Module Selection Checkbox
        bluetooth_check = tk.Checkbutton(tab, text="Enable Bluetooth Scan", variable=self.selected_modules["bluetooth"])
        bluetooth_check.pack(anchor="w")

        tk.Label(tab, text="Bluetooth Scan Options (None currently)").pack(anchor="w")

        tk.Button(tab, text="▶ Run Bluetooth Scan", command=self.run_single_bluetooth_scan).pack(pady=10)

    def create_os_tab_content(self, tab):
        """Content for OS Security tab."""

        # Module Selection Checkbox
        os_check = tk.Checkbutton(tab, text="Enable OS Security Scan", variable=self.selected_modules["os"])
        os_check.pack(anchor="w")

        tk.Label(tab, text="OS Security Options (None currently)").pack(anchor="w")

        tk.Button(tab, text="▶ Run OS Security Scan", command=self.run_single_os_scan).pack(pady=10)

    def create_network_tab_content(self, tab):
        """Content for Network Metadata tab."""

        # Module Selection Checkbox
        network_check = tk.Checkbutton(tab, text="Enable Network Metadata Scan", variable=self.selected_modules["network"])
        network_check.pack(anchor="w")

        tk.Label(tab, text="Network Metadata Options (None currently)").pack(anchor="w")

        tk.Button(tab, text="▶ Run Network Metadata Scan", command=self.run_single_network_scan).pack(pady=10)

    def create_ports_tab_content(self, tab):
        """Content for Port Scan tab."""

        # Module Selection Checkbox
        ports_check = tk.Checkbutton(tab, text="Enable Port Scan", variable=self.selected_modules["ports"])
        ports_check.pack(anchor="w")

        # Port Range Selection
        tk.Label(tab, text="Port Range (e.g., 1-1000):").pack(anchor="w")
        self.port_range_var = tk.StringVar(value="1-65535")  # Changed default to full range
        tk.Entry(tab, textvariable=self.port_range_var).pack(anchor="w")

        # Progress Bar
        self.progress_bar = ttk.Progressbar(tab, orient="horizontal", length=200, mode="determinate")
        self.progress_bar.pack(pady=10)

        # Placeholder for port presets (future)
        tk.Label(tab, text="Port Presets (Coming Soon)").pack(anchor="w")
        # self.port_preset_var = tk.StringVar(value="All")
        # tk.Combobox(tab, textvariable=self.port_preset_var, values=["All", "Common", "Specific"]).pack(anchor="w")

        tk.Button(tab, text="▶ Run Port Scan", command=self.run_single_port_scan).pack(pady=10)

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
        # sys.stdout = TextRedirector(self.output_text) # Remove stdout/stderr redirection
        # sys.stderr = TextRedirector(self.output_text)
        logging.getLogger().handlers.clear()
        logging.basicConfig(
            stream=TextRedirector(self.output_text),  # Use TextRedirector for logging only
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )

        # Button Frame (Run/Stop/Clear)
        button_frame = tk.Frame(tab)
        button_frame.pack(pady=5)

        tk.Button(button_frame, text="■ Stop Scan", command=self.stop_scan).pack(side="left")
        tk.Button(button_frame, text="🧹 Clear Output", command=self.clear_output).pack(side="left", padx=5)

    def start_scan(self):
        """Triggers a scan with selected modules in a background thread."""

        self.stop_requested = False
        selected_modules_list = self.get_selected_modules()
        print("[DEBUG] Selected modules:", selected_modules_list)
        print("Running selected scans...\n")
        self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(selected_modules_list,), daemon=True)
        self.scan_thread.start()
        self.root.after(100, self.update_output)  # Start checking the queue

    def stop_scan(self):
        """Sets a flag to stop the scan process (logic to be respected in modules)."""

        self.stop_requested = True
        print("⚠️ Scan stop requested by user.\n")
        # Disable the stop button while the thread is stopping
        # This prevents multiple stop requests
        self.stop_button.config(state="disabled")
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(100, self.check_scan_thread)  # Check thread status after 100ms
        else:
            self.stop_button.config(state="normal") # Re-enable the stop button

    def check_scan_thread(self):
        """Checks if the scan thread has finished and handles cleanup."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(100, self.check_scan_thread)  # Check again later
        else:
            self.scan_thread = None  # Clear the thread
            self.update_progress(0)  # Reset progress bar
            self.stop_button.config(state="normal") # Re-enable the stop button

    def clear_output(self):
        """Clears all output from the GUI text box."""
        self.output_text.delete(1.0, tk.END)

    def get_selected_modules(self):
        """Determines which modules are selected based on checkboxes."""

        selected_modules = [
            module for module, var in self.selected_modules.items() if var.get()
        ]
        return selected_modules

    def run_scan_thread(self, selected_modules):
        """Runs the selected scans in a thread-safe way."""

        if self.stop_requested:
            return

        # Pass options from GUI
        scan_options = {}
        if "wifi" in selected_modules:
            scan_options["wifi_interface"] = (
                self.wifi_interface_var.get() if hasattr(self, "wifi_interface_var") else None
            )
        if "ports" in selected_modules:
            scan_options["port_range"] = (
                self.port_range_var.get() if hasattr(self, "port_range_var") else "1-65535"
            )

        # Instantiate Scanner if it doesn't exist
        if not hasattr(self, "scanner") or self.scanner is None:
            self.scanner = Scanner(output_queue=self.output_queue, stop_flag=self.stop_requested)  # Pass the queue and stop flag to the Scanner
        else:
            self.scanner.output_queue = self.output_queue  # Update the scanner's queue
            self.scanner.stop_flag = self.stop_requested

        self.scanner.run_scan(selected_modules, **scan_options)  # Call the Scanner's run_scan method

        if not self.stop_requested:
            self.output_queue.put(None)  # Signal end of scan to the queue

        self.update_progress(0)  # Reset progress bar when scan finishes

    def update_progress(self, progress):
        """Updates the progress bar in the Port Scan tab."""
        if self.progress_bar:
            self.progress_bar["value"] = progress
            self.root.update_idletasks()

    def update_output(self):
        """Updates the output text box with messages from the queue."""
        try:
            while True:
                message = self.output_queue.get_nowait()
                if message is None:
                    break  # End of queue
                self.output_text.insert(tk.END, message + "\n")
                self.output_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.update_output)  # Check the queue again after 100ms

    def run_single_wifi_scan(self):
        """Runs only the Wi-Fi scan."""
        self.notebook.select(6)  # Switch to Output tab
        self.start_scan_single(["wifi"])

    def run_single_bluetooth_scan(self):
        """Runs only the Bluetooth scan."""
        self.notebook.select(6)  # Switch to Output tab
        self.start_scan_single(["bluetooth"])

    def run_single_os_scan(self):
        """Runs only the OS Security scan."""
        self.notebook.select(6)  # Switch to Output tab
        self.start_scan_single(["os"])

    def run_single_network_scan(self):
        """Runs only the Network Metadata scan."""
        self.notebook.select(6)  # Switch to Output tab
        self.start_scan_single(["network"])

    def run_single_port_scan(self):
        """Runs only the Port scan."""
        self.notebook.select(6)  # Switch to Output tab
        self.start_scan_single(["ports"])

    def start_scan_single(self, module_list):
        """Starts a scan for a single module."""

        self.stop_requested = False
        print(f"[DEBUG] Running single scan: {module_list[0]}")
        self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(module_list,), daemon=True)
        self.scan_thread.start()
        self.root.after(100, self.update_output)  # Start checking the queue

    def start_scan_all(self):
        """Starts a scan for all modules."""
        self.stop_requested = False
        selected_modules_list = self.get_selected_modules()
        print("[DEBUG] Running all selected scans")
        self.scan_thread = threading.Thread(target=self.run_scan_thread, args=(selected_modules_list,), daemon=True)
        self.scan_thread.start()
        self.root.after(100, self.update_output)