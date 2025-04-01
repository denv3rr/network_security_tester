import tkinter as tk
import threading
import logging
import sys
from io import StringIO
from network_security_tester import run_full_scan

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
        root.geometry("500x350")
        self.stop_requested = False

        # Dictionary mapping: Label -> (internal module key, tkinter variable)
        self.modules = {
            "Wi-Fi Scan": ("wifi", tk.IntVar(value=1)),
            "Bluetooth Scan": ("bluetooth", tk.IntVar(value=1)),
            "OS Security Check": ("os", tk.IntVar(value=1)),
            "Network Metadata Scan": ("network", tk.IntVar(value=1)),
            "Port Scan": ("ports", tk.IntVar(value=1))
        }

        # Create checkboxes dynamically for each scan option
        for label, (_, var) in self.modules.items():
            tk.Checkbutton(root, text=label, variable=var).pack(anchor="w")

        # Frame to hold buttons in one row
        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)

        tk.Button(button_frame, text="▶ Run Scan", command=self.start_scan).pack(side="left", padx=10)
        tk.Button(button_frame, text="■ Stop Scan", command=self.stop_scan).pack(side="left")
        tk.Button(button_frame, text="🧹 Clear Output", command=self.clear_output).pack(side="left", padx=5)

        # Frame to hold Text output with vertical scrollbar
        output_frame = tk.Frame(root)
        output_frame.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(output_frame)
        scrollbar.pack(side="right", fill="y")

        self.output_text = tk.Text(output_frame, height=10, width=60, yscrollcommand=scrollbar.set)
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

    def start_scan(self):
        """Triggers a scan with selected modules in a background thread."""
        self.stop_requested = False
        selected = [key for _, (key, var) in self.modules.items() if var.get()]
        print("[DEBUG] Selected modules:", selected)
        print("Running selected scans...\n")
        threading.Thread(target=self.run_scan_thread, args=(selected,), daemon=True).start()

    def stop_scan(self):
        """Sets a flag to stop the scan process (logic to be respected in modules)."""
        self.stop_requested = True
        print("⚠️ Scan stop requested by user.\n")

    def clear_output(self):
        """Clears all output from the GUI text box."""
        self.output_text.delete(1.0, tk.END)

    def run_scan_thread(self, selected_modules):
        """Runs the selected scans in a thread-safe way."""
        if self.stop_requested:
            return
        result = run_full_scan(selected_modules)
        if not self.stop_requested:
            print(result + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NST_GUI(root)
    root.mainloop()
