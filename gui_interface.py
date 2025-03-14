import tkinter as tk
import threading
import logging
from network_security_tester import run_full_scan

class NST_GUI:
    def __init__(self, root):
        self.root = root
        root.title("Network Security Tester")
        root.geometry("400x400")

        # Dictionary to hold scan modules
        self.modules = {
            "Wi-Fi Scan": tk.IntVar(value=1),
            "Bluetooth Scan": tk.IntVar(value=1),
            "OS Security Check": tk.IntVar(value=1),
            "Network Metadata Scan": tk.IntVar(value=1),
            "Port Scan": tk.IntVar(value=1)
        }

        # Generate checkboxes dynamically
        for name, var in self.modules.items():
            tk.Checkbutton(root, text=name, variable=var).pack(anchor="w")

        # Button to start the scan
        tk.Button(root, text="Run Scan", command=self.start_scan).pack(pady=10)

        # Text box for output display
        self.output_text = tk.Text(root, height=10, width=50)
        self.output_text.pack(fill="both", expand=True)

    def start_scan(self):
        """Starts the scan based on user-selected modules."""
        selected = [
            key.lower().replace(" ", "_") for key, var in self.modules.items() if var.get()
        ]
        threading.Thread(target=self.run_scan_thread, args=(selected,)).start()

    def run_scan_thread(self, selected_modules):
        """Runs the scan in a separate thread to prevent UI freezing."""
        logging.info("Running selected scans...")
        result = run_full_scan(selected_modules)
        self.output_text.insert(tk.END, result + "\n")
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NST_GUI(root)
    root.mainloop()
