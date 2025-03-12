import tkinter as tk
import threading
import logging
from network_security_tester import run_full_scan

class NST_GUI:
    def __init__(self, root):
        self.root = root
        root.title("Network Security Tester")
        root.geometry("400x350")

        self.modules = {
            "Wi-Fi Scan": tk.IntVar(value=1),
            "Bluetooth Scan": tk.IntVar(value=1),
            "OS Security Check": tk.IntVar(value=1),
            "Network Metadata Scan": tk.IntVar(value=1)
        }

        for name, var in self.modules.items():
            tk.Checkbutton(root, text=name, variable=var).pack(anchor="w")

        tk.Button(root, text="Run Scan", command=self.start_scan).pack(pady=10)
        self.output_text = tk.Text(root, height=10, width=50)
        self.output_text.pack(fill="both", expand=True)

    def start_scan(self):
        selected = [key.lower().replace(" ", "_") for key, var in self.modules.items() if var.get()]
        threading.Thread(target=run_full_scan, args=(selected,)).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = NST_GUI(root)
    root.mainloop()
