# ASCII only

import json
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
CONFIG_PATH = BASE_DIR / "config.json"


def save_config(data):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2))


def run_install():
    messagebox.showinfo("CertGuard-PA", "Configuration saved. Starting install...")
    subprocess.Popen(["python", "certguard_agent.py", "deploy"])


def browse_pfx(entry):
    path = filedialog.askopenfilename(filetypes=[("PFX files", "*.pfx")])
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


def wizard():
    root = tk.Tk()
    root.title("CertGuard-PA Setup Wizard")
    root.geometry("400x300")

    fields = {}

    def add_field(label):
        frame = tk.Frame(root)
        frame.pack(fill="x", pady=5)
        tk.Label(frame, text=label).pack(anchor="w")
        entry = tk.Entry(frame)
        entry.pack(fill="x")
        fields[label] = entry
        return entry

    host = add_field("Palo Alto Host")
    api = add_field("API Key")
    name = add_field("Certificate Name")

    pfx_frame = tk.Frame(root)
    pfx_frame.pack(fill="x", pady=5)
    tk.Label(pfx_frame, text="PFX Path").pack(anchor="w")
    pfx_entry = tk.Entry(pfx_frame)
    pfx_entry.pack(side="left", fill="x", expand=True)
    tk.Button(pfx_frame, text="Browse", command=lambda: browse_pfx(pfx_entry)).pack(side="right")

    pwd = add_field("PFX Password")

    def submit():
        data = {
            "firewall_host": host.get(),
            "palo_api_key": api.get(),
            "certificate_name": name.get(),
            "pfx_path": pfx_entry.get(),
            "pfx_password": pwd.get(),
        }
        save_config(data)
        run_install()

    tk.Button(root, text="Install", command=submit).pack(pady=15)

    root.mainloop()


if __name__ == "__main__":
    wizard()
