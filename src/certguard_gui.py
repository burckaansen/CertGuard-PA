# ASCII only

import json
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from certguard_secrets import encrypt_config_secrets
except Exception:
    def encrypt_config_secrets(config):
        return config

BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
CONFIG_PATH = BASE_DIR / "config.json"
AGENT_PATH = BASE_DIR / "certguard_agent.py"
INSTALLER_PATH = BASE_DIR / "Install-CertGuard-PA.ps1"

DEFAULTS = {
    "firewall_host": "",
    "palo_api_key": "",
    "palo_api_key_dpapi": "",
    "skip_tls_validation": True,
    "certificate_name": "LE-test-example",
    "pfx_path": r"C:\certs\test.example.com.pfx",
    "pfx_password": "",
    "pfx_password_dpapi": "",
    "expected_domain": "test.example.com",
    "commit_after_import": False,
    "policy": {
        "import_if_pa_cert_missing": True,
        "block_on_domain_mismatch": True,
        "auto_import_only_if_expiring": True,
        "auto_import_expiry_threshold_days": 7,
        "require_local_newer_or_different": True,
        "use_win_acme_fallback": True
    },
    "deploy": {
        "retry_count": 3,
        "retry_delay_seconds": 5,
        "verify_after_import": True
    },
    "win_acme": {
        "path": r"C:\ProgramData\CertGuard-PA\win-acme\wacs.exe",
        "base_uri": "https://acme-v02.api.letsencrypt.org/",
        "renew_timeout_seconds": 900
    },
    "service": {
        "interval_seconds": 3600
    }
}


def merge_config(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_config(result[key], value)
        else:
            result[key] = value
    return result


def load_config():
    if not CONFIG_PATH.exists():
        return DEFAULTS.copy()
    try:
        return merge_config(DEFAULTS, json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    except Exception:
        return DEFAULTS.copy()


def save_config(data):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_config()
    secure_data = encrypt_config_secrets(data)

    if not secure_data.get("palo_api_key_dpapi") and existing.get("palo_api_key_dpapi"):
        secure_data["palo_api_key_dpapi"] = existing.get("palo_api_key_dpapi")
    if not secure_data.get("pfx_password_dpapi") and existing.get("pfx_password_dpapi"):
        secure_data["pfx_password_dpapi"] = existing.get("pfx_password_dpapi")

    secure_data.pop("palo_api_key", None)
    secure_data.pop("pfx_password", None)
    CONFIG_PATH.write_text(json.dumps(secure_data, indent=2), encoding="utf-8")


def run_agent(command):
    agent = str(AGENT_PATH if AGENT_PATH.exists() else Path(__file__).with_name("certguard_agent.py"))
    return subprocess.run([sys.executable, agent, command], text=True, capture_output=True, timeout=900)


def run_installer_action(action):
    if not INSTALLER_PATH.exists():
        raise FileNotFoundError(f"Installer not found in ProgramData: {INSTALLER_PATH}")
    return subprocess.run([
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(INSTALLER_PATH), "-Action", action
    ], text=True, capture_output=True, timeout=900)


def browse_file(entry, filetypes):
    path = filedialog.askopenfilename(filetypes=filetypes)
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


def open_debug_panel():
    try:
        os.startfile(str(BASE_DIR))
    except Exception as exc:
        messagebox.showerror("Debug", str(exc))


def wizard():
    cfg = load_config()

    root = tk.Tk()
    root.title("CertGuard-PA Setup Wizard")
    root.geometry("820x560")
    root.resizable(False, False)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    header = ttk.Frame(root, padding=(18, 14, 18, 6))
    header.pack(fill="x")
    title_var = tk.StringVar()
    desc_var = tk.StringVar()
    ttk.Label(header, textvariable=title_var, font=("Segoe UI", 16, "bold")).pack(anchor="w")
    ttk.Label(header, textvariable=desc_var).pack(anchor="w", pady=(4, 0))

    body = ttk.Frame(root, padding=(18, 8, 18, 8))
    body.pack(fill="both", expand=True)

    footer = ttk.Frame(root, padding=(18, 8, 18, 14))
    footer.pack(fill="x")

    pages = []
    entries = {}
    vars_ = {}
    page_index = tk.IntVar(value=0)

    def add_page(title, description):
        frame = ttk.Frame(body)
        pages.append((frame, title, description))
        return frame

    def add_entry(parent, label, key, value="", secret=False, browse=None):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=7)
        ttk.Label(row, text=label, width=30).pack(side="left")
        ent = ttk.Entry(row, show="*" if secret else None)
        ent.pack(side="left", fill="x", expand=True)
        ent.insert(0, str(value or ""))
        entries[key] = ent
        if browse:
            if browse == "pfx":
                filetypes = [("PFX/P12 files", "*.pfx *.p12"), ("All files", "*.*")]
            elif browse == "exe":
                filetypes = [("Executable", "*.exe"), ("All files", "*.*")]
            else:
                filetypes = [("All files", "*.*")]
            ttk.Button(row, text="Browse", command=lambda: browse_file(ent, filetypes)).pack(side="left", padx=(8, 0))
        return ent

    p1 = add_page("Step 1 - Palo Alto", "Enter the firewall endpoint and API key.")
    add_entry(p1, "Palo Alto Host", "firewall_host", cfg.get("firewall_host", ""))
    add_entry(p1, "Palo Alto API Key", "palo_api_key", "", secret=True)
    vars_["skip_tls_validation"] = tk.BooleanVar(value=bool(cfg.get("skip_tls_validation", True)))
    ttk.Checkbutton(p1, text="Skip TLS validation for Palo Alto API", variable=vars_["skip_tls_validation"]).pack(anchor="w", pady=8)

    p2 = add_page("Step 2 - Certificate", "Select the local PFX and define the Palo Alto certificate name.")
    add_entry(p2, "Certificate Name", "certificate_name", cfg.get("certificate_name", "LE-test-example"))
    add_entry(p2, "Expected FQDN", "expected_domain", cfg.get("expected_domain", "test.example.com"))
    add_entry(p2, "PFX Path", "pfx_path", cfg.get("pfx_path", ""), browse="pfx")
    add_entry(p2, "PFX Password", "pfx_password", "", secret=True)

    p3 = add_page("Step 3 - Policy", "Define when CertGuard-PA should import the certificate.")
    policy = cfg.get("policy", {})
    vars_["import_if_pa_cert_missing"] = tk.BooleanVar(value=bool(policy.get("import_if_pa_cert_missing", True)))
    vars_["block_on_domain_mismatch"] = tk.BooleanVar(value=bool(policy.get("block_on_domain_mismatch", True)))
    vars_["auto_import_only_if_expiring"] = tk.BooleanVar(value=bool(policy.get("auto_import_only_if_expiring", True)))
    vars_["require_local_newer_or_different"] = tk.BooleanVar(value=bool(policy.get("require_local_newer_or_different", True)))
    vars_["use_win_acme_fallback"] = tk.BooleanVar(value=bool(policy.get("use_win_acme_fallback", True)))
    ttk.Checkbutton(p3, text="Import if certificate does not exist on Palo Alto", variable=vars_["import_if_pa_cert_missing"]).pack(anchor="w", pady=4)
    ttk.Checkbutton(p3, text="Block import if local certificate does not match expected FQDN", variable=vars_["block_on_domain_mismatch"]).pack(anchor="w", pady=4)
    ttk.Checkbutton(p3, text="Auto import only if Palo Alto certificate is expiring", variable=vars_["auto_import_only_if_expiring"]).pack(anchor="w", pady=4)
    ttk.Checkbutton(p3, text="Require local certificate to be newer or different", variable=vars_["require_local_newer_or_different"]).pack(anchor="w", pady=4)
    ttk.Checkbutton(p3, text="Use win-acme fallback if local certificate is not newer", variable=vars_["use_win_acme_fallback"]).pack(anchor="w", pady=4)
    add_entry(p3, "Expiry Threshold Days", "auto_import_expiry_threshold_days", policy.get("auto_import_expiry_threshold_days", 7))

    p4 = add_page("Step 4 - win-acme", "Configure optional win-acme fallback renewal.")
    win_acme = cfg.get("win_acme", {})
    add_entry(p4, "Managed wacs.exe Path", "wacs_path", win_acme.get("path", r"C:\ProgramData\CertGuard-PA\win-acme\wacs.exe"))
    add_entry(p4, "ACME Base URI", "wacs_base_uri", win_acme.get("base_uri", "https://acme-v02.api.letsencrypt.org/"))
    add_entry(p4, "Renew Timeout Seconds", "wacs_timeout", win_acme.get("renew_timeout_seconds", 900))

    p5 = add_page("Step 5 - Deploy and Service", "Configure commit, retry and service interval settings.")
    deploy = cfg.get("deploy", {})
    service = cfg.get("service", {})
    vars_["commit_after_import"] = tk.BooleanVar(value=bool(cfg.get("commit_after_import", False)))
    vars_["verify_after_import"] = tk.BooleanVar(value=bool(deploy.get("verify_after_import", True)))
    ttk.Checkbutton(p5, text="Commit after import", variable=vars_["commit_after_import"]).pack(anchor="w", pady=5)
    ttk.Checkbutton(p5, text="Verify after import", variable=vars_["verify_after_import"]).pack(anchor="w", pady=5)
    add_entry(p5, "Retry Count", "retry_count", deploy.get("retry_count", 3))
    add_entry(p5, "Retry Delay Seconds", "retry_delay_seconds", deploy.get("retry_delay_seconds", 5))
    add_entry(p5, "Service Interval Seconds", "interval_seconds", service.get("interval_seconds", 3600))

    p6 = add_page("Step 6 - Review and Actions", "Save configuration, install service, and run tests.")
    log_box = tk.Text(p6, height=15, wrap="word")
    log_box.pack(fill="both", expand=True)

    def append_log(text):
        log_box.insert("end", text + "\n")
        log_box.see("end")
        root.update_idletasks()

    def collect_config():
        return {
            "firewall_host": entries["firewall_host"].get().strip(),
            "palo_api_key": entries["palo_api_key"].get().strip(),
            "skip_tls_validation": bool(vars_["skip_tls_validation"].get()),
            "certificate_name": entries["certificate_name"].get().strip(),
            "expected_domain": entries["expected_domain"].get().strip(),
            "pfx_path": entries["pfx_path"].get().strip(),
            "pfx_password": entries["pfx_password"].get(),
            "commit_after_import": bool(vars_["commit_after_import"].get()),
            "policy": {
                "import_if_pa_cert_missing": bool(vars_["import_if_pa_cert_missing"].get()),
                "block_on_domain_mismatch": bool(vars_["block_on_domain_mismatch"].get()),
                "auto_import_only_if_expiring": bool(vars_["auto_import_only_if_expiring"].get()),
                "auto_import_expiry_threshold_days": int(entries["auto_import_expiry_threshold_days"].get()),
                "require_local_newer_or_different": bool(vars_["require_local_newer_or_different"].get()),
                "use_win_acme_fallback": bool(vars_["use_win_acme_fallback"].get())
            },
            "deploy": {
                "retry_count": int(entries["retry_count"].get()),
                "retry_delay_seconds": int(entries["retry_delay_seconds"].get()),
                "verify_after_import": bool(vars_["verify_after_import"].get())
            },
            "win_acme": {
                "path": entries["wacs_path"].get().strip(),
                "base_uri": entries["wacs_base_uri"].get().strip(),
                "renew_timeout_seconds": int(entries["wacs_timeout"].get())
            },
            "service": {"interval_seconds": int(entries["interval_seconds"].get())}
        }

    def save_action():
        try:
            save_config(collect_config())
            append_log(f"Configuration saved securely to {CONFIG_PATH}")
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))

    def run_action(command):
        save_action()
        append_log(f"> certguard_agent.py {command}")
        try:
            proc = run_agent(command)
            if proc.stdout:
                append_log(proc.stdout.strip())
            if proc.stderr:
                append_log(proc.stderr.strip())
            append_log(f"Exit code: {proc.returncode}")
        except Exception as exc:
            append_log(f"ERROR: {exc}")

    def installer_action(action):
        save_action()
        append_log(f"> Install-CertGuard-PA.ps1 -Action {action}")
        try:
            proc = run_installer_action(action)
            if proc.stdout:
                append_log(proc.stdout.strip())
            if proc.stderr:
                append_log(proc.stderr.strip())
            append_log(f"Exit code: {proc.returncode}")
        except Exception as exc:
            append_log(f"ERROR: {exc}")

    action_row1 = ttk.Frame(p6)
    action_row1.pack(fill="x", pady=(8, 0))
    ttk.Button(action_row1, text="Save", command=save_action).pack(side="left", padx=4)
    ttk.Button(action_row1, text="Install Service", command=lambda: installer_action("InstallSilent")).pack(side="left", padx=4)
    ttk.Button(action_row1, text="Health", command=lambda: run_action("health")).pack(side="left", padx=4)
    ttk.Button(action_row1, text="Test API", command=lambda: run_action("test-pa")).pack(side="left", padx=4)
    ttk.Button(action_row1, text="Test WACS", command=lambda: run_action("test-wacs")).pack(side="left", padx=4)

    action_row2 = ttk.Frame(p6)
    action_row2.pack(fill="x", pady=(8, 0))
    ttk.Button(action_row2, text="Inspect PFX", command=lambda: run_action("inspect-pfx")).pack(side="left", padx=4)
    ttk.Button(action_row2, text="Policy", command=lambda: run_action("policy")).pack(side="left", padx=4)
    ttk.Button(action_row2, text="Deploy", command=lambda: run_action("deploy")).pack(side="left", padx=4)
    ttk.Button(action_row2, text="Renew WACS", command=lambda: run_action("renew-wacs")).pack(side="left", padx=4)
    ttk.Button(action_row2, text="Debug Folder", command=open_debug_panel).pack(side="left", padx=4)

    def show_page():
        for frame, _, _ in pages:
            frame.pack_forget()
        frame, title, desc = pages[page_index.get()]
        title_var.set(title)
        desc_var.set(desc)
        frame.pack(fill="both", expand=True)
        back_btn.config(state="normal" if page_index.get() > 0 else "disabled")
        next_btn.config(state="normal" if page_index.get() < len(pages) - 1 else "disabled")

    def next_page():
        if page_index.get() < len(pages) - 1:
            page_index.set(page_index.get() + 1)
            show_page()

    def back_page():
        if page_index.get() > 0:
            page_index.set(page_index.get() - 1)
            show_page()

    back_btn = ttk.Button(footer, text="Back", command=back_page)
    next_btn = ttk.Button(footer, text="Next", command=next_page)
    close_btn = ttk.Button(footer, text="Close", command=root.destroy)
    back_btn.pack(side="left", padx=4)
    next_btn.pack(side="left", padx=4)
    close_btn.pack(side="right", padx=4)
    show_page()
    root.mainloop()


if __name__ == "__main__":
    wizard()
