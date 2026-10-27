# ASCII only

import json
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QPoint, QThread, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap, QPolygon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from certguard_secrets import encrypt_config_secrets
except Exception:
    def encrypt_config_secrets(config):
        return config

APP_NAME = "CertGuard-PA"
BASE_DIR = Path(r"C:\ProgramData\CertGuard-PA")
CONFIG_PATH = BASE_DIR / "config.json"
AGENT_PATH = BASE_DIR / "certguard_agent.py"
INSTALLER_PATH = BASE_DIR / "Install-CertGuard-PA.ps1"

DEFAULT_CONFIG = {
    "firewall_host": "",
    "palo_api_key": "",
    "palo_api_key_dpapi": "",
    "skip_tls_validation": True,
    "certificate_name": "LE-test-example",
    "pfx_path": r"C:\certs\test.example.com.pfx",
    "pfx_password": "",
    "pfx_password_dpapi": "",
    "cloudflare_api_token": "",
    "cloudflare_api_token_dpapi": "",
    "cloudflare_zone": "",
    "expected_domain": "test.example.com",
    "commit_after_import": False,
    "policy": {
        "import_if_pa_cert_missing": True,
        "block_on_domain_mismatch": True,
        "auto_import_only_if_expiring": True,
        "auto_import_expiry_threshold_days": 7,
        "require_local_newer_or_different": True,
        "use_win_acme_fallback": True,
        "block_private_key_export_on_import": True,
    },
    "deploy": {
        "retry_count": 3,
        "retry_delay_seconds": 5,
        "verify_after_import": True,
    },
    "win_acme": {
        "path": r"C:\ProgramData\CertGuard-PA\win-acme\wacs.exe",
        "base_uri": "https://acme-v02.api.letsencrypt.org/",
        "renew_timeout_seconds": 900,
    },
    "service": {
        "interval_seconds": 3600,
    },
}


def build_app_icon():
    pixmap = QPixmap(256, 256)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    painter.setBrush(QColor(15, 23, 42))
    painter.setPen(QPen(QColor(59, 130, 246), 4))
    painter.drawRoundedRect(18, 18, 220, 220, 44, 44)

    painter.setPen(QPen(QColor(30, 64, 175), 2))
    painter.drawRoundedRect(35, 35, 186, 186, 34, 34)

    shield = QPolygon([
        QPoint(128, 54), QPoint(187, 78), QPoint(178, 151),
        QPoint(128, 198), QPoint(78, 151), QPoint(69, 78),
    ])
    painter.setBrush(QColor(37, 99, 235))
    painter.setPen(QPen(QColor(147, 197, 253), 2))
    painter.drawPolygon(shield)

    inner = QPolygon([
        QPoint(128, 72), QPoint(168, 91), QPoint(162, 143),
        QPoint(128, 178), QPoint(94, 143), QPoint(88, 91),
    ])
    painter.setBrush(QColor(30, 41, 59))
    painter.setPen(QPen(QColor(96, 165, 250), 2))
    painter.drawPolygon(inner)

    painter.setBrush(QColor(248, 250, 252))
    painter.setPen(QPen(QColor(248, 250, 252), 1))
    painter.drawRoundedRect(102, 98, 52, 56, 7, 7)
    painter.setBrush(QColor(191, 219, 254))
    painter.drawPolygon(QPolygon([QPoint(142, 98), QPoint(154, 110), QPoint(142, 110)]))

    painter.setPen(QPen(QColor(37, 99, 235), 3))
    painter.drawLine(113, 116, 145, 116)
    painter.drawLine(113, 128, 145, 128)
    painter.drawLine(113, 140, 145, 140)

    painter.setBrush(QColor(59, 130, 246))
    painter.setPen(QPen(QColor(59, 130, 246), 1))
    painter.drawRoundedRect(106, 160, 44, 34, 8, 8)
    painter.setPen(QPen(QColor(191, 219, 254), 6))
    painter.drawArc(111, 138, 34, 40, 0, 180 * 16)
    painter.setBrush(QColor(15, 23, 42))
    painter.setPen(QPen(QColor(15, 23, 42), 1))
    painter.drawEllipse(124, 172, 8, 8)
    painter.drawRoundedRect(126, 179, 4, 10, 2, 2)

    painter.end()
    return QIcon(pixmap)


def deep_merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config():
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()
    try:
        return deep_merge(DEFAULT_CONFIG, json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    except Exception:
        return DEFAULT_CONFIG.copy()


def save_config_secure(data):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_config()
    secure_data = encrypt_config_secrets(data)

    if not secure_data.get("palo_api_key_dpapi") and existing.get("palo_api_key_dpapi"):
        secure_data["palo_api_key_dpapi"] = existing.get("palo_api_key_dpapi")
    if not secure_data.get("pfx_password_dpapi") and existing.get("pfx_password_dpapi"):
        secure_data["pfx_password_dpapi"] = existing.get("pfx_password_dpapi")
    if not secure_data.get("cloudflare_api_token_dpapi") and existing.get("cloudflare_api_token_dpapi"):
        secure_data["cloudflare_api_token_dpapi"] = existing.get("cloudflare_api_token_dpapi")

    secure_data.pop("palo_api_key", None)
    secure_data.pop("pfx_password", None)
    secure_data.pop("cloudflare_api_token", None)
    CONFIG_PATH.write_text(json.dumps(secure_data, indent=2), encoding="utf-8")


class CommandWorker(QThread):
    finished = Signal(str, int)

    def __init__(self, command_type, command):
        super().__init__()
        self.command_type = command_type
        self.command = command

    def run(self):
        try:
            if self.command_type == "agent":
                proc = subprocess.run(
                    [sys.executable, str(AGENT_PATH), self.command],
                    text=True,
                    capture_output=True,
                    timeout=900,
                )
            else:
                proc = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(INSTALLER_PATH),
                        "-Action",
                        self.command,
                    ],
                    text=True,
                    capture_output=True,
                    timeout=900,
                )
            output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            self.finished.emit(output.strip(), proc.returncode)
        except Exception as exc:
            self.finished.emit(str(exc), 1)


class Card(QFrame):
    def __init__(self, title, value="Unknown", hint=""):
        super().__init__()
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(8)
        self.title = QLabel(title)
        self.title.setObjectName("cardTitle")
        self.value = QLabel(value)
        self.value.setObjectName("cardValue")
        self.hint = QLabel(hint)
        self.hint.setObjectName("cardHint")
        layout.addWidget(self.title)
        layout.addWidget(self.value)
        layout.addWidget(self.hint)
        layout.addStretch()

    def set_value(self, value, tone="neutral"):
        self.value.setText(value)
        self.value.setProperty("tone", tone)
        self.value.style().unpolish(self.value)
        self.value.style().polish(self.value)


class FormPage(QWidget):
    def __init__(self, title, subtitle):
        super().__init__()
        self.form = QGridLayout()
        self.form.setHorizontalSpacing(14)
        self.form.setVerticalSpacing(12)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)
        header = QLabel(title)
        header.setObjectName("pageTitle")
        sub = QLabel(subtitle)
        sub.setObjectName("pageSubtitle")
        sub.setWordWrap(True)
        root.addWidget(header)
        root.addWidget(sub)
        root.addSpacing(12)
        root.addLayout(self.form)
        root.addStretch()
        self.row = 0

    def add_section(self, title, hint=""):
        label = QLabel(title)
        label.setObjectName("sectionTitle")
        self.form.addWidget(label, self.row, 0, 1, 3)
        self.row += 1
        if hint:
            sub = QLabel(hint)
            sub.setObjectName("sectionHint")
            sub.setWordWrap(True)
            self.form.addWidget(sub, self.row, 0, 1, 3)
            self.row += 1

    def add_line(self, label, value="", password=False, browse=None):
        lbl = QLabel(label)
        edit = QLineEdit()
        edit.setText(str(value or ""))
        if password:
            edit.setEchoMode(QLineEdit.Password)
        self.form.addWidget(lbl, self.row, 0)
        self.form.addWidget(edit, self.row, 1)
        if browse:
            btn = QPushButton("Browse")
            btn.setObjectName("secondaryButton")
            btn.clicked.connect(lambda: self.browse_into(edit, browse))
            self.form.addWidget(btn, self.row, 2)
        self.row += 1
        return edit

    def add_check(self, label, checked=False):
        chk = QCheckBox(label)
        chk.setChecked(bool(checked))
        self.form.addWidget(chk, self.row, 1, 1, 2)
        self.row += 1
        return chk

    def browse_into(self, edit, kind):
        if kind == "pfx":
            filt = "PFX/P12 files (*.pfx *.p12);;All files (*.*)"
        elif kind == "exe":
            filt = "Executable files (*.exe);;All files (*.*)"
        else:
            filt = "All files (*.*)"
        path, _ = QFileDialog.getOpenFileName(self, "Select file", "", filt)
        if path:
            edit.setText(path)


class MainWindow(QMainWindow):
    def __init__(self, app_icon=None):
        super().__init__()
        self.setWindowTitle("CertGuard-PA")
        if app_icon is not None:
            self.setWindowIcon(app_icon)
        self.resize(1280, 760)
        self.setMinimumSize(1060, 660)
        self.cfg = load_config()
        self.worker = None
        self.fields = {}
        self.checks = {}
        self.cards = {}
        self.nav_buttons = []
        self.build_ui()

    def build_ui(self):
        root = QWidget()
        main = QHBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(26, 28, 24, 24)
        sidebar_layout.setSpacing(10)

        brand = QLabel("CertGuard-PA")
        brand.setObjectName("brand")
        brand.setWordWrap(False)
        subtitle = QLabel("Palo Alto Certificate Automation")
        subtitle.setObjectName("brandSub")
        subtitle.setWordWrap(True)
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(22)

        nav_items = ["Dashboard", "Palo Alto", "Certificate", "Policy", "win-acme", "Service", "Operations"]
        for index, name in enumerate(nav_items):
            btn = QPushButton(name)
            btn.setObjectName("navButton")
            btn.setProperty("active", index == 0)
            btn.clicked.connect(lambda checked=False, row=index: self.switch_page(row))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        version = QLabel("v1 baseline")
        version.setObjectName("versionText")
        sidebar_layout.addWidget(version)

        self.stack = QStackedWidget()
        content = QFrame()
        content.setObjectName("content")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(34, 30, 34, 30)
        content_layout.addWidget(self.stack)

        main.addWidget(sidebar_frame, 0)
        main.addWidget(content, 1)
        self.setCentralWidget(root)

        self.build_dashboard()
        self.build_palo_page()
        self.build_cert_page()
        self.build_policy_page()
        self.build_wacs_page()
        self.build_service_page()
        self.build_operations_page()
        self.switch_page(0)

    def build_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        title = QLabel("Dashboard")
        title.setObjectName("pageTitle")
        sub = QLabel("Live operational view for certificate automation.")
        sub.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)
        layout.addSpacing(20)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        self.cards["health"] = Card("Health", "Unknown", "Run health check")
        self.cards["policy"] = Card("Policy", "Unknown", "Last policy decision")
        self.cards["deploy"] = Card("Deploy", "Unknown", "Last deployment")
        self.cards["service"] = Card("Service", "Unknown", "Windows service status")
        grid.addWidget(self.cards["health"], 0, 0)
        grid.addWidget(self.cards["policy"], 0, 1)
        grid.addWidget(self.cards["deploy"], 1, 0)
        grid.addWidget(self.cards["service"], 1, 1)
        layout.addLayout(grid)
        layout.addSpacing(18)

        actions = QHBoxLayout()
        actions.setSpacing(12)
        self.add_action_button(actions, "Health Check", "agent", "health", primary=False)
        self.add_action_button(actions, "Deploy Certificate", "agent", "deploy", primary=True)
        self.add_action_button(actions, "Install Service", "installer", "InstallSilent", primary=False)
        layout.addLayout(actions)
        layout.addStretch()
        self.stack.addWidget(page)

    def build_palo_page(self):
        p = FormPage("Palo Alto", "Firewall endpoint and API authentication.")
        self.fields["firewall_host"] = p.add_line("Palo Alto Host", self.cfg.get("firewall_host", ""))
        self.fields["palo_api_key"] = p.add_line("API Key", "", password=True)
        self.checks["skip_tls_validation"] = p.add_check("Skip TLS validation", self.cfg.get("skip_tls_validation", True))
        self.stack.addWidget(p)

    def build_cert_page(self):
        p = FormPage("Certificate", "Local PFX source and expected certificate identity.")
        self.fields["certificate_name"] = p.add_line("Certificate Name", self.cfg.get("certificate_name", ""))
        self.fields["expected_domain"] = p.add_line("Expected FQDN", self.cfg.get("expected_domain", ""))
        self.fields["pfx_path"] = p.add_line("PFX Path", self.cfg.get("pfx_path", ""), browse="pfx")
        self.fields["pfx_password"] = p.add_line("PFX Password", "", password=True)
        self.stack.addWidget(p)

    def build_policy_page(self):
        p = FormPage("Policy", "Define safe automation conditions.")
        policy = self.cfg.get("policy", {})
        self.checks["import_if_pa_cert_missing"] = p.add_check("Import if certificate does not exist on Palo Alto", policy.get("import_if_pa_cert_missing", True))
        self.checks["block_on_domain_mismatch"] = p.add_check("Block on expected-domain mismatch", policy.get("block_on_domain_mismatch", True))
        self.checks["auto_import_only_if_expiring"] = p.add_check("Import only if Palo Alto certificate is expiring", policy.get("auto_import_only_if_expiring", True))
        self.checks["require_local_newer_or_different"] = p.add_check("Require local certificate to be newer or different", policy.get("require_local_newer_or_different", True))
        self.checks["use_win_acme_fallback"] = p.add_check("Use win-acme fallback if local certificate is not newer", policy.get("use_win_acme_fallback", True))
        self.checks["block_private_key_export_on_import"] = p.add_check("Block Private Key Export on Palo Alto import", policy.get("block_private_key_export_on_import", True))
        self.fields["auto_import_expiry_threshold_days"] = p.add_line("Expiry Threshold Days", policy.get("auto_import_expiry_threshold_days", 7))
        self.stack.addWidget(p)

    def build_wacs_page(self):
        p = FormPage("win-acme", "Optional renewal fallback before deployment.")
        wacs = self.cfg.get("win_acme", {})
        self.fields["wacs_path"] = p.add_line("Managed wacs.exe Path", wacs.get("path", r"C:\ProgramData\CertGuard-PA\win-acme\wacs.exe"))
        self.fields["wacs_base_uri"] = p.add_line("ACME Base URI", wacs.get("base_uri", "https://acme-v02.api.letsencrypt.org/"))
        self.fields["wacs_timeout"] = p.add_line("Renew Timeout Seconds", wacs.get("renew_timeout_seconds", 900))
        p.add_section("Cloudflare DNS-01", "CertGuard owns the DNS credential and provisions win-acme unattended. The token is stored with machine-scope DPAPI.")
        self.fields["cloudflare_zone"] = p.add_line("Cloudflare Zone", self.cfg.get("cloudflare_zone", ""))
        self.fields["cloudflare_api_token"] = p.add_line("Cloudflare API Token", "", password=True)
        self.stack.addWidget(p)

    def build_service_page(self):
        p = FormPage("Service", "Windows service schedule plus Palo Alto deployment behavior.")
        deploy = self.cfg.get("deploy", {})
        service = self.cfg.get("service", {})
        p.add_section("Palo Alto Deployment Options", "These options affect Palo Alto certificate import behavior, not the Windows service itself.")
        self.checks["commit_after_import"] = p.add_check("Palo Alto: Commit after certificate import", self.cfg.get("commit_after_import", False))
        self.checks["verify_after_import"] = p.add_check("Palo Alto: Verify certificate after import", deploy.get("verify_after_import", True))
        self.fields["retry_count"] = p.add_line("Palo Alto Import Retry Count", deploy.get("retry_count", 3))
        self.fields["retry_delay_seconds"] = p.add_line("Palo Alto Import Retry Delay Seconds", deploy.get("retry_delay_seconds", 5))
        p.add_section("Windows Service Schedule", "These options control the local CertGuard-PA background service loop.")
        self.fields["interval_seconds"] = p.add_line("Service Interval Seconds", service.get("interval_seconds", 3600))
        self.stack.addWidget(p)

    def build_operations_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        title = QLabel("Operations")
        title.setObjectName("pageTitle")
        sub = QLabel("Run diagnostics, deploy certificate, and manage the service.")
        sub.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)
        layout.addSpacing(14)
        row1 = QHBoxLayout()
        row1.setSpacing(10)
        self.add_action_button(row1, "Save", "local", "save")
        self.add_action_button(row1, "Health", "agent", "health")
        self.add_action_button(row1, "Test API", "agent", "test-pa")
        self.add_action_button(row1, "Test WACS", "agent", "test-wacs")
        layout.addLayout(row1)
        row2 = QHBoxLayout()
        row2.setSpacing(10)
        self.add_action_button(row2, "Policy", "agent", "policy")
        self.add_action_button(row2, "Compare", "agent", "compare")
        self.add_action_button(row2, "Deploy", "agent", "deploy", primary=True)
        self.add_action_button(row2, "Install Service", "installer", "InstallSilent")
        layout.addLayout(row2)
        row3 = QHBoxLayout()
        row3.setSpacing(10)
        self.add_action_button(row3, "Test Cloudflare", "agent", "test-cloudflare")
        self.add_action_button(row3, "Create / Repair Renewal", "agent", "provision-wacs", primary=True)
        self.add_action_button(row3, "Renew Now", "agent", "renew-wacs")
        layout.addLayout(row3)
        self.log_box = QTextEdit()
        self.log_box.setObjectName("logBox")
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box, 1)
        self.stack.addWidget(page)

    def add_action_button(self, layout, text, command_type, command, primary=False):
        btn = QPushButton(text)
        btn.setObjectName("primaryButton" if primary else "secondaryButton")
        btn.clicked.connect(lambda: self.run_command(command_type, command))
        layout.addWidget(btn)
        return btn

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for row, button in enumerate(self.nav_buttons):
            button.setProperty("active", row == index)
            button.style().unpolish(button)
            button.style().polish(button)

    def append_log(self, text):
        if not hasattr(self, "log_box"):
            return
        self.log_box.append(text)

    def collect_config(self):
        return {
            "firewall_host": self.fields["firewall_host"].text().strip(),
            "palo_api_key": self.fields["palo_api_key"].text().strip(),
            "skip_tls_validation": self.checks["skip_tls_validation"].isChecked(),
            "certificate_name": self.fields["certificate_name"].text().strip(),
            "expected_domain": self.fields["expected_domain"].text().strip(),
            "pfx_path": self.fields["pfx_path"].text().strip(),
            "pfx_password": self.fields["pfx_password"].text(),
            "cloudflare_zone": self.fields["cloudflare_zone"].text().strip(),
            "cloudflare_api_token": self.fields["cloudflare_api_token"].text().strip(),
            "commit_after_import": self.checks["commit_after_import"].isChecked(),
            "policy": {
                "import_if_pa_cert_missing": self.checks["import_if_pa_cert_missing"].isChecked(),
                "block_on_domain_mismatch": self.checks["block_on_domain_mismatch"].isChecked(),
                "auto_import_only_if_expiring": self.checks["auto_import_only_if_expiring"].isChecked(),
                "auto_import_expiry_threshold_days": int(self.fields["auto_import_expiry_threshold_days"].text()),
                "require_local_newer_or_different": self.checks["require_local_newer_or_different"].isChecked(),
                "use_win_acme_fallback": self.checks["use_win_acme_fallback"].isChecked(),
                "block_private_key_export_on_import": self.checks["block_private_key_export_on_import"].isChecked(),
            },
            "deploy": {
                "retry_count": int(self.fields["retry_count"].text()),
                "retry_delay_seconds": int(self.fields["retry_delay_seconds"].text()),
                "verify_after_import": self.checks["verify_after_import"].isChecked(),
            },
            "win_acme": {
                "path": self.fields["wacs_path"].text().strip(),
                "base_uri": self.fields["wacs_base_uri"].text().strip(),
                "renew_timeout_seconds": int(self.fields["wacs_timeout"].text()),
            },
            "service": {
                "interval_seconds": int(self.fields["interval_seconds"].text()),
            },
        }

    def save_config(self):
        try:
            save_config_secure(self.collect_config())
            self.append_log(f"Configuration saved securely: {CONFIG_PATH}")
            return True
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return False

    def run_command(self, command_type, command):
        if command_type == "local" and command == "save":
            self.save_config()
            return
        if not self.save_config():
            return
        self.append_log(f"> {command_type}: {command}")
        self.worker = CommandWorker(command_type, command)
        self.worker.finished.connect(lambda output, code: self.command_finished(command, output, code))
        self.worker.start()

    def command_finished(self, command, output, code):
        if output:
            self.append_log(output)
        self.append_log(f"Exit code: {code}")
        if command == "health":
            if code == 0 and '"ok": true' in output.lower():
                self.cards["health"].set_value("Healthy", "ok")
            else:
                self.cards["health"].set_value("Needs attention", "bad")
        if command == "policy":
            self.cards["policy"].set_value("Updated", "neutral")
        if command == "deploy":
            self.cards["deploy"].set_value("Completed" if code == 0 else "Failed", "ok" if code == 0 else "bad")
        if command == "InstallSilent":
            self.cards["service"].set_value("Installed", "ok" if code == 0 else "bad")


def main():
    app = QApplication(sys.argv)
    app_icon = build_app_icon()
    app.setWindowIcon(app_icon)
    app.setStyleSheet(STYLE)
    window = MainWindow(app_icon=app_icon)
    window.show()
    sys.exit(app.exec())


STYLE = """
QWidget {
    background: #0f172a;
    color: #e5e7eb;
    font-family: Segoe UI;
    font-size: 10pt;
}
#sidebar {
    background: #111827;
    min-width: 300px;
    max-width: 300px;
    border-right: 1px solid #1f2937;
}
#brand {
    font-size: 21pt;
    font-weight: 800;
    color: #f9fafb;
    padding: 0px;
    margin: 0px;
}
#brandSub {
    color: #94a3b8;
    font-size: 10.5pt;
    padding: 0px;
    margin: 0px;
}
#versionText {
    color: #64748b;
    font-size: 9pt;
    padding: 8px 2px 0px 2px;
}
#navButton {
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 14px;
    padding: 13px 16px;
    color: #cbd5e1;
    font-weight: 600;
}
#navButton:hover {
    background: #1e293b;
    color: #f8fafc;
}
#navButton[active="true"] {
    background: #2563eb;
    border: 1px solid #3b82f6;
    color: white;
}
#content {
    background: #0f172a;
}
#pageTitle {
    font-size: 25pt;
    font-weight: 800;
    color: #f8fafc;
}
#pageSubtitle {
    color: #94a3b8;
    font-size: 11pt;
}
#sectionTitle {
    color: #e2e8f0;
    font-size: 12pt;
    font-weight: 800;
    padding-top: 10px;
}
#sectionHint {
    color: #94a3b8;
    font-size: 9.5pt;
    padding-bottom: 8px;
}
#card {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 20px;
    min-height: 145px;
}
#cardTitle {
    color: #94a3b8;
    font-size: 10pt;
    font-weight: 600;
}
#cardValue {
    color: #f8fafc;
    font-size: 21pt;
    font-weight: 800;
}
#cardValue[tone="ok"] { color: #22c55e; }
#cardValue[tone="bad"] { color: #ef4444; }
#cardHint {
    color: #64748b;
}
QLineEdit, QTextEdit {
    background: #111827;
    border: 1px solid #334155;
    border-radius: 11px;
    padding: 9px;
    color: #f8fafc;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #3b82f6;
}
QCheckBox {
    padding: 5px;
}
QPushButton {
    border: 1px solid #334155;
    border-radius: 13px;
    padding: 11px 15px;
    background: #1f2937;
    color: #e5e7eb;
    font-weight: 600;
}
QPushButton:hover {
    background: #334155;
}
#primaryButton {
    background: #2563eb;
    color: white;
    font-weight: 800;
    border: 1px solid #3b82f6;
}
#primaryButton:hover {
    background: #1d4ed8;
}
#secondaryButton {
    background: #1f2937;
}
#logBox {
    font-family: Consolas;
    font-size: 9pt;
}
"""


if __name__ == "__main__":
    main()
