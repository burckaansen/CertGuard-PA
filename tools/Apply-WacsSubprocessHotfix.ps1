# ASCII only
# Applies the WACS subprocess/output hotfix to the local source tree.
# This script is intentionally idempotent and safe to run more than once.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$AgentPath = Join-Path $RepoRoot "src\certguard_agent.py"
$GuiPath = Join-Path $RepoRoot "src\certguard_gui_qt.py"

if (-not (Test-Path $AgentPath)) {
    throw "Agent source not found: $AgentPath"
}
if (-not (Test-Path $GuiPath)) {
    throw "Qt GUI source not found: $GuiPath"
}

Write-Host "[INFO] Applying WACS subprocess hotfix..."

$agent = Get-Content $AgentPath -Raw

if ($agent -notmatch "def decode_process_output\(") {
    $helpers = @'

def decode_process_output(data):
    if not data:
        return ""
    for encoding in ["utf-8", "cp850", "cp1252"]:
        try:
            return data.decode(encoding, errors="replace")
        except Exception:
            pass
    return data.decode("utf-8", errors="replace")


def run_process_capture(args, timeout):
    proc = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    return proc.returncode, decode_process_output(proc.stdout)

'@
    $agent = $agent -replace "`r?`ndef run_win_acme_renew\(\):", "$helpers`r`ndef run_win_acme_renew():"
}

$oldRenew = @'
    proc = subprocess.run([wacs_path, "--renew", "--baseuri", base_uri], text=True, capture_output=True, timeout=timeout)
    output = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-6000:]
'@
$newRenew = @'
    returncode, output = run_process_capture([wacs_path, "--renew", "--baseuri", base_uri], timeout)
    output = output[-6000:]
'@
$agent = $agent.Replace($oldRenew, $newRenew)
$agent = $agent.Replace('state["last_wacs_renew_returncode"] = proc.returncode', 'state["last_wacs_renew_returncode"] = returncode')
$agent = $agent.Replace('if proc.returncode != 0:', 'if returncode != 0:')
$agent = $agent.Replace('raise CertGuardError(f"win-acme renew failed with code {proc.returncode}")', 'raise CertGuardError(f"win-acme renew failed with code {returncode}")')
$agent = $agent.Replace('return {"renewed": True, "returncode": proc.returncode}', 'return {"renewed": True, "returncode": returncode}')

$oldTest = @'
    proc = subprocess.run([wacs_path, "--verbose"], text=True, capture_output=True, timeout=90)
    output = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-4000:]
    result = {"exists": True, "returncode": proc.returncode, "output_tail": output}
'@
$newTest = @'
    returncode, output = run_process_capture([wacs_path, "--verbose"], 30)
    output = output[-4000:]
    result = {"exists": True, "returncode": returncode, "output_tail": output}
'@
$agent = $agent.Replace($oldTest, $newTest)
$agent = $agent.Replace('log(f"win-acme test completed returncode={proc.returncode}", "INFO", 383)', 'log(f"win-acme test completed returncode={returncode}", "INFO", 383)')

Set-Content -Path $AgentPath -Value $agent -Encoding UTF8

Write-Host "[INFO] Applying Qt worker close hotfix..."

$gui = Get-Content $GuiPath -Raw

if ($gui -notmatch "def closeEvent\(self, event\):") {
    $closeEvent = @'

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.append_log("Stopping active command worker before closing...")
            self.worker.terminate()
            self.worker.wait(5000)
        event.accept()

'@
    $gui = $gui -replace "`r?`ndef main\(\):", "$closeEvent`r`ndef main():"
}

$gui = $gui.Replace('if command == "InstallSilent":
            self.cards["service"].set_value("Installed", "ok" if code == 0 else "bad")', 'if command == "InstallSilent":
            self.cards["service"].set_value("Installed", "ok" if code == 0 else "bad")
        self.worker = None')

Set-Content -Path $GuiPath -Value $gui -Encoding UTF8

Write-Host "[INFO] WACS subprocess hotfix applied."
Write-Host "[INFO] Next: .\tools\Build-StandaloneRelease.ps1"
