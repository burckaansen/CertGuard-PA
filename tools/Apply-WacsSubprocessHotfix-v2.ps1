# ASCII only
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$AgentPath = Join-Path $RepoRoot "src\certguard_agent.py"
$GuiPath = Join-Path $RepoRoot "src\certguard_gui_qt.py"

if (-not (Test-Path $AgentPath)) { throw "Agent source not found: $AgentPath" }
if (-not (Test-Path $GuiPath)) { throw "GUI source not found: $GuiPath" }

Write-Host "[INFO] Patching source agent: $AgentPath"
$agent = Get-Content -Path $AgentPath -Raw

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
    $agent = [regex]::Replace($agent, "\r?\ndef run_win_acme_renew\(\):", "$helpers`r`ndef run_win_acme_renew():", 1)
}

$agent = [regex]::Replace(
    $agent,
    'proc = subprocess\.run\(\[wacs_path, "--renew", "--baseuri", base_uri\], text=True, capture_output=True, timeout=timeout\)\s*\r?\n\s*output = \(\(proc\.stdout or ""\) \+ "\\n" \+ \(proc\.stderr or ""\)\)\[-6000:\]',
    'returncode, output = run_process_capture([wacs_path, "--renew", "--baseuri", base_uri], timeout)' + "`r`n" + '    output = output[-6000:]',
    1
)

$agent = $agent.Replace('state["last_wacs_renew_returncode"] = proc.returncode', 'state["last_wacs_renew_returncode"] = returncode')
$agent = $agent.Replace('if proc.returncode != 0:', 'if returncode != 0:')
$agent = $agent.Replace('raise CertGuardError(f"win-acme renew failed with code {proc.returncode}")', 'raise CertGuardError(f"win-acme renew failed with code {returncode}")')
$agent = $agent.Replace('return {"renewed": True, "returncode": proc.returncode}', 'return {"renewed": True, "returncode": returncode}')

$agent = [regex]::Replace(
    $agent,
    'proc = subprocess\.run\(\[wacs_path, "--verbose"\], text=True, capture_output=True, timeout=90\)\s*\r?\n\s*output = \(\(proc\.stdout or ""\) \+ "\\n" \+ \(proc\.stderr or ""\)\)\[-4000:\]\s*\r?\n\s*result = \{"exists": True, "returncode": proc\.returncode, "output_tail": output\}',
    'returncode, output = run_process_capture([wacs_path, "--verbose"], 30)' + "`r`n" + '    output = output[-4000:]' + "`r`n" + '    result = {"exists": True, "returncode": returncode, "output_tail": output}',
    1
)

$agent = $agent.Replace('log(f"win-acme test completed returncode={proc.returncode}", "INFO", 383)', 'log(f"win-acme test completed returncode={returncode}", "INFO", 383)')

if ($agent -match 'text=True, capture_output=True') {
    throw "Patch failed: unsafe subprocess capture is still present."
}
if ($agent -notmatch "def run_process_capture\(") {
    throw "Patch failed: helper function missing."
}

Set-Content -Path $AgentPath -Value $agent -Encoding UTF8
Write-Host "[INFO] Agent patch applied and validated."

$gui = Get-Content -Path $GuiPath -Raw
if ($gui -notmatch "def closeEvent\(self, event\):") {
$closeEvent = @'

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.append_log("Stopping active command worker before closing...")
            self.worker.terminate()
            self.worker.wait(5000)
        event.accept()

'@
    $gui = [regex]::Replace($gui, "\r?\ndef main\(\):", "$closeEvent`r`ndef main():", 1)
    Set-Content -Path $GuiPath -Value $gui -Encoding UTF8
    Write-Host "[INFO] GUI closeEvent patch applied."
}

Write-Host "[INFO] Hotfix v2 completed. Now run: .\tools\Build-StandaloneRelease.ps1"
