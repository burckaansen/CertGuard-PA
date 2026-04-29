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

$testFunction = @'
def test_win_acme():
    config = load_config()
    wacs_path = config.get("win_acme", {}).get("path", "")
    if not wacs_path:
        raise CertGuardError("win-acme path is not configured")
    path_obj = Path(wacs_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"wacs.exe not found: {wacs_path}")
    result = {
        "exists": True,
        "path": str(path_obj),
        "file_name": path_obj.name,
        "size_bytes": path_obj.stat().st_size,
        "note": "Path check only. Use renew-wacs for actual win-acme renewal."
    }
    state = load_state()
    state["last_wacs_test"] = result
    state["last_wacs_test_time"] = utc_now_text()
    save_state(state)
    log("win-acme path test completed", "INFO", 383)
    return result


'@
$agent = [regex]::Replace($agent, '(?s)def test_win_acme\(\):.*?(?=\ndef evaluate_policy\()', $testFunction, 1)

$agent = $agent.Replace(
'    log(f"Compare completed: remote_found={result[''remote_found'']} same={result[''same_fingerprint'']} local_newer={result[''local_newer'']} domain_match={result[''domain_match'']}", "INFO", 340)',
'    log(f"Compare completed: remote_found={result[''remote_found'']} same={result[''same_fingerprint'']} local_newer={result[''local_newer'']} domain_match={result[''domain_match'']}", "INFO", 340)
    log(f"Certificate comparison summary: local_days_left={result.get(''local_days_left'')} remote_days_left={result.get(''remote_days_left'')} remote_found={result.get(''remote_found'')} same_fingerprint={result.get(''same_fingerprint'')}", "INFO", 341)'
)

$agent = $agent.Replace(
'    log(f"Policy decision: action={decision[''action'']} reason={decision[''reason'']}", level, 350)
    return result',
'    log(f"Policy decision: action={decision[''action'']} reason={decision[''reason'']}", level, 350)
    if decision.get("should_import"):
        log(f"Certificate import required: {decision.get(''reason'', ''policy matched'')}", "WARN", 353)
    else:
        log(f"No certificate change required: {decision.get(''reason'', ''policy skipped'')}", "INFO", 351)
    return result'
)

$agent = $agent.Replace(
'        log(f"Policy tick completed: action={action}", "INFO", 302)
        if result["decision"].get("should_import"):
            deploy_certificate(force=False)',
'        log(f"Policy tick completed: action={action}", "INFO", 302)
        if result["decision"].get("should_import"):
            log(f"Certificate import required by scheduled service tick: {result[''decision''].get(''reason'', ''policy matched'')}", "WARN", 354)
            deploy_certificate(force=False)'
)

if ($agent -match 'text=True, capture_output=True') { throw "Patch failed: unsafe subprocess capture is still present." }
if ($agent -notmatch "def run_process_capture\(") { throw "Patch failed: helper function missing." }
if ($agent -match 'run_process_capture\(\[wacs_path, "--verbose"\]') { throw "Patch failed: TestWacs still executes wacs.exe --verbose." }
if ($agent -notmatch "No certificate change required") { throw "Patch failed: explicit no-change event log missing." }
if ($agent -notmatch "Certificate import required") { throw "Patch failed: explicit import-required event log missing." }

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
