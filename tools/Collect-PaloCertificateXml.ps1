# ASCII only
# Collects the Palo Alto certificate API XML response without exposing the API key.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$AgentPath = Join-Path $RepoRoot "src\certguard_agent.py"
$OutputDir = "C:\ProgramData\CertGuard-PA\debug"
$OutputPath = Join-Path $OutputDir "pa-certificate-info.xml"
$SnippetPath = Join-Path $OutputDir "pa-certificate-match.txt"

if (-not (Test-Path $AgentPath)) {
    throw "Agent source not found: $AgentPath"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$PythonScript = @'
import importlib.util
import re
from pathlib import Path

agent_path = Path(r"__AGENT_PATH__")
output_path = Path(r"__OUTPUT_PATH__")
snippet_path = Path(r"__SNIPPET_PATH__")

spec = importlib.util.spec_from_file_location("certguard_agent_diag", str(agent_path))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

config = agent.load_config()
cert_name = (config.get("certificate_name") or "").strip()
root, xml_text = agent.palo_op(
    config,
    "<show><sslmgr-store><config-certificate-info></config-certificate-info></sslmgr-store></show>",
)

output_path.write_text(xml_text, encoding="utf-8")

lower_xml = xml_text.lower()
lower_name = cert_name.lower()
idx = lower_xml.find(lower_name) if lower_name else -1
if idx >= 0:
    start = max(0, idx - 2500)
    end = min(len(xml_text), idx + 5000)
    snippet = xml_text[start:end]
else:
    snippet = "Certificate name was not found in the raw XML response."

snippet = re.sub(r"([?&]key=)[^&\"'<>\s]+", r"\1[REDACTED]", snippet, flags=re.IGNORECASE)
snippet_path.write_text(snippet, encoding="utf-8")

print(f"Certificate name: {cert_name}")
print(f"Raw XML saved: {output_path}")
print(f"Matched snippet saved: {snippet_path}")
print("API key is not written to either file.")
'@

$PythonScript = $PythonScript.Replace("__AGENT_PATH__", $AgentPath.Replace("\", "\\"))
$PythonScript = $PythonScript.Replace("__OUTPUT_PATH__", $OutputPath.Replace("\", "\\"))
$PythonScript = $PythonScript.Replace("__SNIPPET_PATH__", $SnippetPath.Replace("\", "\\"))

$TempScript = Join-Path $env:TEMP "certguard_pa_collect_xml.py"
Set-Content -Path $TempScript -Value $PythonScript -Encoding UTF8

try {
    python $TempScript
} finally {
    Remove-Item $TempScript -Force -ErrorAction SilentlyContinue
}

Write-Host "[INFO] Diagnostic collection completed."
Write-Host "[INFO] Send only this smaller file for analysis: $SnippetPath"
