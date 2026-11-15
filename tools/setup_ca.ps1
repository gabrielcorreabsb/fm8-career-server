<# setup_ca.ps1 — ELEVADO (1 UAC): hosts entry + CA no trust store (LocalMachine\Root)
   Uso: .\setup_ca.ps1   (rode via Start-Process -Verb RunAs)
#>
$ErrorActionPreference = 'Stop'
$repo = 'E:\Projetos\fm8-lsp-server'
$host_entry = '127.0.0.1 gameservices.fm.forzamotorsport.net'
$hosts = 'C:\Windows\System32\drivers\etc\hosts'

# --- hosts ---
$cur = Get-Content $hosts -ErrorAction SilentlyContinue
if (-not ($cur | Where-Object { $_ -match 'gameservices\.fm\.forzamotorsport\.net' -and $_ -notmatch '^\s*#' })) {
  Add-Content -Path $hosts -Value "`r`n# FM8 LSP local server (rota A - lab)`r`n$host_entry" -Encoding ascii
  Write-Host 'HOSTS: entry added'
} else {
  Write-Host 'HOSTS: entry already present'
}

# --- trust store ---
$ca = Import-Certificate -FilePath (Join-Path $repo 'certs\ca.pem') -CertStoreLocation Cert:\LocalMachine\Root
Write-Host ("TRUST: imported CA {0}" -f $ca.Thumbprint)
