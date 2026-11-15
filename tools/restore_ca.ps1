$ErrorActionPreference = 'Continue'
$log = 'E:\Projetos\fm8-lsp-server\restore_ca.log'
function log($m) { $m | Out-File $log -Append -Encoding utf8 }
Remove-Item $log -ErrorAction SilentlyContinue

Copy-Item C:\Windows\System32\drivers\etc\hosts E:\Projetos\fm8-lsp-server\hosts.before_restore.txt -Force

try {
  Copy-Item E:\Projetos\fm8-lsp-server\hosts.backup_20261109.txt C:\Windows\System32\drivers\etc\hosts -Force
  log 'HOSTS: restored from backup_20261109'
} catch {
  log ("HOSTS ERR: {0}" -f $_.Exception.Message)
}

try {
  $t = '3E44359E1CE489ED95792A584DB67659A7448B7B'
  $c = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $t }
  if ($c) {
    Remove-Item -Path ("Cert:\LocalMachine\Root\{0}" -f $t) -Force
    log ('TRUST: CA FM8 removida ({0})' -f $t)
  } else {
    log 'TRUST: CA FM8 nao encontrada (ja estava limpa)'
  }
} catch {
  log ("TRUST ERR: {0}" -f $_.Exception.Message)
}

$has = Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern 'gameservices' -ErrorAction SilentlyContinue
if ($has) {
  $lines = $has | ForEach-Object { $_.Line }
  log ('HOSTS residual: {0}' -f ($lines -join ' | '))
} else {
  log 'HOSTS: sem entrada gameservices'
}
$still = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq '3E44359E1CE489ED95792A584DB67659A7448B7B' }
if ($still) { log 'TRUST final: AINDA PRESENTE' } else { log 'TRUST final: limpo' }
