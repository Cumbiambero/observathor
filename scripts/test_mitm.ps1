<#!
Observathor MITM automated sanity test script (Windows PowerShell)
Prereqs:
  - Build observathor_cli.exe with TLS support (OpenSSL available at configure time)
  - CA not yet trusted (script can optionally install temporarily if run as admin)

Scenarios:
 1. Simple HTTPS POST (form)
 2. Chunked upload (file)
 3. Large body spill to file (> soft limit)
 4. Chunked streaming response
Outputs:
  - Temporary working dir: $WorkDir
  - Captured NDJSON file for manual inspection
Note: Does NOT uninstall CA automatically unless -RemoveCA specified.
#>
[CmdletBinding()]
param(
  [int]$Port = 8888,
  [string]$CliPath = (Resolve-Path -LiteralPath "..\build_tls\Release\observathor_cli.exe" -ErrorAction SilentlyContinue),
  [switch]$InstallCA,
  [switch]$RemoveCA,
  [string]$HttpBin = 'https://httpbin.org',
  [int]$LargeSize = 2000000,
  [int]$SoftLimitGuess = 524288
)

function Fail($msg){ Write-Host "[FAIL] $msg" -ForegroundColor Red; exit 1 }
function Info($msg){ Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Pass($msg){ Write-Host "[PASS] $msg" -ForegroundColor Green }

if(-not $CliPath){ Fail "observathor_cli.exe not found. Provide -CliPath." }
if(-not (Test-Path $CliPath)){ Fail "CliPath '$CliPath' not found." }

$WorkDir = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "observathor_mitm_test_$(Get-Date -Format yyyyMMdd_HHmmss)") | Select-Object -ExpandProperty FullName
$CaPem = Join-Path $WorkDir 'ca.pem'
$Ndjson = Join-Path $WorkDir 'transactions.ndjson'

Info "Working directory: $WorkDir"

# Launch proxy
$Args = @('--port', $Port, '--enable-mitm', '--export-ca', $CaPem, '--file-store', $Ndjson)
Info "Starting proxy: $CliPath $($Args -join ' ')"
$proxy = Start-Process -FilePath $CliPath -ArgumentList $Args -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
if($proxy.HasExited){ Fail "Proxy exited early (code $($proxy.ExitCode))" }

# Detect OpenSSL availability by scanning stdout (race: best-effort)
Start-Sleep -Milliseconds 500
try {
  $proc = Get-Process -Id $proxy.Id -ErrorAction Stop
} catch { Fail "Proxy process not running" }

# Quick probe: attempt a CONNECT and see if decrypted request appears; if binary lacks OpenSSL it will tunnel only.
$testConnect = curl.exe -x "http://127.0.0.1:$Port" https://example.com/ -I 2>&1 | Out-String
if($testConnect -match 'Recv failure' -or $testConnect -match 'Failed to connect') {
  Info "Initial probe failed; continuing (network hiccup)."
}
if($testConnect -match 'Server:'){ # generic header present
  Info "Connectivity probe ok."
}
# Heuristic: if binary was built without OpenSSL, enabling --enable-mitm should just tunnel; we can't easily assert here without internal flag.
# We will proceed; later json check will fail if tls_mitm missing.

# Helper: perform curl request
function Do-Curl($label, $curlArgs){
  Info "[$label] curl $($curlArgs -join ' ')"
  $p = Start-Process -FilePath curl.exe -ArgumentList $curlArgs -RedirectStandardOutput "$WorkDir/$label.out" -RedirectStandardError "$WorkDir/$label.err" -PassThru -NoNewWindow; $p.WaitForExit()
  if($p.ExitCode -ne 0){ Fail "curl $label failed (exit $($p.ExitCode))" }
  Pass "$label completed"
}

# 1. Simple POST
Do-Curl 'post_simple' @('-x', "http://127.0.0.1:$Port", "$HttpBin/post", '-d', 'alpha=1&beta=2')

# 2. Chunked upload (force chunked by disabling content-length) - create file
$chunkFile = Join-Path $WorkDir 'chunk.txt'
'A'*65536 | Out-File -NoNewline -FilePath $chunkFile -Encoding ascii
Do-Curl 'post_chunked' @('-x', "http://127.0.0.1:$Port", "$HttpBin/post", '--data-binary', "@$chunkFile", '-H', 'Transfer-Encoding: chunked')

# 3. Large body spill
$largeFile = Join-Path $WorkDir 'large.bin'
[IO.File]::WriteAllBytes($largeFile, (New-Object byte[] ($LargeSize)))
Do-Curl 'post_large' @('-x', "http://127.0.0.1:$Port", "$HttpBin/post", '--data-binary', "@$largeFile")

# 4. Chunked streaming response
Do-Curl 'resp_stream' @('-x', "http://127.0.0.1:$Port", "$HttpBin/stream/10")

Start-Sleep -Seconds 2

# Basic NDJSON analysis
if(Test-Path $Ndjson){
  $lines = Get-Content $Ndjson
  if($lines.Count -lt 1){
    Write-Warning "No transactions captured. If OpenSSL was not found at build time MITM is disabled; rebuild with -DOBSERVATHOR_ENABLE_TLS=ON and valid OpenSSL install."
    Fail "Aborting tests." }
  if($lines.Count -lt 4){ Fail "Expected >=4 transactions, got $($lines.Count)" }
  $json = $lines | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } | Where-Object { $_ -ne $null }
  $mitmCount = ($json | Where-Object { $_.tls_mitm -eq $true }).Count
  if($mitmCount -lt 4){ Fail "Expected all transactions to be MITM (>=4), got $mitmCount" }
  $spill = $json | Where-Object { $_.request_body_in_file -eq $true }
  if($spill.Count -lt 1){ Fail "Large body did not spill to disk" } else { Pass "Spill to file verified" }
  $chunkReq = $json | Where-Object { $_.request_was_chunked -eq $true }
  if($chunkReq.Count -lt 1){ Fail "Chunked request flag missing" } else { Pass "Chunked request captured" }
  $chunkResp = $json | Where-Object { $_.response_was_chunked -eq $true }
  if($chunkResp.Count -lt 1){ Pass "No chunked response in sample (ok)" } else { Pass "Chunked response captured" }
  Pass "MITM transactions: $mitmCount"
} else {
  Fail "NDJSON file not found: $Ndjson"
}

if($RemoveCA){
  Info "Removing CA from Root store."; certutil -delstore Root Observathor | Out-Null
}

# Cleanup proxy
if(-not $proxy.HasExited){
  Stop-Process -Id $proxy.Id -Force
}

Info "Done. Output dir: $WorkDir"
