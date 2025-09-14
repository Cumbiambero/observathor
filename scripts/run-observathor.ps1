param(
    [string]$BuildConfig = "Debug",
    [switch]$Cli,
    [string]$ListenHost = "127.0.0.1",
    [int]$ListenPort = 8080,
    [switch]$Mitm,
    [string]$Allow = "",
    [string]$Deny = "",
    [switch]$Help
)

if($Help) {
    Write-Host "Observathor Run Script"
    Write-Host "Usage: .\run-observathor.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -BuildConfig <Debug|Release>   Build configuration (default: Debug)"
    Write-Host "  -Cli                          Run CLI version instead of GUI"
    Write-Host "  -ListenHost <host>            Proxy listen host (default: 127.0.0.1)"
    Write-Host "  -ListenPort <port>            Proxy listen port (default: 8080)"
    Write-Host "  -Mitm                         Enable MITM interception"
    Write-Host "  -Allow <pattern>              MITM allow pattern (e.g. '*.example.com')"
    Write-Host "  -Deny <pattern>               MITM deny pattern"
    Write-Host "  -Help                         Show this help"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\run-observathor.ps1                                  # GUI tunneling-only on 127.0.0.1:8080"
    Write-Host "  .\run-observathor.ps1 -Cli -ListenPort 3128           # CLI tunneling-only on port 3128"
    Write-Host "  .\run-observathor.ps1 -Mitm -Allow '*.github.com'     # MITM for GitHub only"
    exit 0
}

$exeRoot = Join-Path $PSScriptRoot ".." | Resolve-Path
$buildDir = Join-Path $exeRoot "build"
if(!(Test-Path $buildDir)) { Write-Host "Build directory not found. Run: cmake --preset debug; cmake --build --preset debug"; exit 1 }

$bin = if($Cli){ "observathor_cli" } else { "observathor_imgui" }
$exePath = Join-Path $buildDir "$BuildConfig/$bin.exe"
if(!(Test-Path $exePath)) { Write-Host "Executable $exePath not found. Ensure you built config $BuildConfig."; exit 1 }

$runArgs = @("--listen", "${ListenHost}:$ListenPort")
if($Mitm) { $runArgs += "--enable-mitm" }
if($Allow -ne "") { $runArgs += "--mitm-allow"; $runArgs += $Allow }
if($Deny -ne "") { $runArgs += "--mitm-deny"; $runArgs += $Deny }

Write-Host "Running $bin with args: $runArgs"
& $exePath @runArgs
