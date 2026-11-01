# FlashTruth Cross-Platform Build Script (PowerShell)
$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot "dist"
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Ext = ".exe" },
    @{ GOOS = "linux";   GOARCH = "amd64"; Ext = ""     },
    @{ GOOS = "linux";   GOARCH = "arm64"; Ext = ""     },
    @{ GOOS = "darwin";  GOARCH = "amd64"; Ext = ""     },
    @{ GOOS = "darwin";  GOARCH = "arm64"; Ext = ""     }
)

Write-Host "=== Building FlashTruth Cross-Platform Binaries ===" -ForegroundColor Cyan
foreach ($t in $targets) {
    $env:CGO_ENABLED = "0"
    $env:GOOS = $t.GOOS
    $env:GOARCH = $t.GOARCH
    $binName = "flashtruth-$($t.GOOS)-$($t.GOARCH)$($t.Ext)"
    $outPath = Join-Path $OutDir $binName
    Write-Host " -> Compiling $binName ..."
    go build -ldflags="-s -w" -o $outPath .
    $sizeMB = [math]::Round((Get-Item $outPath).Length / 1MB, 2)
    Write-Host "    [OK] $outPath ($sizeMB MB)" -ForegroundColor Green
}
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Write-Host "=== All 6 Platform Binaries Built Successfully! ===" -ForegroundColor Cyan
