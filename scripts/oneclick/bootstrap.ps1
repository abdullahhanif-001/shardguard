#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

Write-Host "[scsp] bootstrap (Windows)"

New-Item -ItemType Directory -Force -Path .scsp, vendor, attestations, benchmarks | Out-Null

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host "[scsp] installing nyx-scanner..."
    cargo install nyx-scanner --locked 2>$null
}

py -m pip install -e $Root -q

if (-not (Test-Path "fixtures\MOCK_\M01_shard_three_modules")) {
    py scripts\generate_fixtures.py
}

py -m scsp verify-self --pin
py -m scsp verify-fixtures --generate

Write-Host "[scsp] bootstrap complete — run: py -m scsp gate all"
