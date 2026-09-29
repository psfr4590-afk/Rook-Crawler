#!/usr/bin/env pwsh
# Rook Crawler launcher for Windows PowerShell 7+
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

Write-Host "Rook Crawler 2.1.0 RC" -ForegroundColor Cyan

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw "Node.js 18.17+ is required and was not found in PATH." }
$nodeVersion = [version](node -p "process.versions.node")
if ($nodeVersion -lt [version]"18.17.0") { throw "Node.js 18.17+ is required. Found $nodeVersion." }

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) { throw "npm was not found in PATH." }

if (-not (Test-Path -LiteralPath "package-lock.json")) {
    throw "package-lock.json is required for a deterministic install."
}
if (-not (Test-Path -LiteralPath "node_modules")) {
    Write-Host "[SETUP] Installing locked dependencies..." -ForegroundColor Yellow
    npm ci
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed." }
}

$port = if ($env:PORT) { $env:PORT } else { "8010" }
Write-Host "[LAUNCH] http://127.0.0.1:$port" -ForegroundColor Cyan
& npm.cmd start
exit $LASTEXITCODE
