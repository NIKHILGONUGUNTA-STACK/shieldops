[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$environment = Join-Path $root 'config/dev.env'
if (-not (Test-Path $environment)) { throw 'Missing config/dev.env. Run ./scripts/setup-dev.ps1 first.' }
& docker compose --env-file $environment -f (Join-Path $root 'infrastructure/docker/compose.yml') config --quiet
if ($LASTEXITCODE -ne 0) { throw "Docker Compose configuration validation failed with exit code $LASTEXITCODE." }
Write-Host 'Docker Compose configuration is valid.'
