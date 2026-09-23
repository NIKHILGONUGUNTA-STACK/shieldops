[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$environment = Join-Path $root 'config/dev.env'
if (-not (Test-Path $environment)) { $environment = Join-Path $root 'config/dev.env.example' }
& docker compose --env-file $environment -f (Join-Path $root 'infrastructure/docker/compose.yml') config --quiet
Write-Host 'Docker Compose configuration is valid.'
