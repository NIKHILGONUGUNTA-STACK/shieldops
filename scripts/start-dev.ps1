[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$environment = Join-Path $root 'config/dev.env'
$compose = Join-Path $root 'infrastructure/docker/compose.yml'

if (-not (Test-Path $environment)) {
    throw 'Missing config/dev.env. Run ./scripts/setup-dev.ps1 and set local passwords first.'
}

& docker compose --env-file $environment -f $compose up -d
