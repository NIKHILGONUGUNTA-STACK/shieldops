[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$environment = Join-Path $root 'config/dev.env'
$compose = Join-Path $root 'infrastructure/docker/compose.yml'

if (-not (Test-Path $environment)) {
    throw 'Missing config/dev.env. Run ./scripts/setup-dev.ps1 and set local passwords first.'
}

& docker compose --env-file $environment -f $compose config --quiet
if ($LASTEXITCODE -ne 0) { throw "Docker Compose configuration validation failed with exit code $LASTEXITCODE; the stack was not started." }
& docker compose --env-file $environment -f $compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "Docker Compose startup failed with exit code $LASTEXITCODE." }
