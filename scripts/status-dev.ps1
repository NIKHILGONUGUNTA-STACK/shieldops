[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& docker compose --env-file (Join-Path $root 'config/dev.env') -f (Join-Path $root 'infrastructure/docker/compose.yml') ps
