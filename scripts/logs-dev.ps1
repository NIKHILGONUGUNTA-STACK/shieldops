[CmdletBinding()]
param([string]$Service)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$arguments = @('compose', '--env-file', (Join-Path $root 'config/dev.env'), '-f', (Join-Path $root 'infrastructure/docker/compose.yml'), 'logs', '--follow')
if ($Service) { $arguments += $Service }
& docker @arguments
