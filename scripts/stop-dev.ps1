[CmdletBinding()]
param([switch]$RemoveVolumes)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$environment = Join-Path $root 'config/dev.env'
$compose = Join-Path $root 'infrastructure/docker/compose.yml'
$arguments = @('compose', '--env-file', $environment, '-f', $compose, 'down')
if ($RemoveVolumes) { $arguments += '--volumes' }
& docker @arguments
