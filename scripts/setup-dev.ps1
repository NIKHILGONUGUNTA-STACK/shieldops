[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$example = Join-Path $root 'config/dev.env.example'
$environment = Join-Path $root 'config/dev.env'

if (Test-Path $environment) {
    Write-Host 'config/dev.env already exists; no changes made.'
    exit 0
}

Copy-Item -LiteralPath $example -Destination $environment
Write-Host 'Created config/dev.env. Replace the example password values before starting the stack.'
