$ErrorActionPreference = "Stop"

function Test-Command {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        Write-Host "[missing] $Name"
        return $false
    }

    Write-Host "[ok] $Name -> $($cmd.Source)"
    return $true
}

$ok = $true
$ok = (Test-Command "git") -and $ok
$ok = (Test-Command "docker") -and $ok
$ok = (Test-Command "rg") -and $ok

if (Test-Command "docker") {
    docker compose version
}

if (-not $ok) {
    throw "Missing one or more prerequisites."
}

Write-Host "Prerequisites look usable for scaffold work."

