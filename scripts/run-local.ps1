<#
.SYNOPSIS
  Construit le code ACTUEL de l'arbre de travail (meme non commite) et le lance en local,
  pour montrer les attaques sur la version vulnerable avant correction.
.EXAMPLE
  .\scripts\run-local.ps1 -Port 8090
  .\scripts\run-local.ps1 -Stop
#>
param([int]$Port = 8090, [switch]$Stop)
$ErrorActionPreference = "Continue"
Set-Location (Resolve-Path "$PSScriptRoot\..").Path
$name = "facturation-local"

docker rm -f $name 2>$null | Out-Null
if ($Stop) { Write-Host "$name supprime." -ForegroundColor Green; exit 0 }

Write-Host "Construction de l'image a partir du code actuel..." -ForegroundColor Cyan
docker build -q -t facturation:local app
if ($LASTEXITCODE -ne 0) { Write-Host "docker build a echoue" -ForegroundColor Red; exit 1 }
docker run -d --name $name -p "${Port}:8000" facturation:local | Out-Null

for ($i = 0; $i -lt 20; $i++) {
    $health = curl.exe -s "http://localhost:$Port/health"
    if ($health -match '"ok"') {
        Write-Host "Application locale prete : http://localhost:$Port  ($health)" -ForegroundColor Green
        exit 0
    }
    Start-Sleep -Seconds 1
}
Write-Host "L'application ne repond pas sur le port $Port" -ForegroundColor Red
docker logs $name
exit 1
