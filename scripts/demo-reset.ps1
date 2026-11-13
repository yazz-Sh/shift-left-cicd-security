<#
.SYNOPSIS
  Remet tout a zero apres une demo (pour repeter) :
   - annule les modifications locales,
   - remet main sur le tag "baseline" (local + GitHub, git push --force-with-lease),
   - supprime les conteneurs facturation-app (8081) et facturation-local (8090).
  Le workflow ignore ce push force (condition "github.event.forced") : rien n'est redeploye.
.EXAMPLE
  .\scripts\demo-reset.ps1           # demande confirmation
  .\scripts\demo-reset.ps1 -Force
#>
param([switch]$Force)
$ErrorActionPreference = "Continue"
Set-Location (Resolve-Path "$PSScriptRoot\..").Path

git fetch -q origin --tags
$baseline = git rev-parse --short baseline
Write-Host "AVANT : main local = $(git rev-parse --short main), main GitHub = $(git rev-parse --short origin/main), baseline = $baseline"
if (-not $Force) {
    $answer = Read-Host "Remettre main sur baseline ($baseline) localement ET sur GitHub ? (o/N)"
    if ($answer -ne "o") { Write-Host "Annule."; exit 1 }
}

git checkout -q main
git reset -q --hard baseline                  # annule commits et modifications locales
git clean -q -fd -- app                       # fichiers non suivis eventuellement crees dans app/
git push --force-with-lease --no-verify origin main
docker rm -f facturation-app facturation-local 2>$null | Out-Null

git fetch -q origin
$local = git rev-parse --short main
$remote = git rev-parse --short origin/main
Write-Host "APRES : main local = $local, main GitHub = $remote, baseline = $baseline" -ForegroundColor Cyan
Write-Host "git status : $(if (git status --porcelain) { 'modifications presentes' } else { 'propre' })"
$apps = docker ps -a --filter "name=facturation-app" --filter "name=facturation-local" --format "{{.Names}}"
Write-Host "Conteneurs deployes : $(if ($apps) { $apps -join ', ' } else { 'aucun' })"
if ($local -ne $baseline -or $remote -ne $baseline -or $apps) {
    Write-Host "ECHEC de la remise a zero" -ForegroundColor Red
    exit 1
}
Write-Host "OK - pret pour une nouvelle repetition : .\scripts\demo-prepare.ps1" -ForegroundColor Green
