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
Write-Host "main local  : $(git rev-parse --short main)"
Write-Host "main GitHub : $(git rev-parse --short origin/main)"
Write-Host "baseline    : $baseline"
if (-not $Force) {
    $answer = Read-Host "Remettre main sur baseline ($baseline) localement ET sur GitHub ? (o/N)"
    if ($answer -ne "o") { Write-Host "Annule."; exit 1 }
}

git checkout -q main
git reset -q --hard baseline                  # annule commits et modifications locales
git clean -q -fd -- app                       # fichiers non suivis eventuellement crees dans app/
git push --force-with-lease --no-verify origin main
docker rm -f facturation-app facturation-local 2>$null | Out-Null

Write-Host "`nEtat :" -ForegroundColor Cyan
git log --oneline -1
git status --short
docker ps --filter "name=facturation" --format "{{.Names}} {{.Ports}}"
Write-Host "Pret pour une nouvelle repetition : .\scripts\demo-prepare.ps1" -ForegroundColor Green
