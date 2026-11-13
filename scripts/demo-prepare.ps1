<#
.SYNOPSIS
  Prepare la demo : met la version VULNERABLE (tag demo-vulnerable) dans l'arbre de travail,
  sans la commiter, et supprime toute application deployee.
#>
$ErrorActionPreference = "Continue"
Set-Location (Resolve-Path "$PSScriptRoot\..").Path
$files = "app/facturation/config.py", "app/facturation/main.py", "app/requirements.txt"

git fetch -q origin --tags
if (git status --porcelain -- app) {
    Write-Host "Des modifications existent deja dans app/ : lancez d'abord .\scripts\demo-reset.ps1" -ForegroundColor Red
    exit 1
}
git checkout demo-vulnerable -- $files
git restore --staged -- $files        # modifie mais NON commite, comme un developpeur en train de coder
docker rm -f facturation-app facturation-local 2>$null | Out-Null

Write-Host "`nVersion vulnerable en place (non commitee) :" -ForegroundColor Yellow
git status --short
Write-Host @"

Aucun conteneur deploye (8081 et 8090 libres).
Etapes suivantes :
  1. VS Code : ouvrir app/facturation/config.py, main.py et app/requirements.txt (failles soulignees)
  2. .\scripts\run-local.ps1 -Port 8090 ; .\scripts\demo-attacks.ps1 -Port 8090   -> VULNERABLE
  3. git add -A ; git commit -m "Ajout export factures"                         -> refuse (pre-commit)
  4. git commit --no-verify -m "..." ; git push                                 -> refuse (pre-push)
  5. git push --no-verify                                                        -> pipeline bloque
"@ -ForegroundColor Cyan
