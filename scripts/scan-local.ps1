<#
.SYNOPSIS
  Lance un controle de securite a la main, avec la MEME politique que la CI
  (security/policy.yml + security/exemptions.yml via security/gate.py).
  Aussi utilise par les hooks pre-push (trivy) et pre-commit/pre-push (tests).
.EXAMPLE
  .\scripts\scan-local.ps1 -Only trivy
  .\scripts\scan-local.ps1            # tous les controles
#>
param(
    [ValidateSet("gitleaks", "semgrep", "bandit", "trivy", "tests", "all")]
    [string]$Only = "all"
)
$ErrorActionPreference = "Continue"
$Root = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $Root
New-Item -ItemType Directory -Force reports | Out-Null

# Outils epingles (memes versions que .github/workflows/devsecops.yml)
$GITLEAKS = "zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
$SEMGREP  = "semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed"
$TRIVY    = "aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
$BANDIT   = "bandit==1.9.4"

$Py = Join-Path $Root ".venv\Scripts\python.exe"
function Initialize-Venv {
    if (-not (Test-Path $Py)) { python -m venv .venv }
    # synchronise le venv avec les dependances DU CODE ACTUEL (faille 4 comprise)
    & $Py -m pip install -q --disable-pip-version-check -r app/requirements.txt -r app/requirements-dev.txt pyyaml $BANDIT
    if ($LASTEXITCODE -ne 0) { throw "pip install a echoue" }
}
function Invoke-Gate([string]$Tool) {
    & $Py security/gate.py check --tool $Tool --policy security/policy.yml --exemptions security/exemptions.yml | Out-Host
    return $LASTEXITCODE
}

$failed = @()
Initialize-Venv

if ($Only -in "gitleaks", "all") {
    Write-Host "`n>>> Gitleaks (secrets, fichiers actuels)" -ForegroundColor Cyan
    Remove-Item reports/gitleaks.json -ErrorAction SilentlyContinue
    docker run --rm -v "${Root}:/src" $GITLEAKS dir /src --config /src/.gitleaks.toml --redact `
        --no-banner --exit-code 0 --report-format json --report-path /src/reports/gitleaks.json
    if ((Invoke-Gate gitleaks) -ne 0) { $failed += "gitleaks" }
}
if ($Only -in "semgrep", "all") {
    Write-Host "`n>>> Semgrep (SAST : security/semgrep + p/python)" -ForegroundColor Cyan
    Remove-Item reports/semgrep.json -ErrorAction SilentlyContinue
    docker run --rm -v "${Root}:/src" -w /src $SEMGREP semgrep scan --config security/semgrep --config p/python `
        --metrics off --quiet --json-output reports/semgrep.json --sarif-output reports/semgrep.sarif app
    if ((Invoke-Gate semgrep) -ne 0) { $failed += "semgrep" }
}
if ($Only -in "bandit", "all") {
    Write-Host "`n>>> Bandit (SAST Python)" -ForegroundColor Cyan
    & $Py -m bandit -q -r app/facturation -f json -o reports/bandit.json
    if ((Invoke-Gate bandit) -ne 0) { $failed += "bandit" }
}
if ($Only -in "trivy", "all") {
    Write-Host "`n>>> Trivy fs (SCA : dependances, CVSS >= 7 avec correctif)" -ForegroundColor Cyan
    Remove-Item reports/trivy-fs.json -ErrorAction SilentlyContinue
    $trivyArgs = @("fs", "--quiet", "--scanners", "vuln", "--skip-dirs", "/src/.venv", "--format", "json",
                   "--output", "/src/reports/trivy-fs.json", "/src")
    docker run --rm -v trivy-cache:/root/.cache/trivy -v "${Root}:/src" $TRIVY @trivyArgs
    if ($LASTEXITCODE -ne 0) {
        # panne reseau (base de CVE injoignable) : on reutilise la base en cache plutot que d'echouer
        Write-Host "Telechargement de la base Trivy impossible : nouvel essai avec la base en cache" -ForegroundColor Yellow
        docker run --rm -v trivy-cache:/root/.cache/trivy -v "${Root}:/src" $TRIVY @trivyArgs --skip-db-update
    }
    if ((Invoke-Gate trivy-fs) -ne 0) { $failed += "trivy" }
}
if ($Only -in "tests", "all") {
    Write-Host "`n>>> pytest (6 tests, couverture >= 80 %)" -ForegroundColor Cyan
    Push-Location app
    & $Py -m pytest -q -p no:cacheprovider --cov=facturation --cov-fail-under=80 --cov-report=term-missing:skip-covered
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -ne 0) { $failed += "tests" }
}

if ($failed.Count -gt 0) {
    Write-Host "`nBLOQUE par : $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "`nOK : aucun probleme bloquant ($Only)" -ForegroundColor Green
exit 0
