<#
.SYNOPSIS
  Rejoue les 2 attaques de la demo contre l'application et affiche VULNERABLE ou PROTEGE.
.EXAMPLE
  .\scripts\demo-attacks.ps1 -Port 8090    # version locale (vulnerable)
  .\scripts\demo-attacks.ps1 -Port 8081    # version deployee par le pipeline
#>
param([int]$Port = 8081)
$ErrorActionPreference = "Continue"
$base = "http://localhost:$Port"
$key = "alice-demo-key"        # cle API de demonstration d'Alice (base SQLite de demo)

Write-Host "`n=== Cible : $base ===" -ForegroundColor Cyan
if ((curl.exe -s "$base/health") -notmatch '"ok"') {
    Write-Host "Aucune application sur le port $Port" -ForegroundColor Red
    exit 1
}

# --- Attaque 1 : injection SQL (CWE-89) : Alice tente de lire les factures de Bob
Write-Host "`n[1] Injection SQL : GET /invoices/search?customer=%' OR 1=1 --  (cle d'Alice)"
$sqli = curl.exe -s -G -H "X-API-Key: $key" --data-urlencode "customer=%' OR 1=1 --" "$base/invoices/search"
Write-Host "    Reponse : $sqli"
if ($sqli -match '"owner_id":2') {
    Write-Host "    => VULNERABLE : la facture de Bob (owner_id 2) a fuite" -ForegroundColor Red
} else {
    Write-Host "    => PROTEGE : seules les factures d'Alice sont accessibles" -ForegroundColor Green
}

# --- Attaque 2 : injection de commande (CWE-78) sans authentification
Write-Host "`n[2] Injection de commande : GET /admin/ping?host=127.0.0.1;id  (sans cle)"
$out = curl.exe -s -G -w "`nHTTP %{http_code}" --data-urlencode "host=127.0.0.1;id" "$base/admin/ping"
$code = ($out | Select-Object -Last 1)
$body = ($out | Select-Object -SkipLast 1) -join " "
Write-Host "    $code : $($body.Substring(0, [Math]::Min(160, $body.Length)))"
if ($body -match 'uid=') {
    $uid = [regex]::Match($body, 'uid=[^\\"]*').Value
    Write-Host "    => VULNERABLE : la commande 'id' a ete executee sur le serveur ($uid)" -ForegroundColor Red
} else {
    Write-Host "    => PROTEGE : commande refusee ($code)" -ForegroundColor Green
}
