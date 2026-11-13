# Aide-memoire de la demonstration (≈ 12 min)

## Avant la demo (10 min avant)

- [ ] Docker Desktop demarre (`docker ps` repond)
- [ ] Runner **Idle** : GitHub > Settings > Actions > Runners (service `actions.runner.*` demarre)
- [ ] Internet OK (`curl.exe -s https://api.github.com` repond)
- [ ] `.\scripts\demo-reset.ps1 -Force` puis `.\scripts\demo-prepare.ps1` : 3 fichiers `M`, rien sur 8081
- [ ] VS Code ouvert sur `app/facturation/main.py` et `config.py` (panneau Problems : Ctrl+Shift+M)
- [ ] Onglets : Actions du depot, SonarCloud, boite mail
- [ ] Variable de demo : `$key = "alice-demo-key"` (cle de l'utilisatrice de demonstration)

## Deroule

| # | Commande | Ce que l'on voit | Phrase a dire |
|---|---|---|---|
| 0 | `.\scripts\demo-prepare.ps1` | 3 fichiers modifies, non commites | « Je suis un developpeur qui vient d'ecrire du code vulnerable. » |
| 1 | (VS Code) | soulignements Semgrep : cle AWS l.7-8, SQL l.52, `shell=True` l.61 | « Les failles sont signalees pendant que je code. » |
| 2 | `.\scripts\run-local.ps1 -Port 8090` puis `.\scripts\demo-attacks.ps1 -Port 8090` (50 s) | 2 x **VULNERABLE** (facture de Bob, `uid=10001`) | « Ces failles sont reellement exploitables. » |
|   | `.\scripts\run-local.ps1 -Stop` | | |
| 3 | `git add -A ; git commit -m "Ajout export des factures vers le stockage AWS"` (15 s) | 4 hooks **Failed** | « Le commit est refuse sur mon poste, avec la raison. » |
| 4 | `git commit --no-verify -m "..." ; git push` (35 s) | 5 hooks **Failed**, dont Trivy (8 CVE) | « Meme en forcant le commit, le push est refuse. » |
| 5 | `git push --no-verify` (30 s) | run Actions demarre seul, **1 secrets_scan** rouge, 7 jobs *skipped*, e-mail d'echec | « Un developpeur negligent contourne son poste : le pipeline bloque, rien n'est deploye. » |
| 6 | corriger (taper `docs/DEMO_FIXES.md` ou `Copy-Item docs\fixes\...`) | `git diff` : 4 correctifs | « Requete parametree, pas de shell, secret en variable d'environnement, dependance a jour. » |
| 7 | `git add -A ; git commit -m "Correction des 4 failles de securite" ; git push` (40 s) | hooks **Passed**, run automatique, **8 jobs verts** (≈ 5 min) | « Tous les controles passent : l'image est construite, scannee, testee en DAST puis deployee. » |
| 8 | `.\scripts\demo-attacks.ps1 -Port 8081` | 2 x **PROTEGE** (`[]`, HTTP 401) | « L'application deployee resiste aux memes attaques. » |
|   | Actions > run > Summary / Artifacts ; SonarCloud | rapports, quality gate **Passed** | « Chaque job laisse des rapports JSON/HTML ; SonarCloud centralise. » |
| 9 | `.\scripts\demo-reset.ps1 -Force` (5 s) | `APRES : main = baseline`, aucun conteneur | (apres la demo) |

**Pendant les 5 min du pipeline (etape 7)** : ouvrir le job en cours, montrer `security/policy.yml`
(seuils), `security/exemptions.yml` (derogation tracee), le rapport `gate-trivy-fs.html` du run rouge.

## Si quelque chose casse

| Probleme | Correction en une ligne |
|---|---|
| Job `deploy` en attente « Waiting for a runner » | `Restart-Service "actions.runner.*"` (PowerShell admin) puis verifier **Idle** |
| `docker` ne repond pas / hook gitleaks en erreur | demarrer Docker Desktop, attendre « Engine running », relancer la commande |
| Telechargement de la base Trivy echoue | relancer le job (bouton *Re-run failed jobs*) ; en local le cache est reutilise automatiquement |
| Port 8081 / 8090 deja utilise | `docker rm -f facturation-app facturation-local` |
| Hook : `PermissionError` (cache pre-commit) | ouvrir un **nouveau** terminal (variables `PRE_COMMIT_HOME` / `VIRTUALENV_OVERRIDE_APP_DATA`) |
