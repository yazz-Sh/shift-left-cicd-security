# shift-left-cicd-security

Pipeline DevSecOps **shift-left** pour une petite API de facturation (FastAPI + SQLite).
Objectif : **aucun code vulnerable ne doit atteindre la production**. Les failles sont
detectees le plus tot possible (dans l'editeur, au commit, au push) et, si un developpeur
contourne son poste, le pipeline GitHub Actions les **bloque avant le deploiement**.

- Un seul outil CI : **GitHub Actions**, un seul workflow : `.github/workflows/devsecops.yml`
- Un seul code, une seule branche : `main`
- Deploiement automatique sur un **runner auto-heberge** (ce PC), port **8081**

## Le flux

```
 code ──> IDE ──────────> commit ─────────> push ──────────> GitHub Actions (8 jobs, fail-fast) ──> deploiement
          VS Code         hook pre-commit   hook pre-push    1 secrets   2 sast   3 sonarcloud        runner local
          Semgrep +       gitleaks, bandit  gitleaks, bandit 4 dependances  5 tests  6 image          localhost:8081
          SonarQube IDE   semgrep, pytest   semgrep, trivy,  7 dast   8 deploy
                                            pytest           (1er job en echec => les suivants sont "skipped")
```

## Les 4 couches de protection

| Couche | Quand | Pourquoi elle existe |
|---|---|---|
| 1. **VS Code** (Semgrep, SonarQube for IDE) | pendant la frappe | le developpeur voit la faille avant meme de sauvegarder : correction la moins chere |
| 2. **Hook pre-commit** | `git commit` | refuse le commit : la faille n'entre jamais dans l'historique Git (rapide, ~15 s) |
| 3. **Hook pre-push** | `git push` | controles plus lourds sur tout le depot (Trivy) : rien ne quitte le poste (~30 s) |
| 4. **Workflow fail-fast** | a chaque push sur `main` | les hooks se contournent (`--no-verify`) : le pipeline est le controle **obligatoire** et non contournable |

## Quel outil attrape quelle faille, a quelle couche

| Faille (version `demo-vulnerable`) | VS Code | pre-commit | pre-push | Pipeline (1er job qui bloque) |
|---|---|---|---|---|
| 1. Cle AWS en dur (CWE-798) | Semgrep `detected-aws-access-key-id-value` | gitleaks, pytest | gitleaks, pytest | **1 secrets_scan** (gitleaks) |
| 2. Injection SQL (CWE-89) | Semgrep `sqlalchemy-execute-raw-query` | semgrep, pytest | semgrep, pytest | **2 sast** (semgrep) |
| 3. Injection de commande (CWE-78) | Semgrep `subprocess-shell-true` | bandit B602, semgrep, pytest | bandit, semgrep, pytest | **2 sast** (semgrep + bandit) |
| 4. urllib3 1.26.4 (8 CVE HIGH) | - | pytest | **trivy fs**, pytest | **4 scan_dependencies** (trivy) |

Le detail de chaque correctif est dans [`docs/DEMO_FIXES.md`](docs/DEMO_FIXES.md).

## Les 6 tests (`app/tests/`)

| Test | Verifie |
|---|---|
| `test_health` | `/health` repond `{"status":"ok"}` |
| `test_list_own_invoices` | Alice voit ses 2 factures et jamais celle de Bob |
| `test_no_hardcoded_secret` | aucune cle `AKIA...` dans `config.py`, cles lues depuis l'environnement (faille 1) |
| `test_sql_injection_blocked` | `customer=%' OR 1=1 --` ne renvoie jamais la facture de Bob (faille 2) |
| `test_command_injection_blocked` | `host=127.0.0.1;id` : 401 sans cle, 400 avec cle, jamais `uid=` (faille 3) |
| `test_dependency_is_patched` | urllib3 installe >= 2.8.0 (faille 4) |

Les 4 tests de securite rejouent l'attaque : ils **echouent** sur le code vulnerable et passent sur le code corrige
(tests de non-regression). Couverture exigee : >= 80 % (actuellement 97 %).

## Les 8 jobs du workflow

| # | Job | Detecte | Outil | Rapports (artefacts) |
|---|---|---|---|---|
| 1 | `secrets_scan` | secrets dans les fichiers **actuels** | Gitleaks | JSON, SARIF, HTML |
| 2 | `sast` | failles dans le code source | Semgrep (regles maison + `p/python`), Bandit | JSON, SARIF, HTML |
| 3 | `sonarcloud` | qualite + securite, quality gate SonarCloud | SonarCloud (+ import SARIF Semgrep) | tableau de bord SonarCloud |
| 4 | `scan_dependencies` | CVE des dependances + inventaire | Trivy fs, Syft (SBOM CycloneDX) | JSON, HTML, SBOM |
| 5 | `unit_tests` | regressions fonctionnelles et securite | pytest + couverture | JUnit, coverage XML/HTML |
| 6 | `build_and_scan_image` | CVE de l'image Docker, publication GHCR si saine | Docker, Trivy image | JSON, HTML, empreinte de l'image |
| 7 | `dast` | failles de l'application **en fonctionnement** | OWASP ZAP API scan (`/openapi.json`) | JSON, HTML |
| 8 | `deploy` | deploie l'empreinte exacte testee, verifie `/health` | runner auto-heberge | resume du job |

**Fail-fast** : les jobs sont enchaines par `needs`. Le premier qui echoue arrete tout : les jobs
suivants sont *skipped*, l'image n'est ni construite ni deployee. Les scans de securite passent
**avant** les tests et la construction : inutile de construire un artefact qu'on refusera.

## Seuils bloquants (`security/policy.yml`, appliques par `security/gate.py`)

| Outil | Bloque | Avertit seulement | Pourquoi |
|---|---|---|---|
| Gitleaks | **tout secret** | - | un secret publie est compromis, quelle que soit sa "severite" |
| Semgrep | severite ERROR | WARNING, INFO | les regles ERROR = injection, RCE : exploitables |
| Bandit | HIGH avec confiance >= MEDIUM | le reste | eviter de bloquer sur des faux positifs probables |
| Trivy (fs et image) | CVSS >= 7 (HIGH/CRITICAL) **avec correctif disponible** | MEDIUM/LOW, ou sans correctif | on bloque ce que l'equipe **peut** corriger ; le reste est suivi |
| ZAP | risque High | Medium, Low, Info | alerte High = faille confirmee sur l'application lancee |
| Tous | **rapport manquant ou illisible** | - | un scanner qui n'a pas tourne ne doit pas "passer" |

Les memes seuils sont utilises sur le poste (`scripts/scan-local.ps1`, hooks) et en CI.
Faux positifs : procedure de derogation tracee, voir [`docs/PROCEDURE_DEROGATION.md`](docs/PROCEDURE_DEROGATION.md).

## Ou voir les resultats

- **Actions > run > Summary** : resume lisible de chaque job (PASS/BLOCK, tableau des resultats).
- **Artefacts** du run : tous les rapports JSON / HTML / SARIF / SBOM (`1-secrets-reports` ... `7-dast-reports`).
- **SonarCloud** : https://sonarcloud.io/summary/overall?id=yazz-Sh_shift-left-cicd-security (historique des analyses).
- **E-mail** GitHub a chaque workflow en echec.
- **Historique** : liste des runs dans l'onglet Actions + historique des analyses SonarCloud.
- Captures de la demonstration : [`docs/screenshots/`](docs/screenshots/).

## Secrets du pipeline

- `SONAR_TOKEN` : secret GitHub du depot (jamais dans le code, masque dans les logs).
- `GITHUB_TOKEN` : jeton ephemere fourni par GitHub, droits minimaux par job
  (`contents: read` partout, `packages: write` uniquement dans le job 6).
- Actions epinglees par **SHA de commit**, outils par **digest d'image** : une version ne peut pas etre remplacee en douce.
- Workflow verifie par `actionlint` et `zizmor`. Pas de declencheur `pull_request` (le runner est ce PC) et
  approbation obligatoire pour les contributeurs externes.

## Installation sur un nouveau PC (Windows)

1. Prerequis : Git, Python 3.12, Docker Desktop, VS Code.
2. `git clone https://github.com/yazz-Sh/shift-left-cicd-security.git` puis ouvrir le dossier dans VS Code
   (accepter les extensions recommandees : SonarQube for IDE, Semgrep, Python).
3. `pip install pre-commit pyyaml`
4. Si le cache pre-commit pose un probleme de droits (`PermissionError`) :
   `[Environment]::SetEnvironmentVariable("PRE_COMMIT_HOME", "$env:LOCALAPPDATA\pre-commit-home", "User")` (idem
   `VIRTUALENV_OVERRIDE_APP_DATA`), puis ouvrir un nouveau terminal.
5. `pre-commit install --hook-type pre-commit --hook-type pre-push`
6. Verifier : `.\scripts\scan-local.ps1` (tous les controles, memes seuils que la CI).

Scripts de demonstration : `demo-prepare.ps1`, `run-local.ps1 -Port 8090`, `demo-attacks.ps1 -Port <n>`,
`demo-reset.ps1`. Deroule complet : [`docs/DEMO_CHEATSHEET.md`](docs/DEMO_CHEATSHEET.md).

## Ameliorations futures

- Activer **GitHub push protection** et le *secret scanning* (desactives volontairement pour que la demo
  montre le blocage par le pipeline).
- Secrets applicatifs dans un coffre (**HashiCorp Vault**, OIDC) au lieu de variables d'environnement.
- **Signature des images** (cosign) et verification de la signature avant deploiement.
- Fichier de verrouillage complet des dependances avec empreintes (derogation EXC-2026-001).
- Deploiement sur **Kubernetes** avec politiques d'admission ; revue de code obligatoire (les outils ne
  detectent pas les failles de logique metier, ex. BOLA).

Note : le `git push --force` de `demo-reset.ps1` cree un run dans l'onglet Actions (GitHub enregistre
chaque push), mais tous ses jobs sont *skipped* (`if: !github.event.forced`) : rien n'est redeploye.
