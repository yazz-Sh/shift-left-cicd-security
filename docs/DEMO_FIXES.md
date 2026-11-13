# Correctifs a appliquer pendant la demo

La version vulnerable (tag `demo-vulnerable`) contient 4 failles dans 3 fichiers.
Deux facons de corriger :

- **taper** les lignes ci-dessous (recommande devant le professeur) ;
- ou **copier** les fichiers surs :
  `Copy-Item docs\fixes\config.py app\facturation\config.py` (idem `main.py` et `requirements.txt` vers `app\`).

> La cle AWS factice n'est jamais ecrite dans ce document (Gitleaks bloquerait le commit) :
> elle est representee par `AKIA...`.

---

## Faille 1 - Secret AWS en dur (CWE-798, OWASP A07:2025)

**Fichier :** `app/facturation/config.py`, lignes 7-8

Code vulnerable :
```python
# Cles AWS du compte de stockage des factures
AWS_ACCESS_KEY_ID = "AKIA..."
AWS_SECRET_ACCESS_KEY = "..."
```

Code sur a taper :
```python
# CORRECTIF (CWE-798) : aucun secret dans le code, lecture depuis l'environnement
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
```

**Preuve :** Gitleaks (`aws-access-token`) ne remonte plus rien (pre-commit, pre-push, job `secrets_scan`) ;
le test `test_no_hardcoded_secret` passe au vert.
**Important :** une cle reellement commitee doit aussi etre **revoquee** (elle reste dans l'historique Git).

---

## Faille 2 - Injection SQL (CWE-89, OWASP A05:2025 Injection)

**Fichier :** `app/facturation/main.py`, fonction `search_invoices` (ligne 53)

Code vulnerable :
```python
    rows = conn.execute(
        f"SELECT * FROM invoices WHERE owner_id = {user['id']} AND customer LIKE '%{customer}%'"
    ).fetchall()
```

Code sur a taper :
```python
    # CORRECTIF (CWE-89) : requete parametree
    rows = conn.execute(
        "SELECT * FROM invoices WHERE owner_id = ? AND customer LIKE ?",
        (user["id"], f"%{customer}%"),
    ).fetchall()
```

**Preuve :** la regle Semgrep `facturation-sql-fstring` disparait (pre-commit, job `sast`) ;
le test `test_sql_injection_blocked` passe ; l'attaque `customer=%' OR 1=1 --` ne renvoie plus la facture de Bob
(`demo-attacks.ps1` affiche `PROTEGE`).

---

## Faille 3 - Injection de commande sans authentification (CWE-78, OWASP A05:2025)

**Fichier :** `app/facturation/main.py`, fonction `admin_ping` (lignes 59-62)

Code vulnerable :
```python
@app.get("/admin/ping")
def admin_ping(host: str) -> dict:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return {"host": host, "reachable": result.returncode == 0, "output": result.stdout}
```

Code sur a taper :
```python
@app.get("/admin/ping")
def admin_ping(host: str, x_api_key: str | None = Header(default=None)) -> dict:
    # CORRECTIF (CWE-78) : authentification + validation de l'hote + pas de shell
    current_user(x_api_key)
    if not HOST_RE.fullmatch(host):
        raise HTTPException(status_code=400, detail="Nom d'hote invalide")
    result = subprocess.run(
        ["/usr/bin/ping", "-c", "1", "-W", "2", host], capture_output=True, text=True, timeout=10
    )
    return {"host": host, "reachable": result.returncode == 0, "output": result.stdout}
```

Et en haut du fichier (ligne 2 et apres `db.init_db()`) :
```python
import re
...
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
```

**Preuve :** Bandit `B602` (HIGH) et Semgrep `subprocess-shell-true` disparaissent ;
le test `test_command_injection_blocked` passe (401 sans cle, 400 avec la cle d'Alice) ;
l'attaque `host=127.0.0.1;id` ne renvoie plus `uid=` (`PROTEGE`).

---

## Faille 4 - Dependance vulnerable (CWE-1395, OWASP A03:2025 Supply Chain)

**Fichier :** `app/requirements.txt`, ligne 4

Code vulnerable :
```text
urllib3==1.26.4
```

Code sur a taper :
```text
# CORRECTIF (SCA) : urllib3 >= 2.8.0, aucune CVE HIGH connue (1.26.4 : CVE-2021-33503...)
urllib3==2.8.0
```

**Preuve :** Trivy fs ne remonte plus les 8 CVE HIGH corrigeables (CVE-2021-33503, CVE-2023-43804, ...)
(pre-push, job `scan_dependencies`) ; le test `test_dependency_is_patched` passe
(apres `pip install -r app/requirements.txt`, fait automatiquement par le hook pytest).
