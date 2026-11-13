# Procedure de derogation (faux positifs et risques acceptes)

Un resultat bloquant ne se contourne **jamais** en desactivant un outil ou en modifiant un seuil.
Il se traite par une **derogation tracee** dans `security/exemptions.yml`, revue comme du code.

## 1. Qui peut demander, qui approuve

- Le developpeur ouvre un ticket (ex. `SEC-012`) : outil, regle, emplacement, analyse.
- Le responsable securite (RSSI / lead securite) **approuve** ou refuse. Le developpeur ne s'auto-approuve pas.

## 2. Contenu obligatoire d'une derogation

```yaml
  - id: EXC-2026-002            # identifiant unique
    tool: bandit                # gitleaks | semgrep | bandit | trivy-fs | trivy-image | zap | sonarcloud
    rule: B603                  # regle ou CVE concernee
    location: "app/facturation/main.py"   # perimetre le plus etroit possible
    justification: >-
      FAUX POSITIF : ... (ou RISQUE ACCEPTE : ... + mesure compensatoire)
    approved_by: "RSSI - Nom Prenom"
    ticket: SEC-012
    created: 2026-11-13
    expires: 2027-02-13         # 3 mois maximum, 6 mois pour un risque accepte documente
```

`security/gate.py` **refuse** une derogation incomplete (champ manquant) : le resultat reste bloquant.

## 3. Expiration

A la date `expires`, la derogation est ignoree automatiquement : le resultat **redevient bloquant**
et le pipeline echoue jusqu'a correction ou renouvellement (nouvelle approbation).

## 4. Tracabilite

- La derogation passe par un commit (auteur, date, message) : l'historique Git est le journal d'audit.
- Le gate affiche les resultats `EXEMPTED` avec l'identifiant de la derogation dans le resume du job
  et dans les rapports `gate-<outil>.html/json`.
- Pour SonarCloud, l'issue est passee au statut **Accepted** avec le meme identifiant en commentaire,
  et la derogation est aussi inscrite dans `security/exemptions.yml` (registre unique).
  Exemple reel : `EXC-2026-001` (`docker:S8544`, ticket `SEC-001`).

## 5. Ce qui n'est jamais derogeable

- Un **secret reel** : il doit etre revoque puis retire du code (une derogation ne le rend pas secret).
- Une faille HIGH/CRITICAL exploitable sur un endpoint expose, quand un correctif existe.
