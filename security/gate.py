#!/usr/bin/env python3
"""
Quality gate de securite : un verdict PASS / BLOCK par outil.

Lit le rapport JSON d'un scanner (reports/), applique la politique
(security/policy.yml) et les derogations tracees (security/exemptions.yml).

  python security/gate.py check --tool trivy-fs --policy security/policy.yml \
         --exemptions security/exemptions.yml

Sorties : console, reports/gate-<outil>.json, reports/gate-<outil>.html et,
dans GitHub Actions, un resume Markdown dans $GITHUB_STEP_SUMMARY.
Code de sortie : 0 = PASS, 1 = BLOCK (le job echoue, les jobs suivants sont sautes).
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import sys
from pathlib import Path

import yaml

REPORT_FILES = {
    "gitleaks": "gitleaks.json",
    "semgrep": "semgrep.json",
    "bandit": "bandit.json",
    "trivy-fs": "trivy-fs.json",
    "trivy-image": "trivy-image.json",
    "zap": "zap.json",
}
CONFIDENCE = ["LOW", "MEDIUM", "HIGH"]


# ------------------------------------------------------------ lecture des rapports
def finding(tool, rule, severity, title, location, **extra):
    return {"tool": tool, "rule": str(rule), "severity": severity, "title": title,
            "location": location, **extra}


def parse_gitleaks(data):
    for r in data or []:
        yield finding("gitleaks", r.get("RuleID"), "CRITICAL", r.get("Description", "Secret"),
                      f"{r.get('File')}:{r.get('StartLine')}")


def parse_semgrep(data):
    sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    for r in data.get("results", []):
        ex = r.get("extra", {})
        yield finding("semgrep", r.get("check_id"), sev.get(ex.get("severity"), "MEDIUM"),
                      ex.get("message", "").strip().split("\n")[0][:160],
                      f"{r.get('path')}:{r.get('start', {}).get('line')}")


def parse_bandit(data):
    for r in data.get("results", []):
        yield finding("bandit", r.get("test_id"), r.get("issue_severity", "LOW").upper(),
                      r.get("issue_text", ""), f"{r.get('filename')}:{r.get('line_number')}",
                      confidence=r.get("issue_confidence", "LOW").upper())


def parse_trivy(tool):
    def parse(data):
        for res in data.get("Results", []) or []:
            for v in res.get("Vulnerabilities", []) or []:
                yield finding(tool, v.get("VulnerabilityID"), v.get("Severity", "UNKNOWN").upper(),
                              f"{v.get('PkgName')} {v.get('InstalledVersion')} - {v.get('Title', '')}"[:160],
                              res.get("Target", ""), fixed_version=v.get("FixedVersion") or "")
    return parse


def parse_zap(data):
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances") or [{}]
            yield finding("zap", a.get("pluginid"), risk.get(str(a.get("riskcode")), "INFO"),
                          a.get("alert") or a.get("name", ""),
                          f"{inst[0].get('method', '')} {inst[0].get('uri', '')}")


PARSERS = {"gitleaks": parse_gitleaks, "semgrep": parse_semgrep, "bandit": parse_bandit,
           "trivy-fs": parse_trivy("trivy-fs"), "trivy-image": parse_trivy("trivy-image"),
           "zap": parse_zap}


# ------------------------------------------------------------ politique
def load_yaml(path):
    p = Path(path)
    return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}


def active_exemptions(raw, today):
    """Une derogation incomplete ou expiree est refusee (le resultat redevient bloquant)."""
    active, problems = [], []
    for e in raw.get("exemptions") or []:
        missing = [k for k in ("id", "tool", "rule", "justification", "approved_by", "ticket", "expires")
                   if not e.get(k)]
        if missing:
            problems.append(f"Derogation {e.get('id', '?')} refusee : champs manquants {missing}")
            continue
        expires = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        if expires < today:
            problems.append(f"Derogation {e['id']} EXPIREE le {expires} : le resultat redevient bloquant")
            continue
        active.append(e)
    return active, problems


def decide(f, rules, exemptions):
    for e in exemptions:
        if e["tool"] == f["tool"] and str(e["rule"]) == f["rule"] and e.get("location", "") in f["location"]:
            f["exemption"] = e["id"]
            return "EXEMPTED"
    if f["severity"] not in rules.get("block", []):
        return "WARN"
    if rules.get("block_only_if_fix_available") and not f.get("fixed_version"):
        return "WARN"
    min_conf = rules.get("min_confidence_to_block")
    if min_conf and CONFIDENCE.index(f.get("confidence", "LOW")) < CONFIDENCE.index(min_conf):
        return "WARN"
    return "BLOCK"


def check(tool, reports_dir, policy, exemptions_raw):
    exemptions, problems = active_exemptions(exemptions_raw, dt.date.today())
    rules = (policy.get("tools") or {}).get(tool, {})
    path = Path(reports_dir) / REPORT_FILES[tool]
    findings = []
    if not path.exists():
        problems.append(f"Rapport manquant ({path}) : un scanner sans rapport = BLOCK")
    else:
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "null")
            for f in PARSERS[tool](data if data is not None else {}):
                f["decision"] = decide(f, rules, exemptions)
                findings.append(f)
        except (json.JSONDecodeError, AttributeError) as exc:
            problems.append(f"Rapport illisible ({path}) : {exc}")
    count = {d: sum(f["decision"] == d for f in findings) for d in ("BLOCK", "WARN", "EXEMPTED")}
    blocked = count["BLOCK"] > 0 or any("manquant" in p or "illisible" in p for p in problems)
    return {"tool": tool, "verdict": "BLOCK" if blocked else "PASS", "count": count,
            "findings": findings, "problems": problems}


# ------------------------------------------------------------ sorties
def print_console(r):
    c = r["count"]
    print(f"== Gate {r['tool']} : {c['BLOCK']} bloquant(s), {c['WARN']} avertissement(s), "
          f"{c['EXEMPTED']} derogation(s)")
    for f in r["findings"]:
        if f["decision"] != "WARN":
            print(f"   {f['decision']:<8} {f['severity']:<8} {f['rule']:<30} {f['location']}  {f['title'][:80]}")
    for p in r["problems"]:
        print(f"   ! {p}")
    print(f"== VERDICT {r['tool']} : {r['verdict']}")


def markdown(r):
    icon = "🔴 BLOCK" if r["verdict"] == "BLOCK" else "🟢 PASS"
    c = r["count"]
    lines = [f"### Quality gate `{r['tool']}` : {icon}", "",
             f"Bloquants : **{c['BLOCK']}** · Avertissements : {c['WARN']} · Derogations : {c['EXEMPTED']}", ""]
    if r["findings"]:
        lines += ["| Decision | Severite | Regle / CVE | Emplacement | Description |", "|---|---|---|---|---|"]
        order = {"BLOCK": 0, "EXEMPTED": 1, "WARN": 2}
        for f in sorted(r["findings"], key=lambda x: order[x["decision"]])[:30]:
            title = f["title"].replace("|", "/")[:90]
            lines.append(f"| {f['decision']} | {f['severity']} | {f['rule']} | `{f['location']}` | {title} |")
    lines += [f"- ⚠️ {p}" for p in r["problems"]]
    return "\n".join(lines) + "\n"


def write_html(r, path):
    color = {"BLOCK": "#c0392b", "WARN": "#e67e22", "EXEMPTED": "#2980b9"}
    rows = "".join(
        f"<tr><td style='color:{color[f['decision']]}'><b>{f['decision']}</b></td><td>{f['severity']}</td>"
        f"<td>{html.escape(f['rule'])}</td><td>{html.escape(f['location'])}</td><td>{html.escape(f['title'])}</td>"
        f"<td>{html.escape(f.get('exemption') or f.get('fixed_version') or '')}</td></tr>" for f in r["findings"])
    problems = "".join(f"<li>{html.escape(p)}</li>" for p in r["problems"])
    vcol = "#c0392b" if r["verdict"] == "BLOCK" else "#27ae60"
    Path(path).write_text(f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Gate {r['tool']}</title><style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #ddd;padding:6px;text-align:left}}
th{{background:#f4f4f4}}.v{{display:inline-block;padding:6px 16px;color:#fff;background:{vcol};border-radius:6px}}</style>
</head><body><h1>Quality gate {r['tool']} <span class="v">{r['verdict']}</span></h1>
<p>{dt.datetime.now():%Y-%m-%d %H:%M} - commit {html.escape(os.environ.get('GITHUB_SHA', 'local')[:8])}</p>
<ul>{problems}</ul><table><tr><th>Decision</th><th>Severite</th><th>Regle / CVE</th><th>Emplacement</th>
<th>Description</th><th>Derogation / version corrigee</th></tr>{rows}</table></body></html>""", encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["check"])
    ap.add_argument("--tool", required=True, choices=list(REPORT_FILES))
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--policy", default="security/policy.yml")
    ap.add_argument("--exemptions", default="security/exemptions.yml")
    args = ap.parse_args(argv)

    result = check(args.tool, args.reports, load_yaml(args.policy), load_yaml(args.exemptions))
    print_console(result)
    Path(args.reports).mkdir(parents=True, exist_ok=True)
    Path(args.reports, f"gate-{args.tool}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False),
                                                           encoding="utf-8")
    write_html(result, Path(args.reports, f"gate-{args.tool}.html"))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(markdown(result))
    return 1 if result["verdict"] == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
