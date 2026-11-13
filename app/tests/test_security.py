"""Tests de non-regression securite : un test par faille (1 a 4).
Chaque test REJOUE l'attaque ; il echoue si la faille est reintroduite."""
import importlib
from importlib.metadata import version
from pathlib import Path

from facturation import config
from tests.conftest import ALICE

URLLIB3_FIXED = (2, 8, 0)  # premiere version sans CVE HIGH connue (Trivy)


def test_no_hardcoded_secret(monkeypatch):
    # Faille 1 : un attaquant lit le depot et recupere une cle AWS ecrite en clair
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    importlib.reload(config)
    key_in_code = "AKIA" in Path(config.__file__).read_text(encoding="utf-8")
    assert not key_in_code, "cle AWS ecrite en dur dans config.py"
    assert not (config.AWS_ACCESS_KEY_ID or config.AWS_SECRET_ACCESS_KEY), "cles AWS non lues depuis l'environnement"


def test_sql_injection_blocked(client):
    # Faille 2 : injection SQL "%' OR 1=1 --" pour lire les factures de Bob
    r = client.get("/invoices/search", params={"customer": "%' OR 1=1 --"}, headers=ALICE)
    assert r.status_code == 200
    assert all(i["owner_id"] != 2 for i in r.json())


def test_command_injection_blocked(client):
    # Faille 3 : injection de commande "127.0.0.1;id" sur /admin/ping
    params = {"host": "127.0.0.1;id"}
    anonymous = client.get("/admin/ping", params=params)
    alice = client.get("/admin/ping", params=params, headers=ALICE)
    assert anonymous.status_code == 401
    assert alice.status_code == 400
    assert "uid=" not in anonymous.text + alice.text


def test_dependency_is_patched():
    # Faille 4 : urllib3 vulnerable (CVE-2021-33503, ReDoS) installe dans l'application
    installed = tuple(int(x) for x in version("urllib3").split(".")[:3])
    assert installed >= URLLIB3_FIXED, f"urllib3 {version('urllib3')} est vulnerable"
