"""Tests fonctionnels."""
from tests.conftest import ALICE


def test_health(client):
    # Verifie que l'API repond (sonde de deploiement)
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_list_own_invoices(client):
    # Alice ne voit que ses 2 factures, jamais celle de Bob
    r = client.get("/invoices", headers=ALICE)
    assert r.status_code == 200
    assert sorted(i["id"] for i in r.json()) == [1, 2]
    assert all(i["owner_id"] == 1 for i in r.json())
