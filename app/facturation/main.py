"""API de facturation (FastAPI + SQLite)."""
import subprocess

from fastapi import FastAPI, Header, HTTPException, Request

from . import db

app = FastAPI(title="facturation-api", version="2.0.0")
db.init_db()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """En-tetes de securite HTTP sur toutes les reponses (DAST / ZAP)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


def current_user(api_key: str | None) -> dict:
    """Authentification par cle API (en-tete X-API-Key)."""
    conn = db.connect()
    row = conn.execute("SELECT id, name FROM users WHERE api_key = ?", (api_key,)).fetchone()
    conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Cle API invalide")
    return dict(row)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/invoices")
def list_invoices(x_api_key: str | None = Header(default=None)) -> list[dict]:
    user = current_user(x_api_key)
    conn = db.connect()
    rows = conn.execute("SELECT * FROM invoices WHERE owner_id = ?", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/invoices/search")
def search_invoices(customer: str, x_api_key: str | None = Header(default=None)) -> list[dict]:
    user = current_user(x_api_key)
    conn = db.connect()
    rows = conn.execute(
        f"SELECT * FROM invoices WHERE owner_id = {user['id']} AND customer LIKE '%{customer}%'"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/admin/ping")
def admin_ping(host: str) -> dict:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return {"host": host, "reachable": result.returncode == 0, "output": result.stdout}
