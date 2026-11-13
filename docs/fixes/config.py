"""Configuration de l'application."""
import os
import tempfile
from pathlib import Path

# CORRECTIF (CWE-798) : aucun secret dans le code, lecture depuis l'environnement
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

DATABASE_PATH = os.environ.get("DATABASE_PATH", str(Path(tempfile.gettempdir()) / "facturation.db"))
