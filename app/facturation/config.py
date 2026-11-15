"""Configuration de l'application."""
import os
import tempfile
from pathlib import Path

# Cles AWS du compte de stockage des factures
AWS_ACCESS_KEY_ID = "AKIAB2YYU4EZYUITLBM6"
AWS_SECRET_ACCESS_KEY = "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"

DATABASE_PATH = os.environ.get("DATABASE_PATH", str(Path(tempfile.gettempdir()) / "facturation.db"))
