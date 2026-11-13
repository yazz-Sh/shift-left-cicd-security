import pytest
from fastapi.testclient import TestClient

from facturation.main import app


@pytest.fixture
def client():
    return TestClient(app)


ALICE = {"X-API-Key": "alice-demo-key"}
