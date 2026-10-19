import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "app"))

_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "test.db")
# Variable que l'application corrigée est censée lire (adaptez si besoin)
os.environ.setdefault("SECRET_KEY", "test-only-secret-not-for-prod")
# The test suite logs in many times in a row: raise the brute force limit for tests only
os.environ.setdefault("LOGIN_RATE_LIMIT", "100/minute")
# The tests log in as admin with this exact password: always force it for the test
# database, whatever ADMIN_PASSWORD the developer has in their own environment
os.environ["ADMIN_PASSWORD"] = "admin123"

import app as shop  # noqa: E402


@pytest.fixture()
def client():
    shop.init_db()
    # https:// pour que les cookies "Secure" soient renvoyés ; les 500 sont renvoyés au lieu d'être levés
    return TestClient(shop.app, base_url="https://testserver", raise_server_exceptions=False)
