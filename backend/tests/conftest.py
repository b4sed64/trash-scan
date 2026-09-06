"""Test fixtures.

Tests run against a throwaway SQLite database and never touch the network:
``enable_dns_resolution`` is off and scope tests inject a fake resolver.
"""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("TRASHSCAN_ENABLE_DNS_RESOLUTION", "false")
os.environ.setdefault("TRASHSCAN_SESSION_COOKIE_SECURE", "false")
os.environ.setdefault("TRASHSCAN_ARGON2_TIME_COST", "1")
os.environ.setdefault("TRASHSCAN_ARGON2_MEMORY_COST_KIB", "8192")
os.environ.setdefault("TRASHSCAN_ARGON2_PARALLELISM", "1")
os.environ.setdefault("TRASHSCAN_SCANNER_MODE", "fake")
os.environ.setdefault("TRASHSCAN_CELERY_TASK_ALWAYS_EAGER", "true")
os.environ["TRASHSCAN_RESULT_ROOT"] = tempfile.mkdtemp(prefix="trashscan_results_")

_DB_FD, _DB_PATH = tempfile.mkstemp(suffix=".sqlite3", prefix="trashscan_test_")
os.close(_DB_FD)
os.environ["TRASHSCAN_DATABASE_URL"] = f"sqlite+pysqlite:///{_DB_PATH}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def settings():
    get_settings.cache_clear()
    return get_settings()


def pytest_sessionfinish(session, exitstatus):
    try:
        os.unlink(_DB_PATH)
    except OSError:
        pass
