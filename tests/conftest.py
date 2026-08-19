"""Shared test isolation fixtures."""

import importlib

import pytest


@pytest.fixture(autouse=True)
def isolate_job_storage(tmp_path):
    """Never let endpoint tests enqueue synthetic jobs in the production DB."""
    web_app = importlib.import_module("ip2domain.web.routers.common")
    original_path = web_app.storage.db_path
    stores = (
        web_app.JOBS,
        web_app.VULN_JOBS,
        web_app.REMOTE_DESKTOP_JOBS,
        web_app.CAMERA_JOBS,
        web_app.CENTRA_JOBS,
    )
    web_app.storage.db_path = str(tmp_path / "test-jobs.db")
    web_app.storage._init_db()
    for store in stores:
        store._mem.clear()
    web_app.CENTRA_PERSON_JOBS.clear()
    web_app.CAMERA_CANCEL_EVENTS.clear()
    web_app.IP_CAMERA_CONNECTIONS.clear()
    yield
    for store in stores:
        store._mem.clear()
    web_app.CENTRA_PERSON_JOBS.clear()
    web_app.CAMERA_CANCEL_EVENTS.clear()
    web_app.IP_CAMERA_CONNECTIONS.clear()
    web_app.storage.db_path = original_path
