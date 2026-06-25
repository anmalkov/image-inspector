"""Shared test fixtures."""

import pytest


@pytest.fixture(autouse=True)
def _offline_by_default(monkeypatch, tmp_path):
    """Keep the report loader offline unless a test opts into the online path.

    ``load_report()`` is online-first, so without this any test that exercises it
    would make a real network request to GitHub Pages. Tests that exercise the online
    path delete ``IMAGE_INSPECTOR_OFFLINE`` (and mock HTTP with respx) themselves.
    """
    monkeypatch.setenv("IMAGE_INSPECTOR_OFFLINE", "1")
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "report-cache"))
