"""Integration checks against the real build artifacts bundled in the package.

These are deselected from the default unit run (``-m "not integration"`` in
``pyproject.toml``) because they depend on the offline ``report.json`` snapshot, which
is *not* committed to the repo -- it is fetched from GitHub Pages into the package by
the release workflow. The release runs ``pytest -m integration`` after that snapshot, so
a release fails if the bundled offline fallback is missing or unreadable.
"""

import pytest

from image_inspector.report import ReportSource, load_report

pytestmark = pytest.mark.integration


def test_bundled_report_is_loadable():
    # The autouse fixture in tests/conftest.py forces the offline path, so this loads
    # the packaged report.json rather than hitting the network.
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.images, "bundled report loaded but contains no images"
