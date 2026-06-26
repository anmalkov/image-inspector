"""Integration checks that run against the report snapshot in the source tree.

These are deselected from the default unit run (``-m "not integration"`` in
``pyproject.toml``) because they depend on ``src/image_inspector/data/report.json.gz``, which
is *not* committed to the repo -- it is fetched from GitHub Pages into the working tree by
the release workflow (and can be downloaded locally; see ``docs/development.md``). The
release runs ``pytest -m integration`` from the source checkout, *before* ``uv build``, so
a release fails if that snapshot is missing or unreadable. (Verifying the built wheel
itself is a separate post-build step in the release workflow.)
"""

import pytest

from image_inspector.report import ReportSource, load_report

pytestmark = pytest.mark.integration


def test_bundled_report_is_loadable():
    # The autouse fixture in tests/conftest.py forces the offline path, so this loads
    # the packaged report.json.gz rather than hitting the network.
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.images, "bundled report loaded but contains no images"
