"""Unit tests for UI helpers."""

from image_inspector.ui import format_size


def test_format_size_units():
    assert format_size(None) == "unknown"
    assert format_size(0) == "0 B"
    assert format_size(512) == "512 B"
    assert format_size(1024) == "1.0 KB"
    assert format_size(20393993) == "19.4 MB"
    assert format_size(3 * 1024**3) == "3.0 GB"
