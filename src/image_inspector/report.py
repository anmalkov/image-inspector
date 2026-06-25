"""Load and query the Trivy vulnerability report.

The report is produced nightly by :mod:`image_inspector.scanner` and published to
GitHub Pages; a release-time snapshot is also bundled with the package as
``data/report.json``. At runtime the inspector prefers the **latest report fetched
from GitHub Pages** and falls back to the **packaged** copy when offline, so users see
fresh nightly data without waiting on a PyPI release. The interactive inspector loads
the report once and looks up the resolved image by its (immutable) digest. Missing or
malformed data degrades to an empty report rather than raising, so the picker always
keeps working.

Environment variables:

``IMAGE_INSPECTOR_OFFLINE``
    When set to a truthy value (``1``/``true``/``yes``/``on``), skip the network fetch
    and load the packaged copy directly.
``IMAGE_INSPECTOR_REPORT_URL``
    Override the URL the hosted report is fetched from.
``IMAGE_INSPECTOR_CACHE_DIR``
    Override the directory used to cache the fetched report for ``ETag`` revalidation.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from importlib import resources
from pathlib import Path

import httpx

SCHEMA_VERSION = 2
_REPORT_RESOURCE = "report.json"
_PAGES_URL = "https://anmalkov.github.io/image-inspector/report.json"
# Short timeout so the picker never hangs at startup when offline.
_FETCH_TIMEOUT = httpx.Timeout(3.0, connect=2.0)
_CACHE_FILENAME = "report-cache.json"
_TRUTHY = {"1", "true", "yes", "on"}

# Trivy emits nanosecond-precision timestamps (9 fractional digits) that
# datetime.fromisoformat cannot parse; trim fractional seconds to 6 digits.
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = _FRACTION_RE.sub(r"\1", value.replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


@dataclass(frozen=True)
class ImageVulnerabilities:
    """Vulnerability counts for a single scanned image digest."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total: int = 0
    scanned_at: datetime | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ImageVulnerabilities:
        return cls(
            critical=int(data.get("critical", 0)),
            high=int(data.get("high", 0)),
            medium=int(data.get("medium", 0)),
            low=int(data.get("low", 0)),
            unknown=int(data.get("unknown", 0)),
            total=int(data.get("total", 0)),
            scanned_at=_parse_dt(data.get("scanned_at")),
        )


class ReportSource(StrEnum):
    """Where a loaded report came from (used to show data freshness in the UI)."""

    ONLINE = "online"
    OFFLINE = "offline"


@dataclass(frozen=True)
class VulnerabilityReport:
    """A loaded scan report: metadata plus per-digest vulnerability counts."""

    generated_at: datetime | None = None
    trivy_version: str | None = None
    trivy_db_updated_at: datetime | None = None
    images: dict[str, ImageVulnerabilities] = None  # type: ignore[assignment]
    source: ReportSource | None = None

    def __post_init__(self) -> None:
        if self.images is None:
            object.__setattr__(self, "images", {})

    def lookup(self, digest: str | None) -> ImageVulnerabilities | None:
        """Return counts for an image ``digest``, or ``None`` if not scanned."""
        if not digest:
            return None
        return self.images.get(digest)

    @classmethod
    def empty(cls) -> VulnerabilityReport:
        return cls()

    @classmethod
    def from_dict(cls, data: dict) -> VulnerabilityReport:
        images = {
            digest: ImageVulnerabilities.from_dict(entry)
            for digest, entry in data.get("images", {}).items()
        }
        return cls(
            generated_at=_parse_dt(data.get("generated_at")),
            trivy_version=data.get("trivy_version"),
            trivy_db_updated_at=_parse_dt(data.get("trivy_db_updated_at")),
            images=images,
        )


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _report_url() -> str:
    return os.environ.get("IMAGE_INSPECTOR_REPORT_URL", "").strip() or _PAGES_URL


def _cache_path() -> Path:
    override = os.environ.get("IMAGE_INSPECTOR_CACHE_DIR", "").strip()
    base = Path(override) if override else Path(tempfile.gettempdir()) / "image-inspector"
    return base / _CACHE_FILENAME


def _read_cache(url: str) -> tuple[str | None, str | None]:
    """Return the cached ``(etag, body)`` for ``url`` (``(None, None)`` if absent)."""
    try:
        cached = json.loads(_cache_path().read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    if not isinstance(cached, dict) or cached.get("url") != url:
        return None, None
    return cached.get("etag"), cached.get("body")


def _write_cache(url: str, etag: str | None, body: str) -> None:
    path = _cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"url": url, "etag": etag, "body": body}), encoding="utf-8")
    except OSError:
        pass


def _validate_payload(body: str) -> dict | None:
    """Parse ``body`` and return it only if it is a dict with the supported schema."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return None
    return data


def _fetch_report() -> dict | None:
    """Fetch the hosted report, honouring ``ETag`` revalidation.

    Returns the parsed, schema-validated payload, or ``None`` on any failure (offline,
    timeout, non-200, malformed JSON, schema mismatch) so the caller can fall back to
    the packaged copy.
    """
    url = _report_url()
    etag, cached_body = _read_cache(url)
    headers = {"If-None-Match": etag} if etag else {}
    try:
        response = httpx.get(
            url, headers=headers, timeout=_FETCH_TIMEOUT, follow_redirects=True
        )
    except httpx.HTTPError:
        return None

    if response.status_code == 304 and cached_body is not None:
        return _validate_payload(cached_body)
    if response.status_code != 200:
        return None

    body = response.text
    payload = _validate_payload(body)
    if payload is not None:
        _write_cache(url, response.headers.get("ETag"), body)
    return payload


def _load_packaged() -> dict | None:
    """Load and parse the packaged ``report.json`` (``None`` on any failure)."""
    try:
        raw = resources.files(f"{__package__}.data").joinpath(_REPORT_RESOURCE).read_text("utf-8")
        data = json.loads(raw)
    except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def load_report() -> VulnerabilityReport:
    """Load the vulnerability report: online-first, packaged fallback, empty on failure.

    Prefers the report hosted on GitHub Pages; on any network failure (or when
    ``IMAGE_INSPECTOR_OFFLINE`` is set) falls back to the packaged ``report.json``.
    Returns an empty report if no usable data can be loaded at all, so the picker
    always keeps working.
    """
    if not _env_truthy("IMAGE_INSPECTOR_OFFLINE"):
        payload = _fetch_report()
        if payload is not None:
            return replace(VulnerabilityReport.from_dict(payload), source=ReportSource.ONLINE)

    packaged = _load_packaged()
    if packaged is not None:
        return replace(VulnerabilityReport.from_dict(packaged), source=ReportSource.OFFLINE)

    return VulnerabilityReport.empty()
