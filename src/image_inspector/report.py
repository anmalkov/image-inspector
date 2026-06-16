"""Load and query the Trivy vulnerability report shipped with the package.

The report is produced nightly by :mod:`image_inspector.scanner`, committed to
the repo as ``data/report.json`` and bundled with the package. The interactive
inspector loads it once and looks up the resolved image by its (immutable)
digest. Missing or malformed data degrades to an empty report rather than
raising, so the picker always keeps working.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from importlib import resources

SCHEMA_VERSION = 2
_REPORT_RESOURCE = "report.json"

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


@dataclass(frozen=True)
class VulnerabilityReport:
    """A loaded scan report: metadata plus per-digest vulnerability counts."""

    generated_at: datetime | None = None
    trivy_version: str | None = None
    trivy_db_updated_at: datetime | None = None
    images: dict[str, ImageVulnerabilities] = None  # type: ignore[assignment]

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


def load_report() -> VulnerabilityReport:
    """Load the packaged ``report.json``; return an empty report on any failure."""
    try:
        raw = resources.files(f"{__package__}.data").joinpath(_REPORT_RESOURCE).read_text("utf-8")
        return VulnerabilityReport.from_dict(json.loads(raw))
    except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError, OSError):
        return VulnerabilityReport.empty()
