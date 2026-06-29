"""Load and query the Trivy vulnerability report.

The report is produced nightly by :mod:`image_inspector.scanner` and published to
GitHub Pages; a release-time snapshot is also bundled with the package as
``data/report.json.gz``. At runtime the inspector prefers the **latest report fetched
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

import gzip
import json
import os
import re
import zlib
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from importlib import resources
from pathlib import Path

import httpx

SCHEMA_VERSION = 3
_REPORT_RESOURCE = "report.json.gz"
_DETAILS_RESOURCE = "details.json.gz"
_PAGES_URL = "https://anmalkov.github.io/image-inspector/report.json.gz"
_DETAILS_PAGES_URL = "https://anmalkov.github.io/image-inspector/details.json.gz"
# Short timeout so the picker never hangs at startup when offline.
_FETCH_TIMEOUT = httpx.Timeout(3.0, connect=2.0)
_CACHE_FILENAME = "report-cache.json"
_TRUTHY = {"1", "true", "yes", "on"}

# PyPI lookup used to tell the user a newer tool release is available. Kept on a short
# timeout and fully offline-safe so it can never hang or crash startup.
_DISTRIBUTION_NAME = "base-image-inspector"
_PYPI_URL = f"https://pypi.org/pypi/{_DISTRIBUTION_NAME}/json"
_PYPI_TIMEOUT = httpx.Timeout(3.0, connect=2.0)

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


def _strip_digest(digest: str) -> str:
    """Drop the ``sha256:`` algorithm prefix so digests index consistently.

    The v3 report stores ``d`` without the prefix, but callers look up the full
    ``sha256:<hex>`` form, so both the index keys and lookups are normalised here.
    """
    return digest[7:] if digest.startswith("sha256:") else digest


def _decode_report_bytes(content: bytes) -> str | None:
    """Decode report bytes to text: gunzip when gzipped, else assume UTF-8 JSON.

    Tolerant by design — we now request the gzipped resource, but a plain-JSON body must
    still load (e.g. transparent transport decompression or a transition window). Returns
    ``None`` if the bytes are a corrupt gzip stream or aren't valid UTF-8 after decoding.
    """
    if content[:2] == b"\x1f\x8b":
        try:
            content = gzip.decompress(content)
        except (OSError, EOFError, zlib.error):
            return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
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

    @classmethod
    def from_compact(
        cls, counts: object, *, scanned_at: datetime | None = None
    ) -> ImageVulnerabilities:
        """Build counts from a v3 ``c`` array ``[crit, high, medium, low, unknown]``.

        ``total`` is derived (``sum(c)``) rather than stored. Shorter/longer arrays are
        tolerated by padding/truncating to five severities. ``scanned_at`` carries the
        report's ``generated_at`` (the per-scan time lives in the header in v3, not per
        digest).

        A missing or wrong-typed ``c`` (e.g. ``None`` or a dict) is a structurally
        malformed entry, not "zero vulnerabilities", so it raises ``TypeError`` to let
        ``_build_report`` treat the payload as unusable and fall back rather than silently
        under-reporting.
        """
        if not isinstance(counts, (list, tuple)):
            raise TypeError(f"v3 'c' must be a list, got {type(counts).__name__}")
        nums = [int(v) for v in list(counts)[:5]]
        nums += [0] * (5 - len(nums))
        crit, high, medium, low, unknown = nums
        return cls(
            critical=crit,
            high=high,
            medium=medium,
            low=low,
            unknown=unknown,
            total=crit + high + medium + low + unknown,
            scanned_at=scanned_at,
        )


class ReportSource(StrEnum):
    """Where a loaded report came from (used to show data freshness in the UI)."""

    ONLINE = "online"
    OFFLINE = "offline"
    OUTDATED = "outdated"


@dataclass(frozen=True)
class VulnerabilityReport:
    """A loaded scan report: metadata plus per-digest vulnerability counts."""

    generated_at: datetime | None = None
    trivy_version: str | None = None
    trivy_db_updated_at: datetime | None = None
    images: dict[str, ImageVulnerabilities] = None  # type: ignore[assignment]
    latest: dict[str, ImageVulnerabilities] = None  # type: ignore[assignment]
    source: ReportSource | None = None

    def __post_init__(self) -> None:
        if self.images is None:
            object.__setattr__(self, "images", {})
        if self.latest is None:
            object.__setattr__(self, "latest", {})

    def lookup_digest(self, digest: str | None) -> ImageVulnerabilities | None:
        """Return counts for an image ``digest``, or ``None`` if not scanned.

        Accepts either the bare hex digest or the full ``sha256:<hex>`` form; the
        ``sha256:`` prefix is stripped to match the index built at load time.
        """
        if not digest:
            return None
        return self.images.get(_strip_digest(digest))

    def latest_for_tag(self, reference: str | None) -> ImageVulnerabilities | None:
        """Return counts for a tag's current (head) digest, or ``None`` if unknown."""
        if not reference:
            return None
        return self.latest.get(reference)

    @classmethod
    def empty(cls) -> VulnerabilityReport:
        return cls()

    @classmethod
    def from_dict(cls, data: dict) -> VulnerabilityReport:
        """Build a report from the v3 ``tags`` payload.

        The per-digest index (``images``) and the per-tag head index (``latest``) are both
        derived from each tag's newest-first ``history``. Each digest's ``scanned_at`` is
        the report's ``generated_at``, since v3 keeps the scan time only in the header.
        """
        generated_at = _parse_dt(data.get("generated_at"))
        images: dict[str, ImageVulnerabilities] = {}
        latest: dict[str, ImageVulnerabilities] = {}
        tags = data.get("tags")
        if isinstance(tags, dict):
            for reference, tag_data in tags.items():
                history = tag_data.get("history") if isinstance(tag_data, dict) else None
                if not isinstance(history, list):
                    continue
                for index, entry in enumerate(history):
                    if not isinstance(entry, dict):
                        continue
                    digest = entry.get("d")
                    if not isinstance(digest, str) or not digest:
                        continue
                    vuln = ImageVulnerabilities.from_compact(
                        entry.get("c"), scanned_at=generated_at
                    )
                    images[_strip_digest(digest)] = vuln
                    if index == 0 and isinstance(reference, str):
                        latest[reference] = vuln
        return cls(
            generated_at=generated_at,
            trivy_version=data.get("trivy_version"),
            trivy_db_updated_at=_parse_dt(data.get("trivy_db_updated_at")),
            images=images,
            latest=latest,
        )


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _report_url() -> str:
    return os.environ.get("IMAGE_INSPECTOR_REPORT_URL", "").strip() or _PAGES_URL


def _is_windows() -> bool:
    return os.name == "nt"


def _default_cache_dir() -> Path:
    """Per-user cache directory (never world-writable, unlike the system temp dir)."""
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    if xdg:
        return Path(xdg) / "image-inspector"
    if _is_windows():
        local = os.environ.get("LOCALAPPDATA", "").strip()
        if local:
            return Path(local) / "image-inspector"
    # ``expanduser`` returns "~" unchanged when home is undeterminable, whereas
    # ``Path.home()`` raises ``RuntimeError`` and would break the never-crash guarantee.
    return Path(os.path.expanduser("~")) / ".cache" / "image-inspector"


def _cache_path() -> Path:
    override = os.environ.get("IMAGE_INSPECTOR_CACHE_DIR", "").strip()
    base = Path(override) if override else _default_cache_dir()
    return base / _CACHE_FILENAME


def _read_cache(url: str) -> tuple[str | None, str | None]:
    """Return the cached ``(etag, body)`` for ``url`` (``(None, None)`` if absent).

    Never raises: a missing, unreadable, non-UTF-8, malformed, or wrongly-typed cache is
    treated as a cache miss so cache corruption can never break the loader.
    """
    try:
        # ValueError covers both UnicodeDecodeError (non-UTF-8) and JSONDecodeError.
        cached = json.loads(_cache_path().read_text("utf-8"))
    except (OSError, ValueError):
        return None, None
    if not isinstance(cached, dict) or cached.get("url") != url:
        return None, None
    etag = cached.get("etag")
    body = cached.get("body")
    return (etag if isinstance(etag, str) else None, body if isinstance(body, str) else None)


def _write_cache(url: str, etag: str | None, body: str) -> None:
    path = _cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps({"url": url, "etag": etag, "body": body}), encoding="utf-8")
    except OSError:
        pass


def _validate_payload(body: str) -> dict | None:
    """Parse ``body`` and return it only if it is a usable report payload.

    Requires a dict with the supported ``schema_version`` and a dict ``tags`` map, so
    any malformed payload degrades to the packaged fallback instead of crashing
    ``VulnerabilityReport.from_dict``.
    """
    if not isinstance(body, str):
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return None
    if not isinstance(data.get("tags"), dict):
        return None
    return data


def _schema_is_newer(body: str) -> bool:
    """Return ``True`` if ``body`` is a report whose ``schema_version`` exceeds ours.

    This is the "outdated tool" signal: the online report parsed fine but uses a schema
    newer than this build supports, so the published data exists but we can't read it.
    Any non-dict / unparsable / non-integer / not-newer payload returns ``False``.
    """
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    version = data.get("schema_version")
    # bool is an int subclass; exclude it so ``True``/``False`` never count as a version.
    if not isinstance(version, int) or isinstance(version, bool):
        return False
    return version > SCHEMA_VERSION


@dataclass(frozen=True)
class _FetchOutcome:
    """Result of an online fetch attempt.

    ``payload`` is a usable, schema-matching report (or ``None``); ``schema_too_new`` is
    ``True`` when the online report parsed but uses a newer-than-supported schema, which
    the caller surfaces as an outdated-tool warning.
    """

    payload: dict | None = None
    schema_too_new: bool = False


def _fetch_report() -> _FetchOutcome:
    """Fetch the hosted report, honouring ``ETag`` revalidation.

    Returns a usable, schema-validated payload when available. When the report instead
    uses a newer-than-supported schema, returns an outcome flagged ``schema_too_new`` so
    the caller can fall back to the packaged copy *and* warn that the tool is outdated.
    Any other failure (offline, timeout, non-200, malformed JSON, older schema) yields an
    empty outcome so the caller falls back quietly.
    """
    url = _report_url()
    etag, cached_body = _read_cache(url)
    headers = {"If-None-Match": etag} if etag else {}
    try:
        response = httpx.get(url, headers=headers, timeout=_FETCH_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return _FetchOutcome()

    # A 304 means our cached body is still current. The cache holds the already-decoded
    # (decompressed) text, but a newer tool version could have populated the shared cache
    # with a newer-schema body, so apply the same schema check as the 200 path.
    if response.status_code == 304 and cached_body is not None:
        cached_payload = _validate_payload(cached_body)
        if cached_payload is not None:
            return _FetchOutcome(payload=cached_payload)
        return _FetchOutcome(schema_too_new=_schema_is_newer(cached_body))
    if response.status_code != 200:
        return _FetchOutcome()

    body = _decode_report_bytes(response.content)
    if body is None:
        return _FetchOutcome()
    payload = _validate_payload(body)
    if payload is not None:
        _write_cache(url, response.headers.get("ETag"), body)
        return _FetchOutcome(payload=payload)
    return _FetchOutcome(schema_too_new=_schema_is_newer(body))


def _load_packaged() -> dict | None:
    """Load, parse and validate the packaged ``report.json.gz`` (``None`` on any failure).

    Reuses ``_decode_report_bytes``/``_validate_payload`` so a packaged copy that is a
    corrupt gzip, non-UTF-8, malformed, of an unsupported schema, or whose ``tags`` map is
    not a dict is treated as a load miss instead of crashing
    ``VulnerabilityReport.from_dict``.
    """
    try:
        raw = resources.files(f"{__package__}.data").joinpath(_REPORT_RESOURCE).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None
    body = _decode_report_bytes(raw)
    if body is None:
        return None
    return _validate_payload(body)


def _build_report(payload: dict, source: ReportSource) -> VulnerabilityReport | None:
    """Build a ``VulnerabilityReport`` from ``payload``, or ``None`` if it can't.

    ``_validate_payload`` only guarantees ``images`` is a dict; individual entries (or
    count/timestamp fields) can still have unexpected types that raise inside
    ``from_dict``/``ImageVulnerabilities.from_dict``. Treat any such error as a load
    failure so the caller can fall back instead of crashing the picker at startup.
    """
    try:
        return replace(VulnerabilityReport.from_dict(payload), source=source)
    except (TypeError, ValueError, AttributeError, KeyError):
        return None


def load_report() -> VulnerabilityReport:
    """Load the vulnerability report: online-first, packaged fallback, empty on failure.

    Prefers the report hosted on GitHub Pages; on any network failure (or when
    ``IMAGE_INSPECTOR_OFFLINE`` is set) falls back to the packaged ``report.json.gz``.
    Returns an empty report if no usable data can be loaded at all, so the picker
    always keeps working.

    When the online report uses a schema newer than this build supports, the packaged
    fallback is marked :attr:`ReportSource.OUTDATED` so the UI can warn that the installed
    tool is behind the published data; other fallbacks stay the quiet
    :attr:`ReportSource.OFFLINE` path.
    """
    schema_too_new = False
    if not _env_truthy("IMAGE_INSPECTOR_OFFLINE"):
        outcome = _fetch_report()
        if outcome.payload is not None:
            report = _build_report(outcome.payload, ReportSource.ONLINE)
            if report is not None:
                return report
        schema_too_new = outcome.schema_too_new

    packaged = _load_packaged()
    if packaged is not None:
        source = ReportSource.OUTDATED if schema_too_new else ReportSource.OFFLINE
        report = _build_report(packaged, source)
        if report is not None:
            return report

    return VulnerabilityReport.empty()


def latest_pypi_version() -> str | None:
    """Return the latest published ``base-image-inspector`` version on PyPI, or ``None``.

    Used to tell the user that a newer tool release is available. Skips the lookup
    entirely when ``IMAGE_INSPECTOR_OFFLINE`` is set, and is otherwise fully offline-safe:
    a short timeout plus any network/parse error degrades to ``None`` so it can never hang
    or crash startup.
    """
    if _env_truthy("IMAGE_INSPECTOR_OFFLINE"):
        return None
    try:
        response = httpx.get(_PYPI_URL, timeout=_PYPI_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("info")
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    return version if isinstance(version, str) and version else None


# --- Lazy critical/high details sidecar -----------------------------------------------------
#
# The details sidecar is loaded only when the --dockerfile flow computes the "upgrading fixes
# these" diff, so the always-loaded counts report stays small. It stores critical+high CVEs
# only; medium/low/unknown remain counts-only. The format is a deduped ``vulns`` table plus a
# ``digests`` map of stripped digest -> integer indices into that table.

_DETAILS_SCHEMA_VERSION = SCHEMA_VERSION


@dataclass(frozen=True)
class Vulnerability:
    """One deduped critical/high CVE record (no titles/URLs/CVSS — derivable from ``id``)."""

    id: str
    pkg: str = ""
    sev: str = ""  # "C" or "H"
    fix: str | None = None  # fixed version, or None when unfixed


@dataclass(frozen=True)
class DetailsReport:
    """A loaded details sidecar: per-digest critical/high CVE sets and fix-diff helpers."""

    vulns: tuple[Vulnerability, ...] = ()
    digests: dict[str, tuple[int, ...]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.digests is None:
            object.__setattr__(self, "digests", {})

    @classmethod
    def empty(cls) -> DetailsReport:
        return cls()

    @classmethod
    def from_dict(cls, data: dict) -> DetailsReport:
        vulns: list[Vulnerability] = []
        for record in data.get("vulns") or []:
            if not isinstance(record, dict):
                continue
            cve_id = record.get("id")
            if not isinstance(cve_id, str) or not cve_id:
                continue
            fix = record.get("fix")
            pkg = record.get("pkg")
            sev = record.get("sev")
            vulns.append(
                Vulnerability(
                    id=cve_id,
                    pkg=pkg if isinstance(pkg, str) else "",
                    sev=sev if isinstance(sev, str) else "",
                    fix=fix if isinstance(fix, str) and fix else None,
                )
            )
        digests: dict[str, tuple[int, ...]] = {}
        raw = data.get("digests")
        if isinstance(raw, dict):
            for digest, indices in raw.items():
                if not isinstance(digest, str) or not isinstance(indices, list):
                    continue
                kept = tuple(i for i in indices if isinstance(i, int) and 0 <= i < len(vulns))
                digests[_strip_digest(digest)] = kept
        return cls(vulns=tuple(vulns), digests=digests)

    def cve_set(self, digest: str | None) -> frozenset[Vulnerability]:
        """Critical/high CVEs for a digest (``sha256:`` prefix tolerated); empty if unknown."""
        if not digest:
            return frozenset()
        return frozenset(self.vulns[i] for i in self.digests.get(_strip_digest(digest), ()))

    def fix_diff(
        self, pinned: str | None, latest: str | None
    ) -> tuple[frozenset[Vulnerability], frozenset[Vulnerability]]:
        """Return ``(fixed, still_present)`` for upgrading from ``pinned`` to ``latest``.

        ``fixed`` are critical/high CVEs in the pinned digest gone in the latest; matched by
        CVE id so a CVE present in both (any pkg) counts as still-present. ``still_present`` are
        the pinned CVEs whose id is also in the latest digest.
        """
        pinned_set = self.cve_set(pinned)
        latest_ids = {v.id for v in self.cve_set(latest)}
        fixed = frozenset(v for v in pinned_set if v.id not in latest_ids)
        still_present = frozenset(v for v in pinned_set if v.id in latest_ids)
        return fixed, still_present


def _details_url() -> str:
    return os.environ.get("IMAGE_INSPECTOR_DETAILS_URL", "").strip() or _DETAILS_PAGES_URL


def _validate_details(body: str) -> dict | None:
    """Parse ``body`` and return it only if it is a usable details sidecar payload."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("schema_version") != _DETAILS_SCHEMA_VERSION:
        return None
    if not isinstance(data.get("vulns"), list) or not isinstance(data.get("digests"), dict):
        return None
    return data


def _fetch_details() -> dict | None:
    """Fetch the hosted details sidecar; ``None`` on any failure (offline-safe, no caching)."""
    try:
        response = httpx.get(_details_url(), timeout=_FETCH_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    body = _decode_report_bytes(response.content)
    if body is None:
        return None
    return _validate_details(body)


def _load_packaged_details() -> dict | None:
    """Load + validate the packaged ``details.json.gz`` (``None`` on any failure)."""
    try:
        raw = resources.files(f"{__package__}.data").joinpath(_DETAILS_RESOURCE).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None
    body = _decode_report_bytes(raw)
    if body is None:
        return None
    return _validate_details(body)


def load_details() -> DetailsReport:
    """Lazily load the critical/high details sidecar: online-first, packaged fallback, empty.

    Only the ``--dockerfile`` fix-diff needs this, so it is loaded on demand — never on the
    always-on interactive path. Like :func:`load_report` it prefers the GitHub Pages copy and
    falls back to the packaged snapshot (skipping the network when ``IMAGE_INSPECTOR_OFFLINE``
    is set), returning an empty report so callers can always degrade gracefully.
    """
    if not _env_truthy("IMAGE_INSPECTOR_OFFLINE"):
        payload = _fetch_details()
        if payload is not None:
            return DetailsReport.from_dict(payload)
    packaged = _load_packaged_details()
    if packaged is not None:
        return DetailsReport.from_dict(packaged)
    return DetailsReport.empty()
