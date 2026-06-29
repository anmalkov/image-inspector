"""Compare a Dockerfile's pinned base images against the latest tracked digests.

This wires the pure :mod:`image_inspector.dockerfile` ``FROM`` parser to the loaded
:class:`~image_inspector.report.VulnerabilityReport` (counts) and the lazy
:class:`~image_inspector.report.DetailsReport` (critical/high CVEs). For each ``FROM`` it
reports the pinned digest's vulnerability counts alongside the tag's latest tracked digest,
and computes the critical/high **fix-diff** (what upgrading to latest would fix vs. what
would still be present).

We never scan locally, so every lookup degrades gracefully: an untracked pinned digest
falls back to the latest tracked one, an untracked tag is reported plainly, and ``FROM``
lines that reference an earlier build stage or an unresolved ``ARG`` are skipped with a
note. Output formatting lives elsewhere (``ui``); this module is pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .dockerfile import FromStage, parse_dockerfile_from
from .report import DetailsReport, ImageVulnerabilities, Vulnerability, VulnerabilityReport

# Docker Hub is the implicit registry; its official images live under ``library/``. A
# Dockerfile may spell the same image as ``python``, ``library/python`` or
# ``docker.io/library/python`` -- all of which map to the report key ``python``.
_DOCKER_HUB_HOSTS = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")
_DEFAULT_TAG = "latest"


def normalize_image(image: str) -> str:
    """Canonicalise a Docker Hub image reference to the report's key form.

    Strips an explicit Docker Hub registry host and a leading ``library/`` namespace so
    ``docker.io/library/python`` and ``library/python`` both become ``python``. Images on
    other registries (e.g. ``mcr.microsoft.com/...``) are returned unchanged.
    """
    result = image
    for host in _DOCKER_HUB_HOSTS:
        if result.startswith(host):
            result = result[len(host) :]
            break
    # Only strip ``library/`` when it is the whole namespace (no further registry host),
    # i.e. there is exactly one path segment after it.
    if result.startswith("library/") and result.count("/") == 1:
        result = result[len("library/") :]
    return result


class StageStatus(StrEnum):
    """Outcome of inspecting a single ``FROM`` stage against the report."""

    # A digest is pinned and we have scan data for it.
    PINNED_KNOWN = "pinned_known"
    # A digest is pinned but untracked (EOL/aged out); latest is shown instead.
    PINNED_UNKNOWN = "pinned_unknown"
    # No digest pinned, but the tag's latest digest is tracked.
    TAG_KNOWN = "tag_known"
    # Neither the pinned digest nor the tag is tracked at all.
    UNTRACKED = "untracked"
    # The FROM references an earlier stage or an unresolved ARG: nothing to look up.
    SKIPPED = "skipped"


@dataclass(frozen=True)
class StageInspection:
    """The comparison result for one ``FROM`` stage."""

    stage: FromStage
    status: StageStatus
    reference: str | None = None
    pinned_counts: ImageVulnerabilities | None = None
    latest_counts: ImageVulnerabilities | None = None
    latest_digest: str | None = None
    fixed: tuple[Vulnerability, ...] = ()
    still_present: tuple[Vulnerability, ...] = ()
    note: str | None = None

    @property
    def pinned_digest(self) -> str | None:
        """The digest pinned in the ``FROM`` line, if any (verbatim, ``sha256:`` form)."""
        return self.stage.digest


def _sorted_vulns(vulns: frozenset[Vulnerability]) -> tuple[Vulnerability, ...]:
    """Order CVEs deterministically: critical before high, then by id."""
    return tuple(sorted(vulns, key=lambda v: (v.sev != "C", v.id)))


def inspect_stage(
    stage: FromStage,
    report: VulnerabilityReport,
    details: DetailsReport,
) -> StageInspection:
    """Inspect a single parsed ``FROM`` stage, comparing pinned vs. latest.

    ``report`` supplies counts (all severities) for the pinned digest and the tag's latest
    digest; ``details`` supplies the critical/high CVE sets used for the fix-diff. The
    fix-diff is only computed when both a known pinned digest and a tracked latest digest
    are available.
    """
    if stage.references_stage:
        return StageInspection(
            stage=stage,
            status=StageStatus.SKIPPED,
            note=f"references build stage '{stage.stage_ref}'",
        )
    if stage.unresolved_args:
        names = ", ".join(stage.unresolved_args)
        return StageInspection(
            stage=stage,
            status=StageStatus.SKIPPED,
            note=f"unresolved ARG(s): {names}",
        )
    if not stage.image:
        return StageInspection(
            stage=stage,
            status=StageStatus.SKIPPED,
            note="no image reference",
        )

    image = normalize_image(stage.image)
    tag = stage.tag or _DEFAULT_TAG
    reference = f"{image}:{tag}"

    latest_counts = report.latest_for_tag(reference)
    latest_digest = report.latest_digest_for_tag(reference)

    if stage.digest:
        pinned_counts = report.lookup_digest(stage.digest)
        if pinned_counts is not None:
            fixed, still = _fix_diff(details, stage.digest, latest_digest)
            return StageInspection(
                stage=stage,
                status=StageStatus.PINNED_KNOWN,
                reference=reference,
                pinned_counts=pinned_counts,
                latest_counts=latest_counts,
                latest_digest=latest_digest,
                fixed=fixed,
                still_present=still,
            )
        note = "no data for the pinned digest"
        note += "; showing the latest tracked digest" if latest_counts is not None else ""
        return StageInspection(
            stage=stage,
            status=StageStatus.PINNED_UNKNOWN,
            reference=reference,
            latest_counts=latest_counts,
            latest_digest=latest_digest,
            note=note,
        )

    if latest_counts is not None:
        return StageInspection(
            stage=stage,
            status=StageStatus.TAG_KNOWN,
            reference=reference,
            latest_counts=latest_counts,
            latest_digest=latest_digest,
        )

    return StageInspection(
        stage=stage,
        status=StageStatus.UNTRACKED,
        reference=reference,
        note="image/tag not tracked",
    )


def _fix_diff(
    details: DetailsReport, pinned: str | None, latest: str | None
) -> tuple[tuple[Vulnerability, ...], tuple[Vulnerability, ...]]:
    """Return ``(fixed, still_present)`` C/H CVEs, sorted; empty when latest is unknown."""
    if not latest:
        return (), ()
    fixed_set, still_set = details.fix_diff(pinned, latest)
    return _sorted_vulns(fixed_set), _sorted_vulns(still_set)


def inspect_dockerfile(
    text: str,
    report: VulnerabilityReport,
    details: DetailsReport,
) -> list[StageInspection]:
    """Parse ``text`` and inspect every ``FROM`` stage in source order."""
    return [inspect_stage(stage, report, details) for stage in parse_dockerfile_from(text)]
