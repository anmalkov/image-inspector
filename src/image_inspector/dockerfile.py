"""Parse ``FROM`` instructions out of a Dockerfile into structured stages.

This is a pure utility: it turns the textual ``FROM`` lines of a Dockerfile into
per-stage records (image name, tag, pinned digest, alias, and whether the line
references an earlier build stage). It performs **no** registry or report
lookups and does no output formatting -- those belong to sibling features.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# A ``${NAME}`` or ``$NAME`` build-arg reference inside an image string.
_ARG_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")

# A line that opens a new build stage, e.g. ``FROM python:3.13 AS build``.
_FROM_RE = re.compile(r"^FROM\s+(?P<rest>.+)$", re.IGNORECASE)

# An ``ARG`` declaration, optionally with a default value.
_ARG_RE = re.compile(r"^ARG\s+(?P<rest>.+)$", re.IGNORECASE)

# A ``--platform=...`` (or any ``--flag=value``) option preceding the image.
_FLAG_RE = re.compile(r"^--[A-Za-z0-9-]+=\S+$")


@dataclass(frozen=True)
class FromStage:
    """One ``FROM`` instruction, broken into its meaningful parts.

    Either ``image`` (a registry image reference) or ``stage_ref`` (a reference
    to an earlier stage by alias or numeric index) is set, never both.
    """

    index: int
    raw: str
    image: str | None = None
    tag: str | None = None
    digest: str | None = None
    alias: str | None = None
    stage_ref: str | None = None
    unresolved_args: tuple[str, ...] = field(default_factory=tuple)

    @property
    def references_stage(self) -> bool:
        """Whether this ``FROM`` builds upon an earlier stage rather than an image."""
        return self.stage_ref is not None


def parse_dockerfile_from(text: str) -> list[FromStage]:
    """Parse every ``FROM`` instruction in ``text`` into :class:`FromStage` records.

    Stages are returned in source order. Only ``ARG`` defaults declared before
    the first ``FROM`` (Dockerfile "global" args) are substituted into ``FROM``
    image references, matching Docker's scoping; stage-scoped ``ARG``s have no
    effect here. Args without a resolvable default are left literal and listed
    in :attr:`FromStage.unresolved_args`.
    """
    stages: list[FromStage] = []
    arg_defaults: dict[str, str] = {}
    # Known prior-stage identifiers (lowercased aliases + numeric indices).
    stage_names: set[str] = set()

    for line in _iter_instructions(text):
        arg_match = _ARG_RE.match(line)
        if arg_match:
            # Only global ARGs (before the first FROM) are usable in FROM lines.
            if not stages:
                _record_arg(arg_match.group("rest"), arg_defaults)
            continue

        from_match = _FROM_RE.match(line)
        if not from_match:
            continue

        stage = _parse_from(
            from_match.group("rest"),
            index=len(stages),
            arg_defaults=arg_defaults,
            stage_names=stage_names,
        )
        stages.append(stage)
        stage_names.add(str(stage.index))
        if stage.alias is not None:
            stage_names.add(stage.alias.lower())

    return stages


def _iter_instructions(text: str) -> list[str]:
    """Yield logical instruction lines: comments stripped, continuations joined."""
    instructions: list[str] = []
    buffer: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line
        # Drop full-line comments and parser directives; only strip a comment
        # when it starts the (stripped) line, to avoid touching ``#`` inside a
        # value such as a tag (tags never legitimately contain ``#`` anyway).
        if line.lstrip().startswith("#") and not buffer:
            continue

        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue

        buffer.append(stripped)
        joined = " ".join(part.strip() for part in buffer).strip()
        buffer = []
        if joined:
            instructions.append(joined)

    if buffer:
        joined = " ".join(part.strip() for part in buffer).strip()
        if joined:
            instructions.append(joined)

    return instructions


def _record_arg(rest: str, arg_defaults: dict[str, str]) -> None:
    """Record an ``ARG`` declaration's default value, if it has one."""
    # An ARG line may declare a single arg; only ``NAME=value`` form has a
    # default we can resolve. ``ARG NAME`` (no default) stays unresolved.
    parts = rest.split()
    token = parts[0] if parts else ""
    if "=" in token:
        name, _, value = token.partition("=")
        arg_defaults[name] = _strip_quotes(value)


def _parse_from(
    rest: str,
    *,
    index: int,
    arg_defaults: dict[str, str],
    stage_names: set[str],
) -> FromStage:
    """Parse the text following ``FROM`` into a :class:`FromStage`."""
    tokens = rest.split()

    # Skip any leading option flags (e.g. ``--platform=linux/amd64``).
    while tokens and _FLAG_RE.match(tokens[0]):
        tokens.pop(0)

    raw_ref = tokens.pop(0) if tokens else ""

    alias: str | None = None
    if len(tokens) >= 2 and tokens[0].upper() == "AS":
        alias = tokens[1]

    resolved, unresolved = _resolve_args(raw_ref, arg_defaults)

    # A reference to an earlier stage (by alias or numeric index) is not an
    # image. Such references never carry a tag or digest.
    if resolved.lower() in stage_names:
        return FromStage(
            index=index,
            raw=resolved,
            alias=alias,
            stage_ref=resolved,
            unresolved_args=unresolved,
        )

    image, tag, digest = _split_reference(resolved)
    return FromStage(
        index=index,
        raw=resolved,
        image=image,
        tag=tag,
        digest=digest,
        alias=alias,
        unresolved_args=unresolved,
    )


def _resolve_args(ref: str, arg_defaults: dict[str, str]) -> tuple[str, tuple[str, ...]]:
    """Substitute known ``ARG`` defaults in ``ref``; report unresolved names.

    Unresolved references are left verbatim in the returned string so callers
    can still see (and surface) the literal ``${NAME}`` placeholder.
    """
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name in arg_defaults:
            return arg_defaults[name]
        if name not in unresolved:
            unresolved.append(name)
        return match.group(0)

    resolved = _ARG_REF_RE.sub(replace, ref)
    return resolved, tuple(unresolved)


def _split_reference(ref: str) -> tuple[str | None, str | None, str | None]:
    """Split an image reference into ``(name, tag, digest)``.

    Handles every subset of ``name:tag@sha256:...`` and is careful not to treat
    a registry ``host:port`` prefix as a tag (the tag colon, if any, lives in
    the final path segment after the last ``/``).
    """
    if not ref:
        return None, None, None

    name_tag, sep, digest = ref.partition("@")
    digest_value = digest if sep else None

    slash = name_tag.rfind("/")
    last_segment = name_tag[slash + 1 :]
    colon = last_segment.rfind(":")
    if colon != -1:
        name = name_tag[: slash + 1] + last_segment[:colon]
        tag = last_segment[colon + 1 :]
    else:
        name = name_tag
        tag = None

    return (name or None), (tag or None), digest_value


def _strip_quotes(value: str) -> str:
    """Remove a single matching pair of surrounding quotes, if present."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
