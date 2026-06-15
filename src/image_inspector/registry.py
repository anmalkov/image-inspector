"""Registry clients for Docker Hub and Microsoft Container Registry (MCR)."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

import httpx

from .models import ImageTag, Language, RegistryKind
from .versions import parse_semver

_TIMEOUT = httpx.Timeout(30.0)
_USER_AGENT = "image-inspector/0.1 (+https://github.com)"

# Media types understood when asking a registry for a manifest.
_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_MANIFEST_ACCEPT = ",".join((_OCI_INDEX, _MANIFEST_LIST, _MANIFEST_V2, _OCI_MANIFEST))


class RegistryError(RuntimeError):
    """Raised when a registry request fails or returns unexpected data."""


class RegistryProvider(Protocol):
    """Contract every registry backend implements."""

    def list_tag_names(self, *, want_minors: int) -> list[str]:
        """Return tag names, enough to cover ``want_minors`` minor versions."""
        ...

    def resolve(self, tag: str) -> ImageTag:
        """Return digest + timestamp for a concrete ``tag``."""
        ...


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _distinct_minor_count(tag_names: list[str]) -> int:
    minors = {(v.major, v.minor) for name in tag_names if (v := parse_semver(name)) is not None}
    return len(minors)


class DockerHubProvider:
    """Reads official images from Docker Hub's public registry API."""

    def __init__(self, repository: str, client: httpx.Client) -> None:
        self._repository = repository
        self._client = client

    def list_tag_names(self, *, want_minors: int, max_pages: int = 6) -> list[str]:
        url: str | None = (
            f"https://hub.docker.com/v2/repositories/{self._repository}/tags"
            "?page_size=100&ordering=last_updated"
        )
        names: list[str] = []
        for page in range(max_pages):
            if url is None:
                break
            data = self._get_json(url)
            names.extend(item["name"] for item in data.get("results", []))
            if page >= 1 and _distinct_minor_count(names) >= want_minors:
                break
            url = data.get("next")
        return names

    def resolve(self, tag: str) -> ImageTag:
        url = f"https://hub.docker.com/v2/repositories/{self._repository}/tags/{tag}"
        data = self._get_json(url)
        digest = data.get("digest")
        if not digest:
            raise RegistryError(f"Docker Hub returned no digest for tag '{tag}'.")
        return ImageTag(
            name=tag,
            digest=digest,
            last_updated=_parse_dt(data.get("last_updated")),
            size=self._size(data),
        )

    @staticmethod
    def _size(data: dict) -> int | None:
        """Compressed size of the linux/amd64 image (fallback: ``full_size``)."""
        for image in data.get("images", []):
            if image.get("os") == "linux" and image.get("architecture") == "amd64":
                return image.get("size")
        return data.get("full_size")

    def _get_json(self, url: str) -> dict:
        try:
            response = self._client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise RegistryError(f"Docker Hub request failed: {exc}") from exc


class McrProvider:
    """Reads .NET images from Microsoft Container Registry (v2 registry API)."""

    _BASE = "https://mcr.microsoft.com/v2"

    def __init__(self, repository: str, client: httpx.Client) -> None:
        self._repository = repository
        self._client = client

    def list_tag_names(self, *, want_minors: int) -> list[str]:
        url = f"{self._BASE}/{self._repository}/tags/list"
        try:
            response = self._client.get(url)
            response.raise_for_status()
            return list(response.json().get("tags", []))
        except httpx.HTTPError as exc:
            raise RegistryError(f"MCR request failed: {exc}") from exc

    def resolve(self, tag: str) -> ImageTag:
        url = f"{self._BASE}/{self._repository}/manifests/{tag}"
        try:
            response = self._client.get(url, headers={"Accept": _MANIFEST_ACCEPT})
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RegistryError(f"MCR manifest request failed: {exc}") from exc

        digest = response.headers.get("Docker-Content-Digest")
        if not digest:
            raise RegistryError(f"MCR returned no digest for tag '{tag}'.")
        created, size = self._created_and_size(response.json())
        return ImageTag(name=tag, digest=digest, last_updated=created, size=size)

    def _created_and_size(self, manifest: dict) -> tuple[datetime | None, int | None]:
        """Resolve a manifest (or list) to its config date and compressed size.

        Size is ``config.size`` plus the sum of layer sizes for the linux/amd64
        platform manifest.
        """
        manifests = manifest.get("manifests")
        if manifests:
            target = next(
                (m for m in manifests if m.get("platform", {}).get("architecture") == "amd64"),
                manifests[0],
            )
            manifest = self._get_manifest(target["digest"])

        config = manifest.get("config")
        if not config or "digest" not in config:
            return None, None

        size: int | None = config.get("size", 0) + sum(
            layer.get("size", 0) for layer in manifest.get("layers", [])
        )
        blob = self._get_json(f"{self._BASE}/{self._repository}/blobs/{config['digest']}")
        return _parse_dt(blob.get("created")), size

    def _get_manifest(self, digest: str) -> dict:
        url = f"{self._BASE}/{self._repository}/manifests/{digest}"
        try:
            response = self._client.get(url, headers={"Accept": _MANIFEST_ACCEPT})
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise RegistryError(f"MCR manifest request failed: {exc}") from exc

    def _get_json(self, url: str) -> dict:
        try:
            response = self._client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise RegistryError(f"MCR request failed: {exc}") from exc


def make_client() -> httpx.Client:
    """Create the shared HTTP client used by providers."""
    return httpx.Client(
        timeout=_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": _USER_AGENT},
    )


def get_provider(language: Language, client: httpx.Client) -> RegistryProvider:
    """Return the right provider for a language's registry."""
    if language.registry is RegistryKind.DOCKER_HUB:
        return DockerHubProvider(language.repository, client)
    return McrProvider(language.repository, client)
