"""Tests for the Docker Hub and MCR registry providers (httpx mocked)."""

from datetime import UTC, datetime

import httpx
import pytest
import respx

from image_inspector.registry import (
    DockerHubProvider,
    McrProvider,
    RegistryError,
)

HUB = "https://hub.docker.com/v2/repositories/library/python"
MCR = "https://mcr.microsoft.com/v2/dotnet/sdk"


@pytest.fixture
def client():
    with httpx.Client(follow_redirects=True) as c:
        yield c


@respx.mock
def test_dockerhub_list_tag_names_paginates(client):
    page1 = {
        "results": [{"name": "3.14.0"}, {"name": "3.13.1"}],
        "next": f"{HUB}/tags?page=2",
    }
    page2 = {"results": [{"name": "3.12.5"}], "next": None}
    respx.get(url__startswith=f"{HUB}/tags").mock(
        side_effect=[httpx.Response(200, json=page1), httpx.Response(200, json=page2)]
    )

    provider = DockerHubProvider("library/python", client)
    names = provider.list_tag_names(want_minors=5)

    assert names == ["3.14.0", "3.13.1", "3.12.5"]


@respx.mock
def test_dockerhub_resolve_returns_digest_date_and_size(client):
    respx.get(f"{HUB}/tags/3.13.1").mock(
        return_value=httpx.Response(
            200,
            json={
                "digest": "sha256:abc123",
                "last_updated": "2026-06-11T08:06:21.604775Z",
                "full_size": 999,
                "images": [
                    {"os": "linux", "architecture": "arm64", "size": 111},
                    {"os": "linux", "architecture": "amd64", "size": 42966326},
                ],
            },
        )
    )

    provider = DockerHubProvider("library/python", client)
    tag = provider.resolve("3.13.1")

    assert tag.digest == "sha256:abc123"
    assert tag.last_updated == datetime(2026, 6, 11, 8, 6, 21, 604775, tzinfo=UTC)
    assert tag.size == 42966326


@respx.mock
def test_dockerhub_size_falls_back_to_full_size(client):
    respx.get(f"{HUB}/tags/3.13.1").mock(
        return_value=httpx.Response(
            200, json={"digest": "sha256:abc", "full_size": 555, "images": []}
        )
    )
    provider = DockerHubProvider("library/python", client)
    assert provider.resolve("3.13.1").size == 555


@respx.mock
def test_dockerhub_resolve_without_digest_raises(client):
    respx.get(f"{HUB}/tags/3.13.1").mock(return_value=httpx.Response(200, json={}))
    provider = DockerHubProvider("library/python", client)
    with pytest.raises(RegistryError):
        provider.resolve("3.13.1")


@respx.mock
def test_dockerhub_http_error_raises(client):
    respx.get(url__startswith=f"{HUB}/tags").mock(return_value=httpx.Response(503))
    provider = DockerHubProvider("library/python", client)
    with pytest.raises(RegistryError):
        provider.list_tag_names(want_minors=5)


@respx.mock
def test_mcr_list_tag_names(client):
    respx.get(f"{MCR}/tags/list").mock(
        return_value=httpx.Response(200, json={"tags": ["9.0.315", "8.0.422"]})
    )
    provider = McrProvider("dotnet/sdk", client)
    assert provider.list_tag_names(want_minors=5) == ["9.0.315", "8.0.422"]


@respx.mock
def test_mcr_resolve_walks_manifest_list_to_config(client):
    list_digest = "sha256:listdigest"
    amd_digest = "sha256:amd64digest"
    config_digest = "sha256:configdigest"

    respx.get(f"{MCR}/manifests/9.0.315").mock(
        return_value=httpx.Response(
            200,
            headers={"Docker-Content-Digest": list_digest},
            json={
                "manifests": [
                    {"digest": amd_digest, "platform": {"architecture": "amd64"}},
                    {"digest": "sha256:armdigest", "platform": {"architecture": "arm64"}},
                ]
            },
        )
    )
    respx.get(f"{MCR}/manifests/{amd_digest}").mock(
        return_value=httpx.Response(
            200,
            json={
                "config": {"digest": config_digest, "size": 5000},
                "layers": [{"size": 100}, {"size": 200}, {"size": 700}],
            },
        )
    )
    respx.get(f"{MCR}/blobs/{config_digest}").mock(
        return_value=httpx.Response(200, json={"created": "2026-06-09T22:36:16Z"})
    )

    provider = McrProvider("dotnet/sdk", client)
    tag = provider.resolve("9.0.315")

    assert tag.digest == list_digest
    assert tag.last_updated == datetime(2026, 6, 9, 22, 36, 16, tzinfo=UTC)
    assert tag.size == 6000


@respx.mock
def test_mcr_resolve_without_digest_header_raises(client):
    respx.get(f"{MCR}/manifests/9.0.315").mock(
        return_value=httpx.Response(200, json={"manifests": []})
    )
    provider = McrProvider("dotnet/sdk", client)
    with pytest.raises(RegistryError):
        provider.resolve("9.0.315")
