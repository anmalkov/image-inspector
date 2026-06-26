"""Unit tests for the Dockerfile ``FROM`` parser."""

from image_inspector.dockerfile import FromStage, parse_dockerfile_from


def _only(text: str) -> FromStage:
    """Parse ``text`` and assert it yields exactly one stage."""
    stages = parse_dockerfile_from(text)
    assert len(stages) == 1
    return stages[0]


def test_simple_from_name_and_tag() -> None:
    stage = _only("FROM python:3.13")
    assert stage.index == 0
    assert stage.image == "python"
    assert stage.tag == "3.13"
    assert stage.digest is None
    assert stage.alias is None
    assert stage.references_stage is False
    assert stage.unresolved_args == ()


def test_name_only() -> None:
    stage = _only("FROM ubuntu")
    assert stage.image == "ubuntu"
    assert stage.tag is None
    assert stage.digest is None


def test_case_insensitive_keyword() -> None:
    stage = _only("from python:3.13")
    assert stage.image == "python"
    assert stage.tag == "3.13"


def test_digest_only() -> None:
    stage = _only("FROM python@sha256:abc123")
    assert stage.image == "python"
    assert stage.tag is None
    assert stage.digest == "sha256:abc123"


def test_name_tag_and_digest() -> None:
    stage = _only("FROM python:3.13@sha256:deadbeef")
    assert stage.image == "python"
    assert stage.tag == "3.13"
    assert stage.digest == "sha256:deadbeef"


def test_registry_namespace_prefix() -> None:
    stage = _only("FROM mcr.microsoft.com/dotnet/sdk:9.0")
    assert stage.image == "mcr.microsoft.com/dotnet/sdk"
    assert stage.tag == "9.0"


def test_library_prefix() -> None:
    stage = _only("FROM library/ubuntu:24.04")
    assert stage.image == "library/ubuntu"
    assert stage.tag == "24.04"


def test_registry_host_port_not_mistaken_for_tag() -> None:
    stage = _only("FROM localhost:5000/team/app")
    assert stage.image == "localhost:5000/team/app"
    assert stage.tag is None


def test_registry_host_port_with_tag() -> None:
    stage = _only("FROM localhost:5000/team/app:1.2.3@sha256:cafe")
    assert stage.image == "localhost:5000/team/app"
    assert stage.tag == "1.2.3"
    assert stage.digest == "sha256:cafe"


def test_alias_capture() -> None:
    stage = _only("FROM python:3.13 AS build")
    assert stage.alias == "build"
    assert stage.image == "python"
    assert stage.tag == "3.13"


def test_alias_case_insensitive_keyword() -> None:
    stage = _only("FROM python:3.13 as build")
    assert stage.alias == "build"


def test_multi_stage_indices() -> None:
    text = """
    FROM golang:1.23 AS builder
    FROM gcr.io/distroless/base AS runtime
    """
    stages = parse_dockerfile_from(text)
    assert [s.index for s in stages] == [0, 1]
    assert stages[0].alias == "builder"
    assert stages[1].alias == "runtime"
    assert stages[1].image == "gcr.io/distroless/base"


def test_from_alias_reference_resolves_to_stage() -> None:
    text = """
    FROM python:3.13 AS base
    FROM base
    """
    stages = parse_dockerfile_from(text)
    assert stages[1].references_stage is True
    assert stages[1].stage_ref == "base"
    assert stages[1].image is None
    assert stages[1].tag is None
    assert stages[1].digest is None


def test_from_alias_reference_is_case_insensitive() -> None:
    text = """
    FROM python:3.13 AS Base
    FROM base
    """
    stages = parse_dockerfile_from(text)
    assert stages[1].references_stage is True
    assert stages[1].stage_ref == "base"


def test_from_numeric_index_reference() -> None:
    text = """
    FROM python:3.13
    FROM 0
    """
    stages = parse_dockerfile_from(text)
    assert stages[1].references_stage is True
    assert stages[1].stage_ref == "0"
    assert stages[1].image is None


def test_image_named_like_later_stage_is_not_a_ref() -> None:
    # A stage defined *after* this FROM must not be treated as a reference.
    text = """
    FROM base
    FROM python:3.13 AS base
    """
    stages = parse_dockerfile_from(text)
    assert stages[0].references_stage is False
    assert stages[0].image == "base"


def test_arg_default_resolved_in_tag() -> None:
    text = """
    ARG TAG=3.13
    FROM python:${TAG}
    """
    stage = _only_after_args(text)
    assert stage.image == "python"
    assert stage.tag == "3.13"
    assert stage.unresolved_args == ()


def test_arg_default_resolved_braceless() -> None:
    text = """
    ARG TAG=3.13
    FROM python:$TAG
    """
    stage = _only_after_args(text)
    assert stage.tag == "3.13"


def test_arg_default_resolves_image_name() -> None:
    text = """
    ARG REGISTRY=mcr.microsoft.com
    FROM ${REGISTRY}/dotnet/sdk:9.0
    """
    stage = _only_after_args(text)
    assert stage.image == "mcr.microsoft.com/dotnet/sdk"
    assert stage.tag == "9.0"


def test_unresolved_arg_kept_literal_and_reported() -> None:
    text = """
    ARG TAG
    FROM python:${TAG}
    """
    stage = _only_after_args(text)
    assert stage.tag == "${TAG}"
    assert stage.unresolved_args == ("TAG",)


def test_arg_without_declaration_is_unresolved() -> None:
    stage = _only("FROM python:${TAG}")
    assert stage.tag == "${TAG}"
    assert stage.unresolved_args == ("TAG",)


def test_arg_quoted_default() -> None:
    text = """
    ARG TAG="3.13"
    FROM python:${TAG}
    """
    stage = _only_after_args(text)
    assert stage.tag == "3.13"


def test_platform_flag_skipped() -> None:
    stage = _only("FROM --platform=linux/amd64 python:3.13 AS build")
    assert stage.image == "python"
    assert stage.tag == "3.13"
    assert stage.alias == "build"


def test_comments_and_blank_lines_ignored() -> None:
    text = """
    # syntax=docker/dockerfile:1
    # a comment

    FROM python:3.13
    # trailing comment
    """
    stages = parse_dockerfile_from(text)
    assert len(stages) == 1
    assert stages[0].image == "python"


def test_line_continuation_joined() -> None:
    text = "FROM \\\n    python:3.13 \\\n    AS build"
    stage = _only(text)
    assert stage.image == "python"
    assert stage.tag == "3.13"
    assert stage.alias == "build"


def test_empty_input_yields_no_stages() -> None:
    assert parse_dockerfile_from("") == []


def test_no_from_yields_no_stages() -> None:
    assert parse_dockerfile_from("RUN echo hi\nARG X=1") == []


def _only_after_args(text: str) -> FromStage:
    """Parse ``text`` and return its single ``FROM`` stage (ignoring ARGs)."""
    stages = parse_dockerfile_from(text)
    assert len(stages) == 1
    return stages[0]
