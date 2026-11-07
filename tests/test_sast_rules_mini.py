"""Behavior tests for the public API of sast_rules_mini."""

from __future__ import annotations

import pytest

import sast_rules_mini


def test_normalize_trims_and_lowercases() -> None:
    assert sast_rules_mini.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        sast_rules_mini.normalize(value)


def test_version_is_semver() -> None:
    parts = sast_rules_mini.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
