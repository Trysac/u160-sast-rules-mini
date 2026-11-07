"""Base and specific error classes for sast_rules_mini."""

from __future__ import annotations


class SastError(Exception):
    """Base exception class for sast_rules_mini with a stable machine-readable code."""

    def __init__(self, message: str, code: str = "sast_error") -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"
