"""Lightweight static analysis for Python: ten AST security rules with import alias tracking.

Provides fast AST scanning, inline comment suppression, SARIF 2.1.0 output,
and a command-line interface.
"""

from __future__ import annotations

import logging

from sast_rules_mini.errors import SastError
from sast_rules_mini.formatters import format_text, to_sarif
from sast_rules_mini.rules import RULES, Finding, Rule, Severity
from sast_rules_mini.scanner import scan_paths, scan_source

logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"

__all__ = [
    "RULES",
    "Finding",
    "Rule",
    "SastError",
    "Severity",
    "__version__",
    "format_text",
    "scan_paths",
    "scan_source",
    "to_sarif",
]
