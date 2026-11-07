"""Rule definitions and Finding data structures for sast_rules_mini."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

Severity = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class Rule:
    """Definition of a static analysis rule."""

    id: str
    severity: Severity
    short_description: str


@dataclass(frozen=True)
class Finding:
    """A security finding discovered during static analysis."""

    rule_id: str
    severity: Severity
    path: str
    line: int
    column: int
    message: str


RULES: Mapping[str, Rule] = {
    "PY000": Rule(
        id="PY000",
        severity="low",
        short_description="Parse or file read error",
    ),
    "PY001": Rule(
        id="PY001",
        severity="high",
        short_description="Use of eval or exec",
    ),
    "PY002": Rule(
        id="PY002",
        severity="high",
        short_description="Command execution with shell=True or popen/system",
    ),
    "PY003": Rule(
        id="PY003",
        severity="high",
        short_description="Insecure deserialisation via pickle, marshal or shelve",
    ),
    "PY004": Rule(
        id="PY004",
        severity="high",
        short_description="Insecure YAML loading without SafeLoader",
    ),
    "PY005": Rule(
        id="PY005",
        severity="medium",
        short_description="Weak cryptographic hash function (MD5/SHA1)",
    ),
    "PY006": Rule(
        id="PY006",
        severity="high",
        short_description="Disabled TLS verification",
    ),
    "PY007": Rule(
        id="PY007",
        severity="medium",
        short_description="Hardcoded secret assigned to sensitive variable",
    ),
    "PY008": Rule(
        id="PY008",
        severity="high",
        short_description="SQL injection risk via string formatting or BinOp in execute",
    ),
    "PY009": Rule(
        id="PY009",
        severity="medium",
        short_description="Insecure temporary file creation with tempfile.mktemp",
    ),
    "PY010": Rule(
        id="PY010",
        severity="medium",
        short_description="Flask application run with debug=True",
    ),
}
