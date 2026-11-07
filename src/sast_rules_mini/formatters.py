"""Formatters for scan findings: terminal text and SARIF 2.1.0 output."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sast_rules_mini.rules import RULES, Finding


def format_text(findings: Sequence[Finding]) -> str:
    """Format findings as human-readable terminal text."""
    if not findings:
        return "No findings detected."
    lines = []
    for f in findings:
        lines.append(
            f"{f.path}:{f.line}:{f.column}: [{f.severity.upper()}] {f.rule_id}: {f.message}"
        )
    return "\n".join(lines)


def to_sarif(findings: Sequence[Finding], *, tool_version: str = "0.1.0") -> dict[str, Any]:
    """Export findings to OASIS SARIF 2.1.0 standard schema."""
    severity_to_sarif_level = {
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    sarif_rules = []
    for _rule_id, rule in sorted(RULES.items(), key=lambda r: r[0]):
        sarif_rules.append(
            {
                "id": rule.id,
                "shortDescription": {
                    "text": rule.short_description,
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level.get(rule.severity, "note"),
                },
            }
        )

    results = []
    for f in findings:
        level = severity_to_sarif_level.get(f.severity, "note")
        # Artifact location URI as a POSIX relative path
        uri = f.path.replace("\\", "/")
        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": f.message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column,
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sast-rules-mini",
                        "version": tool_version,
                        "rules": sarif_rules,
                    }
                },
                "columnKind": "unicodeCodePoints",
                "results": results,
            }
        ],
    }
