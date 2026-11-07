# sast-rules-mini

Lightweight static analysis for Python: ten AST security rules with import alias tracking, inline suppressions, text output, and SARIF 2.1.0 with code point columns.

## The Problem

Small projects want a security lint in CI that catches `eval`, `shell=True`, unsafe deserialisation, weak hashes, and string-built SQL, but full SAST suites are heavy to configure and some cost money. Bandit covers this but its output and rule set are large. This tool is a dependency-free AST scanner with ten precise rules and SARIF that GitHub code scanning accepts.

## Installation

```bash
pip install sast-rules-mini
```

## Usage Example

```python
from sast_rules_mini import scan_source, to_sarif

findings = scan_source("import subprocess; subprocess.run(cmd, shell=True)")
sarif_report = to_sarif(findings)
print(f"Found {len(findings)} issues; SARIF version: {sarif_report['version']}")
```

## Public API Summary

- `scan_source(source: str, path: str = '<string>', *, rules: Collection[str] | None = None) -> list[Finding]`: Scans a string for security findings.
- `scan_paths(paths: Sequence[str | Path], *, rules=None, max_file_bytes: int = 1_048_576, max_files: int = 10_000) -> list[Finding]`: Scans files/directories recursively. Returns `SastError` on path failure or when file limits are exceeded.
- `format_text(findings) -> str`: Renders human-readable terminal output.
- `to_sarif(findings, *, tool_version: str) -> dict`: Exports findings to OASIS SARIF 2.1.0 schema.
- `RULES: Mapping[str, Rule]`: Registry of rule IDs, severities, and descriptions.
- `Finding` (dataclass): Contains `rule_id`, `severity` (high/medium/low), `path`, `line`, `column`, `message`.

## Why not Bandit?

Bandit is a comprehensive tool, but `sast-rules-mini` is smaller, has zero runtime dependencies, provides ten precise rules, and outputs SARIF with correct non-ASCII code-point columns.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limitations.
