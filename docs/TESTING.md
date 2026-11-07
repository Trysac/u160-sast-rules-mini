# Testing

## Existing Tests

- `tests/test_scanner.py`: Exercises core logic, covering AST parsing, suppression logic, and all security rules.
- `tests/test_formatters.py`: Verifies `format_text` and `to_sarif` output structures, ensuring correct column indexing and severity mapping.
- `tests/test_rules.py`: Validates the integrity of the `RULES` registry.
- `tests/test_cli.py`: Covers command-line arguments, exit codes, and output handling.

## Coverage

All public modules are tested. The test suite asserts every observable effect (return values, raised exceptions) and is strictly deterministic (no network, no timing dependencies).
