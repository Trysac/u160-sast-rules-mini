# sast-rules-mini

[![PyPI version](https://img.shields.io/pypi/v/trysac-sast-rules-mini)](https://pypi.org/project/trysac-sast-rules-mini/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-sast-rules-mini)](LICENSE)
[![CI](https://github.com/Trysac/u160-sast-rules-mini/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u160-sast-rules-mini/actions/workflows/ci.yml)

Lightweight static analysis for Python: ten AST security rules with import alias tracking, inline suppressions, text output and SARIF 2.1.0 with code point columns

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-sast-rules-mini
# or
uv add trysac-sast-rules-mini
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import sast_rules_mini

# normalize() trims surrounding whitespace and lower-cases the text.
print(sast_rules_mini.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    sast_rules_mini.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
