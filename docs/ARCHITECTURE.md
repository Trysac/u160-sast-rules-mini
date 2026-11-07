# Architecture

`trysac-sast-rules-mini` is designed as a standalone static analysis engine using the Python standard library.

## Components

1. **Scanner (`sast_rules_mini.scanner`)**:
   - Parses Python files into standard AST representations via `ast.parse`.
   - Extracts inline suppression comments using `tokenize`.
   - Tracks module and function aliasing per file across `import` and `from ... import` statements without global state.
   - Converts `ast` node byte offsets to 1-based Unicode code point indices for exact source mapping.
2. **Rules Registry (`sast_rules_mini.rules`)**:
   - Maps canonical rule IDs (`PY000` through `PY010`) to frozen `Rule` definitions with severity levels (`high`, `medium`, `low`).
3. **Formatters (`sast_rules_mini.formatters`)**:
   - Produces compact terminal text format (`path:line:col: [SEVERITY] ID: message`).
   - Exports OASIS SARIF 2.1.0 JSON format with `unicodeCodePoints` columnKind.
4. **Command Line Interface (`sast_rules_mini.__main__`)**:
   - Provides CLI commands with standard exit code semantics: 0 for clean scans, 1 for finding presence, 2 for CLI argument / I/O errors.
