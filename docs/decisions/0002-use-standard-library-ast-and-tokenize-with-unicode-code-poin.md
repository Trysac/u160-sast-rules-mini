# Use standard library ast and tokenize with Unicode code point column mapping for SARIF 2.1.0

Status: accepted (generated, pending human review)

## Context

Small Python projects require a fast, dependency-free static analysis scanner in CI that reports findings in both terminal text and GitHub-compatible SARIF 2.1.0. In Python 3.10+, AST node col_offset values represent UTF-8 byte offsets rather than character code points, which can cause column mismatch errors in SARIF viewers when source lines contain multi-byte characters.

## Decision

Implement the scanner strictly with standard library ast and tokenize. Track import aliases on a per-file basis and compute 1-based Unicode code point columns by slicing the UTF-8 bytes of the matching source line and decoding back to characters. Inline suppressions are parsed via tokenize.tokenize to avoid false positives in string literals.

## Consequences

The library runs without third-party dependencies, ensures exact SARIF 2.1.0 unicodeCodePoints column alignment for non-ASCII characters, and maintains deterministic AST rule evaluation.
