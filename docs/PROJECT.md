# Project record

## Objective

Lightweight static analysis for Python: ten AST security rules with import alias tracking, inline suppressions, text output and SARIF 2.1.0 with code point columns.

## Scope

- Perform static analysis of Python source code using `ast` and `tokenize` from the standard library.
- Implement 10 specific security rules: PY001 (eval/exec), PY002 (subprocess shell=True/os.system), PY003 (pickle/marshal), PY004 (unsafe YAML), PY005 (weak hashes), PY006 (TLS verification), PY007 (hardcoded secrets), PY008 (SQL injection), PY009 (tempfile.mktemp), PY010 (Flask debug).
- Handle import aliasing per-file and support `# nosast` inline suppression.
- Output results in plain text or SARIF 2.1.0 JSON with 1-based Unicode code point columns.

## Out-of-Scope

- Taint tracking, inter-procedural analysis, dynamic symbol resolution, config files, baselines, auto-fix, or analysis of languages other than Python.

## Factory run u160 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4668 | 14309 | 0 | 0 | 0.0286 |
| fix-1 | gemini-3.8-flash | no | 69835 | 2378 | 0 | 563688 | 0.1036 |
| fix-2 | gemini-3.8-flash | no | 26221 | 922 | 0 | 66225 | 0.0281 |
| fix-3 | gemini-3.8-flash | no | 39658 | 805 | 0 | 135604 | 0.0429 |
| fix-4 | gemini-3.8-flash | no | 43715 | 359 | 0 | 153007 | 0.0456 |
| audit | gemini-3.1-flash-lite | no | 61579 | 252 | 0 | 187538 | 0.0205 |
| docs | gemini-3.1-flash-lite | no | 122999 | 1381 | 0 | 0 | 0.0328 |

Total: $0.3021. Prices: Anthropic list prices.
