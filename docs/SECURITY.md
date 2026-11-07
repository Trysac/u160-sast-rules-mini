# Security and Threat Model

## Threat Model

- **Defended**: The tool identifies common syntactic misconfigurations and dangerous patterns (e.g., shell injection, unsafe deserialization) at the AST level. It provides consistent, machine-readable SARIF output for CI integration.
- **Not Defended**: The scanner does not perform inter-procedural dataflow analysis, dynamic symbol resolution, or tracking of aliasing across functions/files. Dynamically executed code (e.g., via `getattr()`, `__import__()`, or reflection) can bypass detection. It never guarantees that code is free of vulnerabilities.

## Limits

- **Secret Handling**: Rule `PY007` identifies assignments to variable names matching sensitive patterns (password, secret, token, api_key), but the actual secret values are never included in findings, reports, or SARIF output.
- **Resource Consumption**: To prevent Denial of Service (DoS) via resource exhaustion, the tool enforces a default file size limit of 1 MB per file and a maximum traversal limit of 10,000 files.
