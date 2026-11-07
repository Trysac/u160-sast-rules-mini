"""Core scanning logic with AST analysis and inline suppression support."""

from __future__ import annotations

import ast
import io
import logging
import re
import tokenize
from collections.abc import Collection, Sequence
from pathlib import Path

from sast_rules_mini.errors import SastError
from sast_rules_mini.rules import RULES, Finding

logger = logging.getLogger(__name__)

PASSWORD_REGEX = re.compile(r"(?i)(^|_)(password|passwd|secret|token|api_key)$")
NOSAST_STRICT = re.compile(r"#\s*nosast(?:\s*:\s*([A-Za-z0-9_,\s]+))?", re.IGNORECASE)

EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules"}


def _byte_offset_to_codepoint(line_str: str, byte_offset: int) -> int:
    """Convert a 0-based UTF-8 byte offset in a line to a 1-based code point offset."""
    line_bytes = line_str.encode("utf-8")
    sliced = line_bytes[: max(0, byte_offset)]
    try:
        decoded = sliced.decode("utf-8", errors="replace")
        return len(decoded) + 1
    except Exception:
        return byte_offset + 1


def _extract_suppressions(source: str) -> dict[int, set[str] | None]:
    """Extract nosast suppression comments per 1-based line number.

    None indicates full suppression on that line (nosast without rule IDs).
    A set indicates specific rule IDs suppressed.
    """
    suppressions: dict[int, set[str] | None] = {}
    try:
        tokens = tokenize.tokenize(io.BytesIO(source.encode("utf-8")).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                match = NOSAST_STRICT.search(tok.string)
                if match:
                    line_num = tok.start[0]
                    rules_part = match.group(1)
                    if rules_part is None:
                        suppressions[line_num] = None
                    else:
                        rule_ids = {r.strip().upper() for r in rules_part.split(",") if r.strip()}
                        current = suppressions.get(line_num)
                        if isinstance(current, set):
                            current.update(rule_ids)
                        elif line_num not in suppressions:
                            suppressions[line_num] = rule_ids
    except Exception:
        logger.debug("Failed to tokenize source for suppressions", exc_info=True)
    return suppressions


class _SourceVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str], path: str, allowed_rules: set[str]) -> None:
        self.source_lines = source_lines
        self.path = path
        self.allowed_rules = allowed_rules
        self.findings: list[Finding] = []
        # Map from alias (local name) to canonical qualified string
        self.aliases: dict[str, str] = {}

    def _get_col(self, node: ast.AST) -> int:
        line_idx = getattr(node, "lineno", 1) - 1
        byte_col = getattr(node, "col_offset", 0)
        if 0 <= line_idx < len(self.source_lines):
            return _byte_offset_to_codepoint(self.source_lines[line_idx], byte_col)
        return byte_col + 1

    def _add_finding(self, rule_id: str, node: ast.AST, message: str) -> None:
        if rule_id not in self.allowed_rules:
            return
        rule = RULES.get(rule_id)
        if not rule:
            return
        line = getattr(node, "lineno", 1)
        col = self._get_col(node)
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=rule.severity,
                path=self.path,
                line=line,
                column=col,
                message=message,
            )
        )

    def _resolve_expr_name(self, expr: ast.AST) -> str | None:
        """Resolve an expression like a.b.c or bare name using the file's import table."""
        if isinstance(expr, ast.Name):
            return self.aliases.get(expr.id, expr.id)
        if isinstance(expr, ast.Attribute):
            left = self._resolve_expr_name(expr.value)
            if left:
                combined = f"{left}.{expr.attr}"
                return self.aliases.get(combined, combined)
            return expr.attr
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            asname = alias.asname or alias.name
            self.aliases[asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            asname = alias.asname or alias.name
            full_name = f"{mod}.{alias.name}" if mod else alias.name
            self.aliases[asname] = full_name
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_secret_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_secret_assignment([node.target], node.value)
        self.generic_visit(node)

    def _check_secret_assignment(self, targets: Sequence[ast.AST], value: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        if not value.value:  # empty string is allowed
            return
        for target in targets:
            var_name: str | None = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr
            if var_name and PASSWORD_REGEX.search(var_name):
                self._add_finding(
                    "PY007",
                    target,
                    f"Hardcoded secret assigned to sensitive variable '{var_name}'",
                )

    def visit_Call(self, node: ast.Call) -> None:
        resolved_func = self._resolve_expr_name(node.func)

        # PY001: bare eval or exec
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval" and resolved_func == "eval":
                self._add_finding("PY001", node, "Use of eval is potentially dangerous")
            elif node.func.id == "exec" and resolved_func == "exec":
                self._add_finding("PY001", node, "Use of exec is potentially dangerous")

        # PY002: subprocess.* shell=True or os.system/popen
        subprocess_funcs = {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }
        if resolved_func in subprocess_funcs:
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._add_finding(
                        "PY002", node, f"Command execution with shell=True in {resolved_func}"
                    )
        if resolved_func in {"os.system", "os.popen"}:
            self._add_finding("PY002", node, f"Command execution via {resolved_func}")

        # PY003: pickle.load/loads, marshal.load/loads, shelve.open
        if resolved_func in {
            "pickle.load",
            "pickle.loads",
            "_pickle.load",
            "_pickle.loads",
            "marshal.load",
            "marshal.loads",
            "shelve.open",
        }:
            self._add_finding("PY003", node, f"Insecure deserialisation via {resolved_func}")

        # PY004: yaml.load without Loader or with unsafe Loader
        if resolved_func == "yaml.load":
            loader_kw = None
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_kw = kw.value
                    break
            if loader_kw is None:
                self._add_finding("PY004", node, "yaml.load called without Loader keyword argument")
            else:
                loader_name = self._resolve_expr_name(loader_kw)
                safe_loaders = {
                    "yaml.SafeLoader",
                    "SafeLoader",
                    "yaml.CSafeLoader",
                    "CSafeLoader",
                }
                if loader_name not in safe_loaders:
                    self._add_finding(
                        "PY004",
                        node,
                        f"yaml.load called with unsafe Loader '{loader_name or 'custom'}'",
                    )

        # PY005: hashlib.md5/sha1 or hashlib.new('md5'/'sha1') unless usedforsecurity=False
        if resolved_func in {"hashlib.md5", "hashlib.sha1"}:
            if not self._has_usedforsecurity_false(node):
                self._add_finding(
                    "PY005", node, f"Weak cryptographic hash function {resolved_func}"
                )
        elif resolved_func == "hashlib.new" and (
            len(node.args) >= 1 and isinstance(node.args[0], ast.Constant)
        ):
            val = str(node.args[0].value).lower()
            if val in {"md5", "sha1"} and not self._has_usedforsecurity_false(node):
                self._add_finding(
                    "PY005", node, f"Weak cryptographic hash function hashlib.new('{val}')"
                )

        # PY006: requests.* verify=False or ssl._create_unverified_context
        requests_funcs = {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "requests.request",
            "requests.head",
        }
        if resolved_func in requests_funcs:
            for kw in node.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                ):
                    self._add_finding(
                        "PY006",
                        node,
                        f"TLS certificate verification disabled in {resolved_func}",
                    )
        if resolved_func == "ssl._create_unverified_context":
            self._add_finding(
                "PY006", node, "Unverified SSL context created with ssl._create_unverified_context"
            )

        # PY008: cursor-like .execute or .executemany with SQL string formatting
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "executemany"}
            and len(node.args) >= 1
            and self._is_unsafe_sql_expr(node.args[0])
        ):
            self._add_finding(
                "PY008",
                node,
                f"Possible SQL injection via formatted query in {node.func.attr}",
            )

        # PY009: tempfile.mktemp
        if resolved_func == "tempfile.mktemp":
            self._add_finding(
                "PY009", node, "Use of insecure tempfile.mktemp (race condition risk)"
            )

        # PY010: .run(debug=True)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if (
                    kw.arg == "debug"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._add_finding(
                        "PY010", node, "Flask or server application run with debug=True"
                    )

        self.generic_visit(node)

    @staticmethod
    def _has_usedforsecurity_false(node: ast.Call) -> bool:
        for kw in node.keywords:
            if (
                kw.arg == "usedforsecurity"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
            ):
                return True
        return False

    @classmethod
    def _is_unsafe_sql_expr(cls, expr: ast.AST) -> bool:
        # Check if f-string with placeholders
        if isinstance(expr, ast.JoinedStr):
            for part in expr.values:
                if isinstance(part, ast.FormattedValue):
                    return True
        # Check if .format() call
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format"
        ):
            return True
        # Check if BinOp with % or + involving a non-constant
        return bool(
            isinstance(expr, ast.BinOp)
            and isinstance(expr.op, (ast.Mod, ast.Add))
            and not (isinstance(expr.left, ast.Constant) and isinstance(expr.right, ast.Constant))
        )


def scan_source(
    source: str,
    path: str = "<string>",
    *,
    rules: Collection[str] | None = None,
) -> list[Finding]:
    """Scan Python source code string for SAST security findings."""
    allowed_rules = set(RULES.keys()) if rules is None else set(rules)

    # Check for empty or invalid source lines
    source_lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        logger.debug("Failed to parse %s: %s", path, exc)
        if "PY000" in allowed_rules:
            lineno = getattr(exc, "lineno", 1) or 1
            offset = getattr(exc, "offset", 1) or 1
            return [
                Finding(
                    rule_id="PY000",
                    severity=RULES["PY000"].severity,
                    path=path,
                    line=lineno,
                    column=offset,
                    message="file could not be parsed",
                )
            ]
        return []

    suppressions = _extract_suppressions(source)
    visitor = _SourceVisitor(source_lines, path, allowed_rules)
    visitor.visit(tree)

    # Filter suppressions
    filtered_findings: list[Finding] = []
    for f in visitor.findings:
        if f.line in suppressions:
            supp = suppressions[f.line]
            if supp is None or f.rule_id in supp:
                continue
        filtered_findings.append(f)

    # Sort findings by path, line, column, rule_id
    filtered_findings.sort(key=lambda x: (x.path, x.line, x.column, x.rule_id))
    return filtered_findings


def scan_paths(
    paths: Sequence[str | Path],
    *,
    rules: Collection[str] | None = None,
    max_file_bytes: int = 1_048_576,
    max_files: int = 10_000,
) -> list[Finding]:
    """Scan files and directories recursively for Python security issues."""
    allowed_rules = set(RULES.keys()) if rules is None else set(rules)
    file_list: list[Path] = []

    def collect_dir(d: Path) -> None:
        # Skip symlinked directories
        if d.is_symlink():
            return
        try:
            entries = sorted(d.iterdir(), key=lambda p: p.name)
        except OSError as err:
            logger.debug("Unable to read dir %s: %s", d, err)
            return
        for entry in entries:
            if entry.name in EXCLUDED_DIRS:
                continue
            if not entry.is_symlink() and entry.is_dir():
                collect_dir(entry)
            elif entry.is_file() and entry.name.endswith(".py"):
                file_list.append(entry)
                if len(file_list) > max_files:
                    raise SastError(
                        f"File count exceeded maximum limit of {max_files}",
                        code="too_many_files",
                    )

    for p in paths:
        path_obj = Path(p)
        if not path_obj.exists():
            raise SastError(f"Path does not exist: {p}", code="file_not_found")
        if not path_obj.is_symlink() and path_obj.is_dir():
            collect_dir(path_obj)
        elif path_obj.is_file():
            file_list.append(path_obj)
            if len(file_list) > max_files:
                raise SastError(
                    f"File count exceeded maximum limit of {max_files}",
                    code="too_many_files",
                )

    all_findings: list[Finding] = []

    for file_path in file_list:
        posix_path = file_path.as_posix()
        try:
            file_size = file_path.stat().st_size
        except OSError:
            if "PY000" in allowed_rules:
                all_findings.append(
                    Finding(
                        rule_id="PY000",
                        severity=RULES["PY000"].severity,
                        path=posix_path,
                        line=1,
                        column=1,
                        message="file could not be parsed",
                    )
                )
            continue

        if file_size > max_file_bytes:
            if "PY000" in allowed_rules:
                all_findings.append(
                    Finding(
                        rule_id="PY000",
                        severity=RULES["PY000"].severity,
                        path=posix_path,
                        line=1,
                        column=1,
                        message="file too large",
                    )
                )
            continue

        try:
            raw_bytes = file_path.read_bytes()
            source = raw_bytes.decode("utf-8")
        except (UnicodeDecodeError, OSError):
            if "PY000" in allowed_rules:
                all_findings.append(
                    Finding(
                        rule_id="PY000",
                        severity=RULES["PY000"].severity,
                        path=posix_path,
                        line=1,
                        column=1,
                        message="file could not be parsed",
                    )
                )
            continue

        findings = scan_source(source, path=posix_path, rules=rules)
        all_findings.extend(findings)

    all_findings.sort(key=lambda x: (x.path, x.line, x.column, x.rule_id))
    return all_findings
