"""Comprehensive tests for trysac-sast-rules-mini static analysis package."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sast_rules_mini import (
    SastError,
    format_text,
    scan_paths,
    scan_source,
    to_sarif,
)
from sast_rules_mini.__main__ import main


def test_rule_py002_subprocess_run_shell() -> None:
    # Acceptance test 1
    source_bad = "import subprocess as sp\nsp.run(cmd, shell=True)\n"
    res_bad = scan_source(source_bad)
    assert len(res_bad) == 1
    f = res_bad[0]
    assert f.rule_id == "PY002"
    assert f.severity == "high"
    assert f.path == "<string>"
    assert f.line == 2
    assert f.column == 1

    source_good = "import subprocess as sp\nsp.run(cmd, shell=False)\n"
    assert scan_source(source_good) == []


def test_rule_py001_eval_exec_and_py002_os_and_py003_deserialization() -> None:
    # Acceptance test 2
    # eval(x) returns PY001 while obj.eval(x) returns nothing
    assert any(f.rule_id == "PY001" for f in scan_source("eval(x)"))
    assert not any(f.rule_id == "PY001" for f in scan_source("obj.eval(x)"))
    assert any(f.rule_id == "PY001" for f in scan_source("exec(x)"))
    assert not any(f.rule_id == "PY001" for f in scan_source("obj.exec(x)"))

    # os.system(c) and 'from os import popen\npopen(c)' return PY002
    res_sys = scan_source("import os\nos.system(c)")
    assert any(f.rule_id == "PY002" for f in res_sys)
    res_popen = scan_source("from os import popen\npopen(c)")
    assert any(f.rule_id == "PY002" for f in res_popen)

    # pickle.loads(b) and marshal.load(f) return PY003
    res_pickle = scan_source("import pickle\npickle.loads(b)")
    assert any(f.rule_id == "PY003" for f in res_pickle)
    res_marshal = scan_source("import marshal\nmarshal.load(f)")
    assert any(f.rule_id == "PY003" for f in res_marshal)
    res_shelve = scan_source("import shelve\nshelve.open('f')")
    assert any(f.rule_id == "PY003" for f in res_shelve)


def test_rule_py004_yaml_loaders() -> None:
    # Acceptance test 3
    # 'from yaml import load\nload(s)\n' returns PY004
    res1 = scan_source("from yaml import load\nload(s)\n")
    assert any(f.rule_id == "PY004" for f in res1)

    # yaml.load(s, Loader=yaml.SafeLoader) and yaml.safe_load(s) return nothing
    res2 = scan_source("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)")
    assert not any(f.rule_id == "PY004" for f in res2)
    res3 = scan_source("import yaml\nyaml.safe_load(s)")
    assert not any(f.rule_id == "PY004" for f in res3)

    # yaml.load(s, Loader=yaml.FullLoader) returns PY004
    res4 = scan_source("import yaml\nyaml.load(s, Loader=yaml.FullLoader)")
    assert any(f.rule_id == "PY004" for f in res4)

    # Bare CSafeLoader imported
    res5 = scan_source("from yaml import load, CSafeLoader\nload(s, Loader=CSafeLoader)")
    assert not any(f.rule_id == "PY004" for f in res5)


def test_rule_py005_hashlib() -> None:
    # Acceptance test 4
    # hashlib.md5(b'x') and hashlib.new('sha1') return PY005 with severity 'medium'
    res1 = scan_source("import hashlib\nhashlib.md5(b'x')")
    assert any(f.rule_id == "PY005" and f.severity == "medium" for f in res1)

    res2 = scan_source("import hashlib\nhashlib.new('sha1')")
    assert any(f.rule_id == "PY005" and f.severity == "medium" for f in res2)

    # hashlib.md5(b'x', usedforsecurity=False) returns nothing
    res3 = scan_source("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)")
    assert not any(f.rule_id == "PY005" for f in res3)

    # hashlib.new('SHA1', usedforsecurity=False)
    res4 = scan_source("import hashlib\nhashlib.new('SHA1', usedforsecurity=False)")
    assert not any(f.rule_id == "PY005" for f in res4)

    # Safe hash sha256
    res5 = scan_source("import hashlib\nhashlib.sha256(b'x')")
    assert not any(f.rule_id == "PY005" for f in res5)


def test_rule_py007_hardcoded_secrets() -> None:
    # Acceptance test 5
    # db_password = 'hunter2' returns PY007 and neither format_text nor to_sarif output contains 'hunter2'
    # while db_password = '' and PASSWORD_FIELD = 'pw' return nothing
    findings = scan_source("db_password = 'hunter2'")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY007"
    text_out = format_text(findings)
    assert "hunter2" not in text_out
    sarif_out = to_sarif(findings)
    assert "hunter2" not in json.dumps(sarif_out)
    assert "db_password" in findings[0].message

    # Empty string
    assert scan_source("db_password = ''") == []
    # PASSWORD_FIELD does not match regex (^|_)(password|passwd|secret|token|api_key)$
    assert scan_source("PASSWORD_FIELD = 'pw'") == []
    # Matching variations
    assert len(scan_source("user_api_key = 'secret'")) == 1
    assert len(scan_source("my_token: str = 'token_abc'")) == 1
    assert len(scan_source("obj.passwd = 'test'")) == 1


def test_rule_py008_sql_injection() -> None:
    # Acceptance test 6
    # cursor.execute(f'SELECT * FROM t WHERE id = {i}'), cursor.execute('SELECT ' + col)
    # and cursor.execute('SELECT {}'.format(c)) return PY008,
    # and cursor.execute('SELECT * FROM t WHERE id = %s', (i,)) returns nothing
    res1 = scan_source("cursor.execute(f'SELECT * FROM t WHERE id = {i}')")
    assert any(f.rule_id == "PY008" for f in res1)

    res2 = scan_source("cursor.execute('SELECT ' + col)")
    assert any(f.rule_id == "PY008" for f in res2)

    res3 = scan_source("cursor.execute('SELECT {}'.format(c))")
    assert any(f.rule_id == "PY008" for f in res3)

    res_safe = scan_source("cursor.execute('SELECT * FROM t WHERE id = %s', (i,))")
    assert not any(f.rule_id == "PY008" for f in res_safe)

    # executemany variation and % formatting
    res4 = scan_source("cursor.executemany('SELECT ' % var, items)")
    assert any(f.rule_id == "PY008" for f in res4)
    # Constant BinOp is fine
    res_const_binop = scan_source("cursor.execute('SELECT ' + '1')")
    assert not any(f.rule_id == "PY008" for f in res_const_binop)


def test_rule_py006_py009_py010() -> None:
    # PY006: requests and ssl
    res_req = scan_source("import requests\nrequests.get('https://example.com', verify=False)")
    assert any(f.rule_id == "PY006" for f in res_req)
    res_ssl = scan_source("import ssl\nssl._create_unverified_context()")
    assert any(f.rule_id == "PY006" for f in res_ssl)

    # PY009: tempfile.mktemp
    res_mktemp = scan_source("import tempfile\ntempfile.mktemp()")
    assert any(f.rule_id == "PY009" for f in res_mktemp)

    # PY010: .run(debug=True)
    res_flask = scan_source("app.run(debug=True)")
    assert any(f.rule_id == "PY010" for f in res_flask)
    res_flask_safe = scan_source("app.run(debug=False)")
    assert not any(f.rule_id == "PY010" for f in res_flask_safe)


def test_nosast_inline_suppressions() -> None:
    # Acceptance test 7
    # A trailing comment '# nosast: PY002' removes only PY002 findings on that line,
    # and '# nosast' removes every finding on that line
    src1 = "import subprocess as sp\nsp.run(cmd, shell=True)  # nosast: PY002\n"
    assert scan_source(src1) == []

    # Suppress only PY002 but line has PY001 as well
    src2 = "eval(x); sp.run(cmd, shell=True)  # nosast: PY002\n"
    findings2 = scan_source(src2)
    assert len(findings2) == 1
    assert findings2[0].rule_id == "PY001"

    # Complete suppression with # nosast
    src3 = "eval(x); sp.run(cmd, shell=True)  # nosast\n"
    assert scan_source(src3) == []


def test_sarif_output_and_unicode_codepoints() -> None:
    # Acceptance test 8
    # to_sarif(...) has version '2.1.0', runs[0].columnKind 'unicodeCodePoints', and for path 'src\\app.py'
    # with line 'x = "\u00e9"; eval(y)' the result has ruleId 'PY001', level 'error',
    # artifactLocation.uri 'src/app.py', startLine 1 and startColumn 10
    source = 'x = "\u00e9"; eval(y)'
    findings = scan_source(source, path="src\\app.py")
    assert len(findings) == 1
    sarif = to_sarif(findings)

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["columnKind"] == "unicodeCodePoints"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "PY001"
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/app.py"
    assert loc["region"]["startLine"] == 1
    assert loc["region"]["startColumn"] == 10


def test_scan_paths_and_py000(tmp_path: Path) -> None:
    # Acceptance test 9 & 10
    # A file of 1_048_577 bytes yields PY000 with message 'file too large' without being parsed,
    # and scan_paths skips directories named '.git', '.venv', 'venv' and 'node_modules'
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("a = 1\n", encoding="utf-8")

    large_file = tmp_path / "large.py"
    large_file.write_bytes(b" " * 1_048_577)

    syntax_err_file = tmp_path / "syntax_err.py"
    syntax_err_file.write_text("def foo(:\n", encoding="utf-8")

    null_byte_file = tmp_path / "binary.py"
    null_byte_file.write_bytes(b"def foo(): \x00 return 1\n")

    # Skipped folders
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "bad.py").write_text("eval(x)", encoding="utf-8")

    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "bad.py").write_text("eval(x)", encoding="utf-8")

    findings = scan_paths([tmp_path])
    # Should contain large_file PY000, syntax_err PY000, and null_byte PY000
    messages = {f.message for f in findings}
    assert "file too large" in messages
    assert "file could not be parsed" in messages
    # Git and venv should NOT be scanned
    paths = [f.path for f in findings]
    assert not any(".git" in p or ".venv" in p for p in paths)


def test_cli_main(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Acceptance test 9
    # main(['--format', 'sarif', d]) returns 1 and prints JSON when d has findings,
    # returns 0 for a clean directory and 2 for a missing path; a file with a syntax error
    # or a '\x00' byte yields one PY000 finding while other files are still scanned
    bad_dir = tmp_path / "bad_dir"
    bad_dir.mkdir()
    (bad_dir / "app.py").write_text("eval(x)\n", encoding="utf-8")

    clean_dir = tmp_path / "clean_dir"
    clean_dir.mkdir()
    (clean_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

    # Clean directory -> exit 0
    ret_clean = main([str(clean_dir)])
    assert ret_clean == 0
    capsys.readouterr()

    # Directory with findings, sarif format -> exit 1
    ret_bad = main(["--format", "sarif", str(bad_dir)])
    assert ret_bad == 1
    captured = capsys.readouterr()
    sarif_json = json.loads(captured.out)
    assert sarif_json["version"] == "2.1.0"

    # Missing path -> exit 2
    ret_missing = main([str(tmp_path / "non_existent_path")])
    assert ret_missing == 2


def test_cli_output_file_and_min_severity(tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text("import hashlib\nhashlib.md5(b'x')\neval('x')\n", encoding="utf-8")

    out_file = tmp_path / "report.txt"
    ret = main(["--output", str(out_file), "--min-severity", "high", str(file_path)])
    assert ret == 1
    content = out_file.read_text(encoding="utf-8")
    assert "PY001" in content
    assert "PY005" not in content


def test_sast_error_max_files(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"test_{i}.py").write_text("a = 1", encoding="utf-8")
    with pytest.raises(SastError) as exc_info:
        scan_paths([tmp_path], max_files=3)
    assert exc_info.value.code == "too_many_files"


def test_rules_filter_and_formatting() -> None:
    res = scan_source("eval(x)", rules=["PY002"])
    assert res == []

    assert format_text([]) == "No findings detected."
