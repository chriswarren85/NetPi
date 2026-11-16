"""Tests for AF-06: split shadowed _normalize_validation_status."""
import ast
import os

import app


def test_export_status():
    assert app._normalize_export_status("ok") == "PASS"
    assert app._normalize_export_status("info") == "PASS"
    assert app._normalize_export_status("warning") == "WARN"
    assert app._normalize_export_status("error") == "FAIL"
    assert app._normalize_export_status("") == "UNKNOWN"


def test_report_status_unchanged():
    assert app._normalize_validation_status("ok") == "pass"
    assert app._normalize_validation_status("warning") == "warn"
    assert app._normalize_validation_status("info") == "warn"
    assert app._normalize_validation_status("error") == "fail"
    assert app._normalize_validation_status("") == "unknown"


def test_export_rows_info_is_pass_with_note():
    device_rows, _ = app._build_validation_export_rows(
        [
            {
                "name": "DSP-01",
                "ip": "10.0.0.5",
                "results": [
                    {"check": "ping", "status": "pass"},
                    {"check": "conn", "status": "info"},
                ],
            }
        ],
        [],
    )
    assert [row["result"] for row in device_rows] == ["PASS", "PASS"]
    assert device_rows[0]["recommended action"] == "No action required."
    assert device_rows[1]["recommended action"] == app.EXPORT_INFO_NOTE


def test_no_duplicate_top_level_functions():
    app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
    with open(app_path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=app_path)

    seen = {}
    duplicates = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in seen:
                duplicates.append((node.name, seen[node.name], node.lineno))
            else:
                seen[node.name] = node.lineno

    assert not duplicates, f"duplicate top-level function definitions found: {duplicates}"
