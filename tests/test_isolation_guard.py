"""Tests for AF-13: pytest must never touch the real data/current_project.json."""
import os

import app

_REAL_STATE_FILE = os.path.join(os.path.dirname(app.__file__), "data", "current_project.json")

if os.path.exists(_REAL_STATE_FILE):
    _REAL_MTIME_BEFORE = os.path.getmtime(_REAL_STATE_FILE)
    with open(_REAL_STATE_FILE, encoding="utf-8") as _f:
        _REAL_CONTENT_BEFORE = _f.read()
else:
    _REAL_MTIME_BEFORE = None
    _REAL_CONTENT_BEFORE = None


def test_real_state_file_untouched(client, tmp_data_dir):
    if _REAL_CONTENT_BEFORE is None:
        import pytest
        pytest.skip("real data/current_project.json does not exist")

    client.post("/tools/api/projects/create", json={"project_id": "guard-proj"})
    client.post("/tools/api/projects/switch", json={"project_id": "guard-proj"})

    with open(_REAL_STATE_FILE, encoding="utf-8") as f:
        content_after = f.read()
    mtime_after = os.path.getmtime(_REAL_STATE_FILE)

    assert content_after == _REAL_CONTENT_BEFORE
    assert mtime_after == _REAL_MTIME_BEFORE
    assert str(app.CURRENT_PROJECT_STATE_FILE).startswith(str(tmp_data_dir))
