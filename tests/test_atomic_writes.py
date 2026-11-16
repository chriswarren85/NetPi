"""Tests for AF-02: save_run and AI baseline record route through safe_write_json."""
import json
import os

import pytest


def test_save_run_uses_safe_write_json(tmp_data_dir, monkeypatch):
    import app as netpi_app

    calls = []
    real_safe_write_json = netpi_app.safe_write_json

    def spy(path, data, **kwargs):
        calls.append(path)
        return real_safe_write_json(path, data, **kwargs)

    monkeypatch.setattr(netpi_app, "safe_write_json", spy)

    path = netpi_app.save_run({"x": 1})

    assert len(calls) == 1
    assert calls[0] == path
    with open(path) as f:
        assert json.load(f) == {"x": 1}
    assert not os.path.exists(path + ".tmp")


def test_ai_baseline_record_uses_safe_write_json(client, monkeypatch):
    import app as netpi_app

    calls = []
    real_safe_write_json = netpi_app.safe_write_json

    def spy(path, data, **kwargs):
        calls.append(path)
        return real_safe_write_json(path, data, **kwargs)

    monkeypatch.setattr(netpi_app, "safe_write_json", spy)

    resp = client.post("/tools/api/ai/baseline/record", json={})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert len(calls) == 1
    assert calls[0].endswith("baseline.json")
