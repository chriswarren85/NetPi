"""Tests for AF-05: after_request hook enforces ok/error/timestamp on /tools/api/ errors."""
import re

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def test_ok_false_gets_timestamp(client):
    resp = client.post("/tools/api/devices/add_manual", json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data.get("ok") is False
    assert data.get("success") is False
    assert "error" in data
    assert TIMESTAMP_RE.match(data.get("timestamp") or "")


def test_error_without_ok_gets_ok_and_timestamp(client):
    resp = client.post("/tools/api/fingerprint_host", json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data.get("ok") is False
    assert data.get("error") == "Missing IP"
    assert TIMESTAMP_RE.match(data.get("timestamp") or "")


def test_unknown_job_404_shape(client):
    resp = client.get("/tools/api/discover_hosts/status/nope")
    assert resp.status_code == 404
    data = resp.get_json()
    assert data.get("ok") is False
    assert TIMESTAMP_RE.match(data.get("timestamp") or "")


def test_success_untouched(client):
    resp = client.get("/tools/api/projects")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert "timestamp" not in data


def test_non_api_untouched(client):
    resp = client.get("/tools/settings")
    assert resp.status_code == 200
    assert not resp.is_json
