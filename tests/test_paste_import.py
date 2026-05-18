"""Tests for the paste-based device import flow."""
import pytest
from conftest import SAMPLE_PASTE


def test_preview_pasted_returns_shape(client):
    """preview_pasted returns expected envelope keys."""
    resp = client.post(
        "/tools/api/devices/preview_pasted",
        json={"text": SAMPLE_PASTE},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    for key in ("headers_detected", "rows_total", "rows_valid", "devices"):
        assert key in data, f"missing key: {key}"


def test_preview_pasted_device_count(client):
    """Preview correctly counts two valid device rows from the sample paste."""
    resp = client.post(
        "/tools/api/devices/preview_pasted",
        json={"text": SAMPLE_PASTE},
    )
    data = resp.get_json()
    assert data["rows_valid"] == 2
    assert data["rows_duplicate"] == 0
    # rows_total may include header row depending on parser implementation
    assert data["rows_total"] >= 2


def test_import_pasted_adds_devices(client):
    """import_pasted commits new devices and returns added count."""
    resp = client.post(
        "/tools/api/devices/import_pasted",
        json={"text": SAMPLE_PASTE},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("added") == 2
    assert data.get("skipped_count", 0) == 0


def test_import_pasted_duplicate_skipped(client):
    """Importing the same paste twice skips all rows on second import."""
    client.post("/tools/api/devices/import_pasted", json={"text": SAMPLE_PASTE})
    resp = client.post("/tools/api/devices/import_pasted", json={"text": SAMPLE_PASTE})
    data = resp.get_json()
    assert data.get("added", 0) == 0
    assert data.get("skipped_count", 0) == 2


def test_import_pasted_invalid_ip_ignored(client):
    """Rows with invalid IPs are not added; valid rows are still committed."""
    bad_paste = "name\tip\ttype\n" "good-dev\t10.0.2.1\tswitch\n" "bad-dev\tnot-an-ip\tswitch\n"
    resp = client.post("/tools/api/devices/import_pasted", json={"text": bad_paste})
    data = resp.get_json()
    # The valid row is committed; the invalid-IP row is rejected at parse or import stage
    assert data.get("added") == 1
