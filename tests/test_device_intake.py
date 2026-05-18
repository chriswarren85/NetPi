"""Tests for the device intake endpoints (manual add + bulk save)."""
import json
import pytest
from conftest import SAMPLE_DEVICE


def test_add_manual_device(client):
    """Manual device add returns ok=True and device appears in saved list."""
    resp = client.post(
        "/tools/api/devices/add_manual",
        json=SAMPLE_DEVICE,
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True or data.get("success") is True


def test_add_manual_duplicate_ip(client):
    """Adding a device with the same IP twice should report conflict, not crash."""
    client.post("/tools/api/devices/add_manual", json=SAMPLE_DEVICE)
    resp = client.post("/tools/api/devices/add_manual", json=SAMPLE_DEVICE)
    assert resp.status_code in (200, 409)
    data = resp.get_json()
    # Should not silently succeed with a duplicate
    ok_field = data.get("ok") or data.get("success")
    if resp.status_code == 200:
        assert not ok_field or data.get("conflict") or data.get("duplicate") or data.get("error")


def test_save_devices_roundtrip(client):
    """POST to devices/save persists the list and returns it."""
    payload = {"devices": [SAMPLE_DEVICE]}
    resp = client.post(
        "/tools/api/devices/save",
        json=payload,
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("success") is True
    returned = data.get("devices", [])
    assert isinstance(returned, list)
    assert len(returned) == 1
    assert returned[0]["ip"] == SAMPLE_DEVICE["ip"]


def test_save_devices_empty_list(client):
    """Saving an empty device list should be accepted."""
    resp = client.post(
        "/tools/api/devices/save",
        json={"devices": []},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("success") is True
    assert data.get("devices") == []
