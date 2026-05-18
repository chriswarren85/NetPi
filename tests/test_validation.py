"""Tests for validation run and result shape."""
import pytest
from conftest import SAMPLE_DEVICE


def _seed_device(client, device=None):
    device = device or SAMPLE_DEVICE
    client.post("/tools/api/devices/save", json={"devices": [device]})


def test_validate_all_empty_inventory(client):
    """validate_all on empty inventory returns ok=True with zero results."""
    resp = client.post("/tools/api/validate_all", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("count") == 0
    assert isinstance(data.get("results"), list)


def test_validate_all_response_shape(client):
    """validate_all with one device returns the expected envelope structure."""
    _seed_device(client)
    resp = client.post("/tools/api/validate_all", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert "count" in data
    assert "results" in data
    assert "detected_systems" in data


def test_validate_all_result_row_keys(client):
    """Each result row must contain at minimum ip and effective_type."""
    _seed_device(client)
    resp = client.post("/tools/api/validate_all", json={})
    data = resp.get_json()
    assert data["count"] >= 1
    row = data["results"][0]
    for key in ("ip", "effective_type"):
        assert key in row, f"missing key in result row: {key}"


def test_validate_all_vlan_filter(client):
    """VLAN filter narrows results; unmatched VLAN returns zero results."""
    devices = [
        {**SAMPLE_DEVICE, "ip": "10.0.1.1", "mac": "AA:BB:CC:DD:EE:01"},
        {**SAMPLE_DEVICE, "ip": "10.0.1.2", "name": "dev-2", "mac": "AA:BB:CC:DD:EE:02"},
    ]
    save_resp = client.post("/tools/api/devices/save", json={"devices": devices})
    assert save_resp.get_json().get("success") is True

    # Filter for a VLAN ID that no device has → zero results
    resp = client.post("/tools/api/validate_all", json={"vlan": "nonexistent-vlan"})
    data = resp.get_json()
    assert data.get("ok") is True
    assert data["count"] == 0
