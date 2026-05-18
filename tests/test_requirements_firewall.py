"""Tests for requirements generation and firewall plan endpoints."""
import pytest
from conftest import SAMPLE_DEVICE


def _seed_device(client, device=None):
    client.post("/tools/api/devices/save", json={"devices": [device or SAMPLE_DEVICE]})


def test_generate_requirements_empty(client):
    """generate_requirements on empty inventory returns ok=True with zero results."""
    resp = client.post("/tools/api/generate_requirements", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("count") == 0
    assert isinstance(data.get("results"), list)
    assert "summary" in data


def test_generate_requirements_with_devices(client):
    """generate_requirements returns one result row per device."""
    _seed_device(client)
    resp = client.post("/tools/api/generate_requirements", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("count") == 1


def test_generate_requirements_inline_devices(client):
    """Passing devices[] inline bypasses stored inventory."""
    two_devices = [
        {**SAMPLE_DEVICE, "ip": "10.0.1.1"},
        {**SAMPLE_DEVICE, "ip": "10.0.1.2", "name": "sw-02"},
    ]
    resp = client.post("/tools/api/generate_requirements", json={"devices": two_devices})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("count") == 2


def test_generate_firewall_plan_empty(client):
    """generate_firewall_plan on empty inventory returns ok=True."""
    resp = client.post("/tools/api/generate_firewall_plan", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True


def test_generate_firewall_plan_with_device(client):
    """generate_firewall_plan with a seeded device does not crash."""
    _seed_device(client)
    resp = client.post("/tools/api/generate_firewall_plan", json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    # Rules may be at top level or nested under firewall_plan
    has_rules = "rules" in data or "firewall_plan" in data or "count" in data
    assert has_rules
