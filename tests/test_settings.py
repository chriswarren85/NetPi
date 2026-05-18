"""Tests for settings load and save."""
import pytest


def test_settings_page_loads(client):
    """GET /tools/settings returns 200 HTML."""
    resp = client.get("/tools/settings")
    assert resp.status_code == 200
    assert b"<!DOCTYPE html" in resp.data or b"<html" in resp.data


def test_ipschedule_api(client):
    """GET /api/ipschedule returns ok=True with expected structure."""
    resp = client.get("/tools/api/ipschedule")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert "devices" in data
    assert isinstance(data["devices"], list)


def test_project_name_api(client):
    """GET /api/project-name returns a string (may be empty for a fresh project)."""
    resp = client.get("/tools/api/project-name")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data.get("name"), str)
