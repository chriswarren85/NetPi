"""Tests for project switching and data isolation."""
import json
import pytest
from conftest import SAMPLE_DEVICE


def test_list_projects(client):
    """GET /api/projects returns ok=True and includes default project."""
    resp = client.get("/tools/api/projects")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert "projects" in data
    assert "active_project_id" in data


def test_create_project(client):
    """Creating a new project returns ok=True with the new project_id."""
    resp = client.post("/tools/api/projects/create", json={"project_id": "test-proj"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("project_id") == "test-proj"


def test_create_duplicate_project_fails(client):
    """Creating a project that already exists returns an error."""
    client.post("/tools/api/projects/create", json={"project_id": "dupe-proj"})
    resp = client.post("/tools/api/projects/create", json={"project_id": "dupe-proj"})
    assert resp.status_code in (400, 409)
    data = resp.get_json()
    assert data.get("ok") is False


def test_switch_project(client):
    """Switching to a new project updates active_project_id."""
    client.post("/tools/api/projects/create", json={"project_id": "proj-b"})
    resp = client.post("/tools/api/projects/switch", json={"project_id": "proj-b"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("active_project_id") == "proj-b"


def test_project_data_isolation(client, tmp_data_dir):
    """Devices saved in project A are not visible after switching to project B."""
    import app as netpi_app

    # Seed a device in the default project
    client.post("/tools/api/devices/save", json={"devices": [SAMPLE_DEVICE]})

    # Create and switch to project B
    client.post("/tools/api/projects/create", json={"project_id": "isolated-b"})
    client.post("/tools/api/projects/switch", json={"project_id": "isolated-b"})

    # Active project is now isolated-b — its device list should be empty
    devices_b = netpi_app.load_devices()
    assert len(devices_b) == 0, "Project B should not inherit Project A's devices"
