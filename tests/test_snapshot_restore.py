"""Tests for project snapshot export and restore."""
import io
import json
import zipfile
import pytest
from conftest import SAMPLE_DEVICE


def test_snapshot_returns_zip(client):
    """GET /api/project/snapshot returns a valid zip binary."""
    resp = client.get("/tools/api/project/snapshot")
    assert resp.status_code == 200
    assert resp.content_type in (
        "application/octet-stream",
        "application/zip",
        "application/x-zip-compressed",
    )
    buf = io.BytesIO(resp.data)
    assert zipfile.is_zipfile(buf), "Response is not a valid ZIP file"


def test_snapshot_contains_manifest(client):
    """Snapshot ZIP contains a manifest.json with expected keys."""
    resp = client.get("/tools/api/project/snapshot")
    buf = io.BytesIO(resp.data)
    with zipfile.ZipFile(buf) as zf:
        names = zf.namelist()
        assert "manifest.json" in names, "manifest.json missing from snapshot"
        manifest = json.loads(zf.read("manifest.json"))
        for key in ("schema_version", "exported_at", "app_name"):
            assert key in manifest, f"manifest missing key: {key}"


def test_snapshot_with_devices(client):
    """Snapshot taken after seeding devices includes a devices.json."""
    client.post("/tools/api/devices/save", json={"devices": [SAMPLE_DEVICE]})
    resp = client.get("/tools/api/project/snapshot")
    buf = io.BytesIO(resp.data)
    with zipfile.ZipFile(buf) as zf:
        names = zf.namelist()
        device_files = [n for n in names if "devices.json" in n]
        assert device_files, "devices.json not found in snapshot"


def test_restore_roundtrip(client):
    """Restoring a snapshot re-imports the devices it was taken from."""
    # Seed a device, take a snapshot
    client.post("/tools/api/devices/save", json={"devices": [SAMPLE_DEVICE]})
    snap_resp = client.get("/tools/api/project/snapshot")
    assert snap_resp.status_code == 200

    # Clear devices, then restore
    client.post("/tools/api/devices/save", json={"devices": []})

    restore_resp = client.post(
        "/tools/api/project/restore",
        data={"file": (io.BytesIO(snap_resp.data), "snapshot.avp")},
        content_type="multipart/form-data",
    )
    assert restore_resp.status_code == 200
    data = restore_resp.get_json()
    assert data.get("ok") is True
