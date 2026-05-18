"""
Pytest configuration and shared fixtures for NetPi.

The app uses a global DATA_DIR and active_project_id session.
We override DATA_DIR to a temp directory and inject a clean project for each test.
"""
import json
import os
import pytest
import tempfile


@pytest.fixture()
def tmp_data_dir(monkeypatch, tmp_path):
    """Point DATA_DIR at a fresh temp directory and seed a default project."""
    import app as netpi_app

    monkeypatch.setattr(netpi_app, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(netpi_app, "_ACTIVE_PROJECT_ID", "default")

    # Create the default project directory with empty device/settings files
    project_dir = tmp_path / "default"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "devices.json").write_text(json.dumps({"devices": []}), encoding="utf-8")
    (project_dir / "settings.json").write_text(json.dumps({}), encoding="utf-8")
    (project_dir / "fingerprints.json").write_text(json.dumps({}), encoding="utf-8")
    (project_dir / "device_evidence.json").write_text(json.dumps({}), encoding="utf-8")

    return tmp_path


@pytest.fixture()
def client(tmp_data_dir):
    """Flask test client with a fresh data directory."""
    import app as netpi_app

    netpi_app.app.config["TESTING"] = True
    with netpi_app.app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Sample device payloads
# ---------------------------------------------------------------------------

SAMPLE_DEVICE = {
    "name": "sw-core-01",
    "ip": "10.0.1.1",
    "type": "switch",
    "vlan": "10",
    "mac": "AA:BB:CC:DD:EE:FF",
    "vendor": "Cisco",
    "notes": "Core switch",
}

SAMPLE_PASTE = (
    "name\tip\ttype\tvlan\n"
    "amp-01\t10.0.1.10\tamplifier\t20\n"
    "dsp-01\t10.0.1.11\tdsp\t20\n"
)
