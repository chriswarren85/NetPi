from flask import Flask, render_template, request, jsonify, redirect, send_file
import json, os, subprocess, csv
from datetime import datetime
import copy
import socket
import platform
import threading
import uuid
import queue
import time
import signal
import zipfile
import shutil
from command_helpers import (
    build_nmap_command,
    build_nmap_host_discovery_command,
    build_ping_command,
    build_traceroute_command,
    build_arp_lookup_commands,
)
from checks.network import run_base_checks
from checks.devices import run_device_checks
import io
import ipaddress
import re
from checks.validation import (
    SYSTEM_VALIDATION_RULES,
    run_validation,
    run_validation_for_all,
    run_system_validation,
    run_connectivity_validation,
    summarize_connectivity_results,
    resolve_passive_mac,
)
from checks.flows import (
    generate_flows_from_system_results,
    generate_flows_from_connectivity_results,
)
from checks.system_requirements import aggregate_flows_by_system
from checks.requirements import (
    load_requirements_config,
    generate_device_requirements,
)
try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        nextCmd,
    )
    SNMP_HLAPI_AVAILABLE = True
except Exception:
    CommunityData = ContextData = ObjectIdentity = ObjectType = SnmpEngine = UdpTransportTarget = None
    getCmd = nextCmd = None
    SNMP_HLAPI_AVAILABLE = False

app = Flask(__name__)
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
DEFAULT_PROJECT_ID = "default"
CURRENT_PROJECT_STATE_FILE = os.path.join(DATA_DIR, "current_project.json")
PROJECT_BACKUPS_DIRNAME = "project_backups"
PROJECTS_STATE_RESERVED_NAMES = {
    PROJECT_BACKUPS_DIRNAME,
    "__pycache__",
}
LEGACY_SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")
LEGACY_DEVICES_FILE = os.path.join(BASE_DIR, "devices.json")
LEGACY_TOPOLOGY_FILE = os.path.join(BASE_DIR, "topology.json")
LEGACY_MULTICAST_GROUPS_FILE = os.path.join(BASE_DIR, "multicast_groups.json")
LEGACY_FINGERPRINTS_FILE = os.path.join(DATA_DIR, "fingerprints.json")
LEGACY_DEVICE_EVIDENCE_FILE = os.path.join(DATA_DIR, "device_evidence.json")
BACKGROUND_JOBS = {}
BACKGROUND_JOBS_LOCK = threading.Lock()
DEVICE_EVIDENCE_LOCK = threading.Lock()
PROJECT_STATE_LOCK = threading.Lock()
DISCOVERY_SUBNET_TIMEOUT_SECONDS = 10
_SETTINGS_LOAD_LOGGED = False
_ACTIVE_PROJECT_ID = DEFAULT_PROJECT_ID
SNAPSHOT_SCHEMA_VERSION = "1.0"
PROJECT_STATE_REQUIRED_FILES = [
    "devices.json",
    "settings.json",
    "data/fingerprints.json",
    "data/device_evidence.json",
]
PROJECT_STATE_OPTIONAL_FILES = [
    "topology.json",
    "multicast_groups.json",
    "requirements.json",
    "flows.json",
    "firewall_plan.json",
    "recommendations.json",
    "report.json",
    "data/requirements.json",
    "data/flows.json",
    "data/firewall_plan.json",
    "data/recommendations.json",
    "data/report.json",
]
PROJECT_RESTORE_ALLOWLIST = set(PROJECT_STATE_REQUIRED_FILES + [
    "topology.json",
    "multicast_groups.json",
    "requirements.json",
    "flows.json",
    "firewall_plan.json",
    "recommendations.json",
    "report.json",
    "data/requirements.json",
    "data/flows.json",
    "data/firewall_plan.json",
    "data/recommendations.json",
    "data/report.json",
])
SNAPSHOT_COMPARE_DEVICE_FIELDS = [
    "ip",
    "name",
    "hostname",
    "type",
    "effective_type",
    "suggested_type",
    "mac",
    "mac_address",
    "vlan",
    "zone",
    "room",
    "status",
    "reachable",
    "reachability",
    "confidence",
    "confidence_score",
    "open_ports",
]
SNAPSHOT_COMPARE_ARTIFACT_PATHS = {
    "topology": ["topology.json"],
    "multicast_groups": ["multicast_groups.json"],
    "recommendations": ["recommendations.json", "data/recommendations.json"],
    "requirements": ["requirements.json", "data/requirements.json"],
    "flows": ["flows.json", "data/flows.json"],
    "firewall_plan": ["firewall_plan.json", "data/firewall_plan.json"],
    "report": ["report.json", "data/report.json"],
}


def _sanitize_project_id(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", text):
        return ""
    return text


def _load_current_project_state():
    if not os.path.exists(CURRENT_PROJECT_STATE_FILE):
        return {}
    try:
        with open(CURRENT_PROJECT_STATE_FILE, encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _save_current_project_state(project_id):
    os.makedirs(DATA_DIR, exist_ok=True)
    payload = {
        "active_project_id": project_id,
        "updated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }
    temp_path = CURRENT_PROJECT_STATE_FILE + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temp_path, CURRENT_PROJECT_STATE_FILE)
    except PermissionError:
        with open(CURRENT_PROJECT_STATE_FILE, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


def get_active_project_id():
    with PROJECT_STATE_LOCK:
        return _ACTIVE_PROJECT_ID


def _set_active_project_id(project_id, *, persist=True):
    normalized = _sanitize_project_id(project_id) or DEFAULT_PROJECT_ID
    with PROJECT_STATE_LOCK:
        global _ACTIVE_PROJECT_ID
        _ACTIVE_PROJECT_ID = normalized
        if persist:
            _save_current_project_state(normalized)
    return normalized


def _project_dir(project_id=None, *, ensure=False):
    pid = _sanitize_project_id(project_id or get_active_project_id()) or DEFAULT_PROJECT_ID
    path = os.path.abspath(os.path.join(DATA_DIR, pid))
    if ensure:
        os.makedirs(path, exist_ok=True)
    return path


def get_project_path(filename, project_id=None, *, ensure_parent=False):
    rel = str(filename or "").replace("\\", "/").strip().lstrip("/")
    if not rel or ".." in rel.split("/"):
        raise ValueError(f"Unsafe project path: {filename}")
    path = os.path.abspath(os.path.join(_project_dir(project_id, ensure=True), rel.replace("/", os.sep)))
    if ensure_parent:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return path


def _list_project_ids():
    os.makedirs(DATA_DIR, exist_ok=True)
    found = set()
    for name in os.listdir(DATA_DIR):
        candidate = _sanitize_project_id(name)
        full = os.path.join(DATA_DIR, name)
        if not candidate or candidate in PROJECTS_STATE_RESERVED_NAMES or not os.path.isdir(full):
            continue
        found.add(candidate)
    found.add(DEFAULT_PROJECT_ID)
    return sorted(found)


def _migrate_legacy_data_to_default_project():
    default_dir = _project_dir(DEFAULT_PROJECT_ID, ensure=True)
    _ = default_dir

    legacy_to_project_map = [
        (LEGACY_DEVICES_FILE, "devices.json"),
        (LEGACY_SETTINGS_FILE, "settings.json"),
        (LEGACY_TOPOLOGY_FILE, "topology.json"),
        (LEGACY_MULTICAST_GROUPS_FILE, "multicast_groups.json"),
        (LEGACY_FINGERPRINTS_FILE, "data/fingerprints.json"),
        (LEGACY_DEVICE_EVIDENCE_FILE, "data/device_evidence.json"),
    ]
    for source, rel_target in legacy_to_project_map:
        if not os.path.exists(source):
            continue
        target = get_project_path(rel_target, DEFAULT_PROJECT_ID, ensure_parent=True)
        if os.path.exists(target):
            continue
        try:
            shutil.copy2(source, target)
        except Exception:
            pass


def _initialize_project_state():
    os.makedirs(DATA_DIR, exist_ok=True)
    _migrate_legacy_data_to_default_project()
    state = _load_current_project_state()
    candidate = _sanitize_project_id(state.get("active_project_id") if isinstance(state, dict) else "")
    active = candidate if candidate else DEFAULT_PROJECT_ID
    _project_dir(active, ensure=True)
    _set_active_project_id(active, persist=not candidate)


def _settings_file():
    return get_project_path("settings.json")


def _devices_file():
    return get_project_path("devices.json")


def _fingerprints_file():
    return get_project_path("data/fingerprints.json")


def _device_evidence_file():
    return get_project_path("data/device_evidence.json")


def _topology_file():
    return get_project_path("topology.json")


def _multicast_groups_file():
    return get_project_path("multicast_groups.json")


def _runs_dir():
    return get_project_path("runs")


_initialize_project_state()


def guess_type_from_vendor(vendor_raw):
    vendor = (vendor_raw or "").lower()

    vendor_map = [
        (['crestron'], 'crestron'),
        (['audinate'], 'dante'),
        (['qsc', 'q-sys'], 'qsys'),
        (['biamp'], 'biamp'),
        (['shure'], 'shure'),
        (['novastar'], 'novastar'),
        (['barco'], 'barco_ctrl'),
        (['yamaha'], 'audio-device'),
        (['extron'], 'control-processor'),

        # Displays / projection
        (['samsung', 'lg', 'nec', 'philips'], 'display'),
        (['epson', 'benq'], 'projector'),

        # Cameras
        (['axis', 'hikvision', 'dahua'], 'camera'),

        # Network
        (['netgear', 'cisco', 'aruba', 'juniper', 'hp', 'hpe', 'ruckus', 'ubiquiti'], 'network-device'),

        # Security / firewall
        (['fortinet', 'palo alto', 'sophos'], 'firewall'),

        # VoIP
        (['yealink', 'poly', 'polycom'], 'voip-device'),

        # Printers
        (['brother', 'xerox', 'canon', 'ricoh', 'kyocera', 'lexmark'], 'printer'),
    ]

    for keys, result in vendor_map:
        if any(k in vendor for k in keys):
            return result

    return 'generic'

def device_name_prefix(device_type):
    t = (device_type or "").strip().lower()

    if t in ("display", "camera-or-display"):
        return "LCD"
    elif t == "projector":
        return "PJ"
    elif t == "camera":
        return "CAM"
    elif t in ("network-device", "firewall", "snmp-device", "ssh-device", "telnet-device"):
        return "SW"
    elif t in ("crestron", "control-processor", "barco_ctrl"):
        return "CP"
    elif t in ("qsys", "biamp", "shure", "dante", "audio-device", "voip-device"):
        return "DSP"
    elif t in ("novastar",):
        return "VX"
    elif t in ("printer",):
        return "PRN"
    elif t in ("rtsp-device",):
        return "STREAM"
    elif t in ("artnet", "sacn", "grandma"):
        return "LGT"
    else:
        return "DEV"


def generate_device_name(devices, device_type, preferred_name=""):
    preferred_name = (preferred_name or "").strip()
    if preferred_name:
        return preferred_name

    prefix = device_name_prefix(device_type)
    used_numbers = []

    for d in devices:
        name = (d.get("name") or "").strip().upper()
        if not name.startswith(prefix + "-"):
            continue
        suffix = name[len(prefix) + 1:]
        if suffix.isdigit():
            used_numbers.append(int(suffix))

    n = 1
    while n in used_numbers:
        n += 1

    return f"{prefix}-{n:02d}"


def get_system_gateway():
    try:
        out = subprocess.check_output(['ip', 'route', 'show', 'default'], timeout=5).decode()
        for line in out.splitlines():
            parts = line.split()
            if 'via' in parts:
                return parts[parts.index('via') + 1]
    except Exception:
        pass
    return None


def resolve_gateway(settings):
    for vlan in settings.get('vlans', []):
        gw = vlan.get('gateway')
        if gw:
            return gw

    gw = get_system_gateway()
    if gw:
        return gw

    return '192.168.1.1'


def resolve_subnet(settings):
    for vlan in settings.get('vlans', []):
        subnet = vlan.get('subnet')
        if subnet:
            return subnet
    return '192.168.1.0/24'


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def resolve_selected_subnet(settings, selected_vlan=""):
    selected_vlan = (selected_vlan or "").strip()
    if selected_vlan and "/" in selected_vlan:
        return selected_vlan

    if selected_vlan:
        for vlan in settings.get("vlans", []):
            if (vlan.get("name") or "").strip() == selected_vlan:
                subnet = (vlan.get("subnet") or "").strip()
                if subnet:
                    return subnet
                break

    subnet = resolve_subnet(settings)
    return (subnet or "").strip()


def _discovery_status_message(status, devices_found_count, subnet):
    target = subnet or "selected subnet"
    noun = "host" if devices_found_count == 1 else "hosts"

    if status == "queued":
        return f"Queued discovery for {target}."
    if status == "running":
        return f"Discovery running on {target}: {devices_found_count} live {noun} found so far."
    if status == "completed":
        return f"Discovery completed on {target}: {devices_found_count} live {noun} found."
    if status == "cancelled":
        return f"Discovery cancelled on {target} after finding {devices_found_count} live {noun}."
    if status == "failed":
        return f"Discovery failed on {target}."
    return ""


def _discovery_progress_message(current_subnet, current_index=0, total_subnets=0):
    current_subnet = (current_subnet or "").strip()
    if not current_subnet:
        return ""
    if total_subnets and total_subnets > 1 and current_index:
        return f"Scanning subnet {current_index} of {total_subnets}: {current_subnet}"
    return f"Scanning {current_subnet}..."


def _is_known_discovery_assertion_failure(stderr_output):
    stderr_text = (stderr_output or "").strip()
    if not stderr_text:
        return False

    known_markers = (
        "target.cc:503",
        "htn.toclock_running",
        "assertion",
        "void target::stoptimeoutclock",
    )
    stderr_lower = stderr_text.lower()
    return any(marker in stderr_lower for marker in known_markers)


def _format_discovery_process_error(stderr_output, returncode):
    stderr_text = (stderr_output or "").strip()
    if _is_known_discovery_assertion_failure(stderr_text):
        return (
            "Nmap host discovery failed due to a known scanner assertion "
            "error on this platform/version."
        )
    return stderr_text or f"nmap exited with status {returncode}"


def _get_configured_vlan_subnets(settings):
    subnets = []
    seen = set()

    for vlan in settings.get("vlans", []):
        subnet = (vlan.get("subnet") or "").strip()
        if subnet and subnet not in seen:
            subnets.append(subnet)
            seen.add(subnet)

    return subnets


def _resolve_discovery_subnets(settings, selected_vlan=""):
    selected_vlan = (selected_vlan or "").strip()
    if selected_vlan:
        subnet = resolve_selected_subnet(settings, selected_vlan)
        return [subnet] if subnet else [], False

    subnets = _get_configured_vlan_subnets(settings)
    if subnets:
        return subnets, True

    fallback_subnet = (resolve_subnet(settings) or "").strip()
    return ([fallback_subnet] if fallback_subnet else []), True


def _merge_discovered_devices(*device_groups):
    merged = []
    seen_ips = set()

    for group in device_groups:
        for device in group or []:
            ip = (device.get("ip") or "").strip()
            if ip and ip in seen_ips:
                continue
            if ip:
                seen_ips.add(ip)
            merged.append(device)

    return merged


def _snapshot_background_job(job):
    progress = copy.deepcopy(job.get("progress") or {})
    results = copy.deepcopy(job.get("results") or {})
    snapshot = {
        "job_id": job["job_id"],
        "kind": job.get("kind") or "",
        "status": job["status"],
        "message": job.get("message") or "",
        "started_at": job["started_at"],
        "updated_at": job["updated_at"],
        "progress": progress,
        "results": results,
        "error": job.get("error") or ""
    }

    if snapshot["kind"] == "discover_hosts":
        snapshot["devices_found_count"] = progress.get("devices_found_count", 0)
        snapshot["devices"] = copy.deepcopy(results.get("devices") or [])
        snapshot["subnet"] = results.get("subnet") or ""
        snapshot["subnets"] = copy.deepcopy(results.get("subnets") or [])
        snapshot["current_subnet"] = progress.get("current_subnet", "")
        snapshot["current_subnet_index"] = progress.get("current_subnet_index", 0)
        snapshot["total_subnets"] = progress.get("total_subnets", len(snapshot["subnets"]))
        snapshot["progress_message"] = progress.get("progress_message", "")

    return snapshot


def _get_background_job(job_id):
    with BACKGROUND_JOBS_LOCK:
        return BACKGROUND_JOBS.get(job_id)


def _update_background_job(
    job_id,
    *,
    status=None,
    message=None,
    error=None,
    progress_updates=None,
    results_updates=None,
    mutate_fn=None,
    **extra
):
    with BACKGROUND_JOBS_LOCK:
        job = BACKGROUND_JOBS.get(job_id)
        if not job:
            return None

        if mutate_fn:
            mutate_fn(job)
        if status is not None:
            job["status"] = status
        if message is not None:
            job["message"] = message
        if error is not None:
            job["error"] = error
        if progress_updates:
            progress = job.setdefault("progress", {})
            progress.update(progress_updates)
        if results_updates:
            results = job.setdefault("results", {})
            results.update(results_updates)
        if extra:
            job.update(extra)

        job["updated_at"] = utc_now_iso()
        return _snapshot_background_job(job)


def _create_background_job(kind, *, message="", progress=None, results=None, **extra):
    job_id = uuid.uuid4().hex
    now = utc_now_iso()
    job = {
        "job_id": job_id,
        "kind": kind,
        "status": "queued",
        "message": message,
        "started_at": now,
        "updated_at": now,
        "progress": copy.deepcopy(progress or {}),
        "results": copy.deepcopy(results or {}),
        "error": "",
    }
    job.update(extra)

    with BACKGROUND_JOBS_LOCK:
        BACKGROUND_JOBS[job_id] = job

    return _snapshot_background_job(job)


def _start_background_job(target, *args):
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


def _build_discovery_popen_kwargs():
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return kwargs


def _terminate_lingering_discovery_children(subnet, *, force=False):
    subnet = (subnet or "").strip()
    if os.name == "nt" or not subnet:
        return

    sig = signal.SIGKILL if force else signal.SIGTERM

    try:
        output = subprocess.check_output(
            ["ps", "-eo", "pid=,args="],
            text=True,
            timeout=3,
        )
    except Exception:
        return

    current_pid = os.getpid()
    for raw_line in output.splitlines():
        line = (raw_line or "").strip()
        if not line or f"nmap -sn {subnet}" not in line or "-oG -" not in line:
            continue

        try:
            pid_text, _args = line.split(None, 1)
            pid = int(pid_text)
        except Exception:
            continue

        if pid == current_pid:
            continue

        try:
            os.kill(pid, sig)
        except Exception:
            pass


def _terminate_discovery_process(process, *, force=False, subnet=""):
    if not process or process.poll() is not None:
        _terminate_lingering_discovery_children(subnet, force=force)
        return

    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        else:
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.killpg(os.getpgid(process.pid), sig)
    except Exception:
        try:
            if force:
                process.kill()
            else:
                process.terminate()
        except Exception:
            pass
    finally:
        _terminate_lingering_discovery_children(subnet, force=force)


def _cancel_background_job(job_id, *, expected_kind=None, message=None):
    with BACKGROUND_JOBS_LOCK:
        job = BACKGROUND_JOBS.get(job_id)
        if not job:
            return None
        if expected_kind and (job.get("kind") or "") != expected_kind:
            return None
        if job.get("status") in ("completed", "failed", "cancelled"):
            return _snapshot_background_job(job)

        job["cancel_requested"] = True
        job["status"] = "cancelled"
        if message is not None:
            job["message"] = message
        job["updated_at"] = utc_now_iso()
        process = job.get("process")

    if process:
        subnet = ((job.get("progress") or {}).get("current_subnet") or (job.get("results") or {}).get("subnet") or "")
        _terminate_discovery_process(process, subnet=subnet)

    return _snapshot_background_job(_get_background_job(job_id))


def _create_discovery_job(subnet):
    subnets = [subnet] if subnet else []
    progress_message = _discovery_progress_message(subnet, 1 if subnet else 0, len(subnets))
    return _create_background_job(
        "discover_hosts",
        message=_discovery_status_message("queued", 0, subnet),
        progress={
            "devices_found_count": 0,
            "current_subnet": subnet,
            "current_subnet_index": 1 if subnet else 0,
            "total_subnets": len(subnets),
            "progress_message": progress_message
        },
        results={
            "devices": [],
            "subnet": subnet,
            "subnets": subnets
        },
        cancel_requested=False,
        process=None,
        auto_mode=False
    )


def _get_discovery_job(job_id):
    job = _get_background_job(job_id)
    if not job or (job.get("kind") or "") != "discover_hosts":
        return None
    return job


def _snapshot_discovery_job(job):
    return _snapshot_background_job(job)


def _append_discovery_device(job_id, device):
    def mutate(job):
        results = job.setdefault("results", {})
        devices = results.setdefault("devices", [])
        device_ip = (device.get("ip") or "").strip()
        if device_ip and any((existing.get("ip") or "").strip() == device_ip for existing in devices):
            count = len(devices)
            job.setdefault("progress", {})["devices_found_count"] = count
            return

        devices.append(device)
        count = len(devices)
        progress = job.setdefault("progress", {})
        progress["devices_found_count"] = count
        subnet = results.get("subnet") or ""
        progress_message = progress.get("progress_message") or ""
        status_message = _discovery_status_message(job.get("status"), count, subnet)
        job["message"] = f"{progress_message} {status_message}".strip() if progress_message else status_message

    return _update_background_job(job_id, mutate_fn=mutate)


def _persist_discovery_macs(discovered_devices):
    if not isinstance(discovered_devices, list) or not discovered_devices:
        return

    try:
        devices = load_devices()
    except Exception:
        return

    changed = False
    by_ip = {
        str((device or {}).get("ip") or "").strip(): device
        for device in devices
        if isinstance(device, dict) and str((device or {}).get("ip") or "").strip()
    }

    for discovered in discovered_devices:
        if not isinstance(discovered, dict):
            continue
        ip = str(discovered.get("ip") or "").strip()
        if not ip:
            continue
        existing_device = by_ip.get(ip)
        if not isinstance(existing_device, dict):
            continue

        if _apply_observed_mac(
            existing_device,
            discovered.get("mac") or discovered.get("mac_address"),
            discovered.get("mac_source") or "arp-cache",
        ):
            changed = True

        if not (existing_device.get("vendor") or "").strip():
            vendor_value = str(discovered.get("vendor") or "").strip()
            if vendor_value:
                existing_device["vendor"] = vendor_value
                changed = True

    if changed:
        try:
            save_devices_file(devices)
        except Exception:
            pass


def _extract_mac_from_neighbor_output(output_text):
    mac_match = re.search(r'([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})', str(output_text or ''))
    if not mac_match:
        return ""
    return _normalize_mac_value(mac_match.group(1))


def _lookup_cached_mac_for_ip(ip):
    target_ip = str(ip or "").strip()
    if not target_ip:
        return ""

    for command in build_arp_lookup_commands(target_ip):
        if not command:
            continue
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.DEVNULL,
                timeout=1.2
            ).decode(errors='ignore')
        except Exception:
            continue

        resolved = _extract_mac_from_neighbor_output(output)
        if resolved:
            return resolved

    return ""


def _parse_discovery_line(line):
    if 'Host:' not in line:
        return None

    parts = line.split()
    if len(parts) < 2:
        return None

    ip = parts[1]
    hostname = ''
    reverse_dns = ''
    mdns_name = ''
    mac = ''
    vendor = ''

    if len(parts) > 2 and parts[2].startswith('(') and parts[2].endswith(')'):
        hostname = parts[2].strip('()')

    if 'MAC Address:' in line:
        try:
            mac_part = line.split('MAC Address:', 1)[1].strip()
            if ' (' in mac_part and mac_part.endswith(')'):
                mac = mac_part.split(' (', 1)[0].strip()
                vendor = mac_part.split(' (', 1)[1][:-1].strip()
            else:
                mac = mac_part.strip()
        except Exception:
            mac = ''
            vendor = ''

    if not _normalize_mac_value(mac):
        mac = _lookup_cached_mac_for_ip(ip) or ""

    if not hostname:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            reverse_dns = hostname
        except Exception:
            hostname = ''

    if not hostname:
        try:
            mdns = subprocess.check_output(
                ['avahi-resolve-address', ip],
                stderr=subprocess.DEVNULL,
                timeout=3
            ).decode().strip()
            if '\t' in mdns:
                hostname = mdns.split('\t', 1)[1].strip()
                mdns_name = hostname
        except Exception:
            hostname = ''

    try:
        record_device_observation(
            {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "type": "",
            },
            source="discovery",
            extra={
                "hostname": hostname,
                "reverse_dns": reverse_dns,
                "mdns_name": mdns_name,
                "guessed_type": guess_type_from_vendor(vendor),
                "inventory_type": "",
            },
        )
    except Exception:
        pass

    normalized_mac = _normalize_mac_value(mac)

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": normalized_mac or "",
        "mac_address": normalized_mac or None,
        "mac_source": "arp-cache" if normalized_mac else "unknown",
        "vendor": vendor,
        "guessed_type": guess_type_from_vendor(vendor),
        "status": "online"
    }


def _discover_hosts_for_subnet(subnet, job_id=None, timeout_seconds=DISCOVERY_SUBNET_TIMEOUT_SECONDS):
    devices = []
    process = subprocess.Popen(
        build_nmap_host_discovery_command(subnet, output_flag='-oG'),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        **_build_discovery_popen_kwargs()
    )
    stdout_queue = queue.Queue()

    def _read_stdout_lines():
        try:
            for raw_line in iter(process.stdout.readline, ''):
                stdout_queue.put(raw_line)
        finally:
            stdout_queue.put(None)

    stdout_thread = threading.Thread(target=_read_stdout_lines, daemon=True)
    stdout_thread.start()

    if job_id:
        _update_background_job(job_id, process=process)

    try:
        started_at = time.monotonic()
        stdout_complete = False

        while True:
            if job_id:
                job = _get_discovery_job(job_id)
                if not job:
                    break
                if job.get("cancel_requested"):
                    _terminate_discovery_process(process, subnet=subnet)
                    break

            if process.poll() is None and (time.monotonic() - started_at) > timeout_seconds:
                _terminate_discovery_process(process, subnet=subnet)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    _terminate_discovery_process(process, force=True, subnet=subnet)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                raise TimeoutError(f"Discovery timed out for {subnet} after {timeout_seconds} seconds")

            try:
                raw_line = stdout_queue.get(timeout=0.2)
            except queue.Empty:
                if process.poll() is not None and stdout_complete:
                    break
                continue

            if raw_line is None:
                stdout_complete = True
                if process.poll() is not None:
                    break
                continue

            line = raw_line.strip()
            if not line:
                continue

            device = _parse_discovery_line(line)
            if not device:
                continue

            devices.append(device)
            if job_id:
                _append_discovery_device(job_id, device)

        returncode = process.wait(timeout=5)
        stderr_output = (process.stderr.read() or '').strip()

        if job_id:
            job = _get_discovery_job(job_id)
            if job and job.get("cancel_requested"):
                _update_background_job(
                    job_id,
                    status="cancelled",
                    message=_discovery_status_message("cancelled", len(devices), subnet),
                    error=""
                )
                _persist_discovery_macs(devices)
                return devices

        if _is_known_discovery_assertion_failure(stderr_output):
            raise RuntimeError(_format_discovery_process_error(stderr_output, returncode))

        if returncode != 0:
            raise RuntimeError(_format_discovery_process_error(stderr_output, returncode))

        _persist_discovery_macs(devices)
        return devices
    finally:
        if job_id:
            _update_background_job(job_id, process=None)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def _discover_hosts_across_subnets(subnets, job_id=None, timeout_seconds=DISCOVERY_SUBNET_TIMEOUT_SECONDS):
    merged_devices = []
    subnet_errors = []
    total_subnets = len(subnets)

    for index, subnet in enumerate(subnets, start=1):
        if job_id:
            progress_message = _discovery_progress_message(subnet, index, total_subnets)
            _update_background_job(
                job_id,
                progress_updates={
                    "current_subnet": subnet,
                    "current_subnet_index": index,
                    "total_subnets": total_subnets,
                    "progress_message": progress_message
                },
                message=progress_message
            )
            job = _get_discovery_job(job_id)
            if not job or job.get("cancel_requested"):
                break

        try:
            discovered = _discover_hosts_for_subnet(subnet, job_id=job_id, timeout_seconds=timeout_seconds)
            merged_devices = _merge_discovered_devices(merged_devices, discovered)
        except Exception as exc:
            subnet_errors.append({"subnet": subnet, "error": str(exc)})
            if job_id:
                job = _get_discovery_job(job_id)
                if not job or job.get("cancel_requested"):
                    break
                _update_background_job(
                    job_id,
                    message=f"{_discovery_progress_message(subnet, index, total_subnets)} Skipping subnet after error: {exc}"
                )

    return merged_devices, subnet_errors


def _run_discovery_job(job_id):
    job = _get_discovery_job(job_id)
    if not job:
        return

    results = job.get("results") or {}
    subnet = (results.get("subnet") or "")
    subnets = results.get("subnets") or ([subnet] if subnet else [])
    is_auto_mode = bool(job.get("auto_mode"))
    initial_progress_message = (job.get("progress") or {}).get("progress_message") or ""
    _update_background_job(
        job_id,
        status="running",
        message=f"{initial_progress_message} {_discovery_status_message('running', 0, subnet)}".strip() if initial_progress_message else _discovery_status_message("running", 0, subnet),
        error=""
    )

    try:
        if is_auto_mode:
            devices, subnet_errors = _discover_hosts_across_subnets(subnets, job_id=job_id)
        else:
            devices = _discover_hosts_for_subnet(subnet, job_id=job_id)
            subnet_errors = []

        final_job = _get_discovery_job(job_id)
        if final_job and final_job.get("status") != "cancelled":
            results_updates = {"devices": devices}
            if subnet_errors:
                results_updates["subnet_errors"] = subnet_errors
            completed_message = _discovery_status_message("completed", len(devices), subnet)
            if is_auto_mode:
                completed_message = f"Discovery completed across {len(subnets)} subnet(s): {len(devices)} live {'host' if len(devices) == 1 else 'hosts'} found."
                if subnet_errors:
                    completed_message += f" Skipped {len(subnet_errors)} subnet(s) with errors/timeouts."
            _update_background_job(
                job_id,
                status="completed",
                message=completed_message,
                error="",
                results_updates=results_updates
            )
    except Exception as exc:
        _update_background_job(
            job_id,
            status="failed",
            message=f"Discovery failed on {subnet or 'selected subnet'}: {exc}",
            error=str(exc)
        )


def find_dhcp_lease_file():
    lease_paths = [
        '/etc/pihole/dhcp.leases',
        '/var/lib/misc/dnsmasq.leases',
        '/run/pihole/dhcp.leases'
    ]
    for path in lease_paths:
        if os.path.exists(path):
            return path
    return None


def _default_settings():
    return {
        "project_name": "",
        "job_number": "",
        "client_name": "",
        "site_location": "",
        "dns_suffix": ".av",
        "ntp_server": "",
        "snmp_community": "",
        "vlans": [],
    }


def _merge_settings_defaults(raw_settings):
    defaults = _default_settings()
    if not isinstance(raw_settings, dict):
        return defaults

    merged = dict(raw_settings)  # preserve unknown/custom keys
    for key, default_value in defaults.items():
        if key not in merged:
            merged[key] = copy.deepcopy(default_value)
    if not isinstance(merged.get("vlans"), list):
        merged["vlans"] = []
    return merged


SNMP_SYS_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_contact": "1.3.6.1.2.1.1.4.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
}
SNMP_INTERFACE_OIDS = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "mac_address": "1.3.6.1.2.1.2.2.1.6",
    "index": "1.3.6.1.2.1.2.2.1.1",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
}
SNMP_MAX_INTERFACES = 12
SNMP_TIMEOUT_SECONDS = 1
SNMP_RETRIES = 0
TOPOLOGY_SNMP_MAX_ROWS = 64
TOPOLOGY_SNMP_MAX_PORT_ROWS = 128
LLDP_LOC_PORT_ID_OID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORT_DESC_OID = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS_ID_OID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_ID_OID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC_OID = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME_OID = "1.0.8802.1.1.2.1.4.1.1.9"
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
CDP_CACHE_ADDRESS_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_CACHE_DEVICE_ID_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
IGMP_CACHE_SELF_OID = "1.3.6.1.2.1.85.1.2.1.3"
IGMP_CACHE_LAST_REPORTER_OID = "1.3.6.1.2.1.85.1.2.1.4"


def _safe_snmp_text(value):
    if value is None:
        return ""
    text = str(value).strip()
    return text[:512]


def _normalize_snmp_interface_mac(value):
    normalized = _normalize_mac_value(value)
    if normalized == "00:00:00:00:00:00":
        return ""
    return normalized


def _snmp_value_to_python(value):
    if value is None:
        return ""
    try:
        pretty = value.prettyPrint()
    except Exception:
        pretty = str(value)
    return pretty.strip()


def _infer_vendor_from_snmp(snmp_data):
    text = " ".join([
        _safe_snmp_text((snmp_data or {}).get("sys_descr")),
        _safe_snmp_text((snmp_data or {}).get("sys_name")),
    ]).lower()
    vendor_tokens = (
        ("QSC", ("qsc", "q-sys", "qsys")),
        ("Crestron", ("crestron",)),
        ("Biamp", ("biamp", "tesira")),
        ("Shure", ("shure",)),
        ("Barco", ("barco", "clickshare")),
        ("Cisco", ("cisco",)),
        ("Aruba", ("aruba", "hewlett packard enterprise", "hpe officeconnect")),
        ("NETGEAR", ("netgear",)),
        ("Ubiquiti", ("ubiquiti", "unifi")),
        ("Fortinet", ("fortinet", "fortigate")),
        ("Juniper", ("juniper",)),
    )
    for vendor_name, tokens in vendor_tokens:
        if any(token in text for token in tokens):
            return vendor_name
    return ""


def _infer_model_from_snmp(snmp_data):
    text = " ".join([
        _safe_snmp_text((snmp_data or {}).get("sys_descr")),
        _safe_snmp_text((snmp_data or {}).get("sys_name")),
    ])
    patterns = (
        r"\b(CP4|MC4|RMC4|PRO4)\b",
        r"\b(TSW-\d+[A-Z]*)\b",
        r"\b(TSS-\d+[A-Z]*)\b",
        r"\b(NV-32-H|NV32-H|NV-21|NV21)\b",
        r"\b(TSC-\d+[A-Z]*)\b",
        r"\b(CORE(?:\s+|[-_]?)(?:110F|510I|510C|NANO|8 FLEX))\b",
        r"\b(TESIRA(?:FORT[E]?)?(?:\s+[A-Z0-9-]+)?)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return re.sub(r"\s+", " ", match.group(1).strip())
    return ""


def _infer_firmware_from_snmp(snmp_data):
    text = " ".join([
        _safe_snmp_text((snmp_data or {}).get("sys_descr")),
        _safe_snmp_text((snmp_data or {}).get("sys_name")),
    ])
    patterns = (
        r"(?:firmware|fw|software version|version|release)[^\dA-Za-z]{0,8}([A-Za-z0-9][A-Za-z0-9._-]{1,31})",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _snmp_get_scalar_map(ip, community):
    values = {}
    if not SNMP_HLAPI_AVAILABLE or not ip or not community:
        return values

    objects = [ObjectType(ObjectIdentity(oid)) for oid in SNMP_SYS_OIDS.values()]
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT_SECONDS, retries=SNMP_RETRIES),
            ContextData(),
            *objects,
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
    except Exception:
        return values

    if error_indication or error_status:
        return values

    keys = list(SNMP_SYS_OIDS.keys())
    for idx, var_bind in enumerate(var_binds or []):
        try:
            _, value = var_bind
        except Exception:
            continue
        if idx < len(keys):
            values[keys[idx]] = _safe_snmp_text(_snmp_value_to_python(value))
    return values


def _snmp_walk_interface_table(ip, community, max_rows=SNMP_MAX_INTERFACES):
    if not SNMP_HLAPI_AVAILABLE or not ip or not community or max_rows <= 0:
        return []

    rows_by_index = {}
    column_keys = list(SNMP_INTERFACE_OIDS.keys())
    objects = [ObjectType(ObjectIdentity(oid)) for oid in SNMP_INTERFACE_OIDS.values()]

    try:
        iterator = nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT_SECONDS, retries=SNMP_RETRIES),
            ContextData(),
            *objects,
            lexicographicMode=False,
            ignoreNonIncreasingOid=True,
            maxRows=max_rows,
        )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication or error_status:
                break
            row = {}
            row_index = ""
            for key, var_bind in zip(column_keys, var_binds or []):
                try:
                    oid, value = var_bind
                    oid_text = oid.prettyPrint()
                except Exception:
                    continue
                row_index = oid_text.rsplit(".", 1)[-1]
                row[key] = _snmp_value_to_python(value)
            if row_index:
                rows_by_index[row_index] = row
            if len(rows_by_index) >= max_rows:
                break
    except Exception:
        return []

    interfaces = []
    for row_index in sorted(rows_by_index.keys(), key=lambda value: int(value) if str(value).isdigit() else value):
        raw = rows_by_index[row_index]
        interface = {
            "index": int(raw.get("index") or row_index) if str(raw.get("index") or row_index).isdigit() else row_index,
            "name": _safe_snmp_text(raw.get("name") or ""),
            "descr": _safe_snmp_text(raw.get("descr") or ""),
            "mac_address": _normalize_snmp_interface_mac(raw.get("mac_address") or ""),
        }
        if not interface["name"] and interface["descr"]:
            interface["name"] = interface["descr"]
        if interface["index"] == "" and not interface["name"] and not interface["descr"] and not interface["mac_address"]:
            continue
        interfaces.append(interface)
    return interfaces


def _collect_snmp_data(ip, settings=None):
    settings = settings if isinstance(settings, dict) else load_settings()
    community = str((settings or {}).get("snmp_community") or "").strip()
    if not community:
        return None
    if not SNMP_HLAPI_AVAILABLE:
        return None

    scalar_values = _snmp_get_scalar_map(ip, community)
    if not scalar_values:
        return None

    interfaces = _snmp_walk_interface_table(ip, community, max_rows=SNMP_MAX_INTERFACES)
    snmp_data = {
        "sys_descr": scalar_values.get("sys_descr", ""),
        "sys_name": scalar_values.get("sys_name", ""),
        "sys_location": scalar_values.get("sys_location", ""),
        "sys_contact": scalar_values.get("sys_contact", ""),
        "interfaces": interfaces,
    }
    return snmp_data


def _merge_snmp_enrichment(device, snmp_data):
    if not isinstance(device, dict) or not isinstance(snmp_data, dict):
        return False

    changed = False
    current_snmp = copy.deepcopy(device.get("snmp_data") or {})
    if current_snmp != snmp_data:
        device["snmp_data"] = snmp_data
        changed = True

    if device.get("snmp_enriched") is not True:
        device["snmp_enriched"] = True
        changed = True

    inferred_vendor = _infer_vendor_from_snmp(snmp_data)
    inferred_model = _infer_model_from_snmp(snmp_data)
    inferred_firmware = _infer_firmware_from_snmp(snmp_data)

    if inferred_vendor and not str(device.get("vendor") or "").strip():
        device["vendor"] = inferred_vendor
        changed = True
    if inferred_model and not str(device.get("model") or "").strip():
        device["model"] = inferred_model
        changed = True
    if inferred_firmware and not str(device.get("firmware_version") or "").strip():
        device["firmware_version"] = inferred_firmware
        changed = True

    unique_interface_macs = []
    for interface in snmp_data.get("interfaces") or []:
        mac_value = _normalize_snmp_interface_mac((interface or {}).get("mac_address"))
        if mac_value and mac_value not in unique_interface_macs:
            unique_interface_macs.append(mac_value)
    if len(unique_interface_macs) == 1 and str(device.get("snmp_mac") or "").strip() != unique_interface_macs[0]:
        device["snmp_mac"] = unique_interface_macs[0]
        changed = True

    return changed


def _apply_snmp_to_validation_result(result, device):
    if not isinstance(result, dict) or not isinstance(device, dict):
        return
    if "snmp_enriched" in device:
        result["snmp_enriched"] = bool(device.get("snmp_enriched"))
    if isinstance(device.get("snmp_data"), dict):
        result["snmp_data"] = copy.deepcopy(device.get("snmp_data"))
    if str(device.get("model") or "").strip():
        result["model"] = device.get("model")
    if str(device.get("firmware_version") or "").strip():
        result["firmware_version"] = device.get("firmware_version")
    if str(device.get("snmp_mac") or "").strip():
        result["snmp_mac"] = device.get("snmp_mac")
    evidence = result.get("evidence")
    if isinstance(evidence, dict):
        if isinstance(device.get("snmp_data"), dict):
            evidence["snmp_data"] = copy.deepcopy(device.get("snmp_data"))
        if str(device.get("snmp_mac") or "").strip():
            evidence["snmp_mac"] = device.get("snmp_mac")
        if str(device.get("vendor") or "").strip():
            evidence["vendor"] = device.get("vendor")


def _best_effort_snmp_enrich_device(device, validation_result=None, settings=None):
    if not isinstance(device, dict):
        return False

    ip = str(device.get("ip") or "").strip()
    if not ip:
        return False
    if validation_result is not None and not _validation_confirms_reachability(validation_result):
        return False

    snmp_data = _collect_snmp_data(ip, settings=settings)
    if not isinstance(snmp_data, dict):
        return False

    changed = _merge_snmp_enrichment(device, snmp_data)
    if validation_result is not None:
        _apply_snmp_to_validation_result(validation_result, device)
    return changed


def _load_topology_defaults():
    return {
        "topology": [],
        "generated_at": "",
        "switches_considered": 0,
        "switches_queried": 0,
    }


def load_topology_snapshot():
    defaults = _load_topology_defaults()
    topology_file = _topology_file()
    if not os.path.exists(topology_file):
        return copy.deepcopy(defaults)

    try:
        with open(topology_file, encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return copy.deepcopy(defaults)

    if isinstance(data, list):
        payload = copy.deepcopy(defaults)
        payload["topology"] = [row for row in data if isinstance(row, dict)]
        return payload

    if not isinstance(data, dict):
        return copy.deepcopy(defaults)

    payload = copy.deepcopy(defaults)
    payload["topology"] = [row for row in (data.get("topology") or []) if isinstance(row, dict)]
    payload["generated_at"] = str(data.get("generated_at") or "").strip()
    payload["switches_considered"] = int(data.get("switches_considered") or 0)
    payload["switches_queried"] = int(data.get("switches_queried") or 0)
    return payload


def save_topology_snapshot(data):
    payload = _load_topology_defaults()
    payload["topology"] = [copy.deepcopy(row) for row in (data or {}).get("topology") or [] if isinstance(row, dict)]
    payload["generated_at"] = str((data or {}).get("generated_at") or "").strip()
    payload["switches_considered"] = int((data or {}).get("switches_considered") or 0)
    payload["switches_queried"] = int((data or {}).get("switches_queried") or 0)

    topology_file = _topology_file()
    topology_dir = os.path.dirname(topology_file) or "."
    tmp_path = topology_file + ".tmp"
    os.makedirs(topology_dir, exist_ok=True)
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    try:
        os.replace(tmp_path, topology_file)
    except PermissionError:
        with open(topology_file, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def _snmp_walk_column(ip, community, base_oid, max_rows=TOPOLOGY_SNMP_MAX_ROWS):
    if not SNMP_HLAPI_AVAILABLE or not ip or not community or not base_oid or max_rows <= 0:
        return []

    rows = []
    try:
        iterator = nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT_SECONDS, retries=SNMP_RETRIES),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
            ignoreNonIncreasingOid=True,
            maxRows=max_rows,
        )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication or error_status:
                break
            for oid, value in (var_binds or []):
                rows.append({
                    "oid": oid.prettyPrint(),
                    "value": _snmp_value_to_python(value),
                })
                if len(rows) >= max_rows:
                    return rows
    except Exception:
        return []
    return rows


def _snmp_oid_suffix_parts(base_oid, oid_text):
    base = str(base_oid or "").strip().rstrip(".")
    oid = str(oid_text or "").strip()
    prefix = base + "."
    if not oid.startswith(prefix):
        return []
    return [part for part in oid[len(prefix):].split(".") if part != ""]


def _snmp_text_to_mac(value):
    text = str(value or "").strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    return _normalize_mac_value(text)


def _snmp_text_to_ip(value):
    text = str(value or "").strip()
    if not text:
        return ""

    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        pass

    if text.lower().startswith("0x"):
        hex_value = text[2:]
        if len(hex_value) == 8:
            try:
                raw = bytes.fromhex(hex_value)
                return str(ipaddress.ip_address(raw))
            except Exception:
                return ""
        return ""

    parts = [part for part in re.split(r"[\s,;:/-]+", text) if part != ""]
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return ".".join(parts)

    return ""


def _device_runtime_type_hint(device):
    return normalize_platform_name(
        (device or {}).get("_resolved_type")
        or (device or {}).get("effective_type")
        or (device or {}).get("type")
        or ""
    )


def _device_topology_text(device):
    device = device or {}
    snmp_data = device.get("snmp_data") if isinstance(device.get("snmp_data"), dict) else {}
    return " ".join([
        str(device.get("name") or ""),
        str(device.get("hostname") or ""),
        str(device.get("vendor") or ""),
        str(device.get("model") or ""),
        str(device.get("notes") or ""),
        str(snmp_data.get("sys_name") or ""),
        str(snmp_data.get("sys_descr") or ""),
    ]).lower()


def _device_is_switch_candidate(device):
    device = device or {}
    dtype = _device_runtime_type_hint(device)
    text = _device_topology_text(device)

    explicit_types = {
        "switch",
        "managed-switch",
        "network-switch",
        "cisco-switch",
        "aruba-switch",
        "netgear-switch",
        "unifi-switch",
    }
    weak_network_types = {
        "network-device",
        "snmp-device",
        "ssh-device",
        "telnet-device",
    }
    switch_vendor_tokens = (
        "cisco",
        "catalyst",
        "aruba",
        "procurve",
        "hewlett packard enterprise",
        "hpe",
        "netgear",
        "juniper",
        "ubiquiti",
        "unifi",
        "ruckus",
        "arista",
        "extreme",
        "dell networking",
    )
    switch_hint_tokens = (
        "switch",
        "catalyst",
        "procurve",
        "switching",
        "stackwise",
        "access switch",
        "distribution switch",
        "edge switch",
        "unifi switch",
        "ex-series",
        "sw-",
    )
    exclusion_tokens = (
        "firewall",
        "fortigate",
        "router",
        "gateway",
        "wireless",
        "access point",
        "controller",
    )

    if dtype in explicit_types:
        return True
    if any(token in text for token in exclusion_tokens):
        return False
    if dtype in weak_network_types and any(token in text for token in switch_hint_tokens):
        return True
    if dtype in weak_network_types and any(token in text for token in switch_vendor_tokens) and any(token in text for token in switch_hint_tokens):
        return True
    return False


def _device_is_cisco_like(device):
    text = _device_topology_text(device)
    return "cisco" in text or "catalyst" in text


def _topology_inventory_index(devices):
    by_ip = {}
    by_mac = {}
    by_hostname = {}

    for device in devices or []:
        if not isinstance(device, dict):
            continue
        ip_text = str(device.get("ip") or "").strip()
        mac_text = _normalize_mac_value(device.get("mac") or device.get("mac_address") or device.get("snmp_mac"))
        host_candidates = (
            device.get("name"),
            device.get("hostname"),
            ((device.get("snmp_data") or {}).get("sys_name") if isinstance(device.get("snmp_data"), dict) else ""),
        )

        if ip_text:
            by_ip[ip_text] = device
        if mac_text:
            by_mac[mac_text] = device
        for candidate in host_candidates:
            normalized = _normalize_identity_hostname(candidate)
            if normalized:
                by_hostname[normalized.lower()] = device

    return {
        "by_ip": by_ip,
        "by_mac": by_mac,
        "by_hostname": by_hostname,
    }


def _match_topology_neighbor(inventory_index, neighbor_ip="", neighbor_mac="", neighbor_hostname=""):
    inventory_index = inventory_index or {}
    normalized_mac = _normalize_mac_value(neighbor_mac)
    hostname_key = _normalize_identity_hostname(neighbor_hostname).lower() if _normalize_identity_hostname(neighbor_hostname) else ""
    ip_text = str(neighbor_ip or "").strip()

    if normalized_mac and normalized_mac in (inventory_index.get("by_mac") or {}):
        return inventory_index["by_mac"][normalized_mac]
    if ip_text and ip_text in (inventory_index.get("by_ip") or {}):
        return inventory_index["by_ip"][ip_text]
    if hostname_key and hostname_key in (inventory_index.get("by_hostname") or {}):
        return inventory_index["by_hostname"][hostname_key]
    return None


def _switch_display_name(device):
    snmp_data = device.get("snmp_data") if isinstance(device.get("snmp_data"), dict) else {}
    return (
        str(device.get("name") or "").strip()
        or _normalize_identity_hostname(device.get("hostname"))
        or _normalize_identity_hostname(snmp_data.get("sys_name"))
        or str(device.get("ip") or "").strip()
    )


def _build_port_label_map(ip, community, *, prefer_desc=False):
    primary_oid = IF_DESCR_OID if prefer_desc else IF_NAME_OID
    secondary_oid = IF_NAME_OID if prefer_desc else IF_DESCR_OID
    labels = {}

    for row in _snmp_walk_column(ip, community, primary_oid, max_rows=TOPOLOGY_SNMP_MAX_PORT_ROWS):
        suffix = _snmp_oid_suffix_parts(primary_oid, row.get("oid"))
        if not suffix:
            continue
        labels[suffix[-1]] = _safe_snmp_text(row.get("value"))

    for row in _snmp_walk_column(ip, community, secondary_oid, max_rows=TOPOLOGY_SNMP_MAX_PORT_ROWS):
        suffix = _snmp_oid_suffix_parts(secondary_oid, row.get("oid"))
        if not suffix:
            continue
        index = suffix[-1]
        if not labels.get(index):
            labels[index] = _safe_snmp_text(row.get("value"))

    return labels


def _build_lldp_local_port_map(ip, community):
    labels = {}

    for row in _snmp_walk_column(ip, community, LLDP_LOC_PORT_DESC_OID, max_rows=TOPOLOGY_SNMP_MAX_PORT_ROWS):
        suffix = _snmp_oid_suffix_parts(LLDP_LOC_PORT_DESC_OID, row.get("oid"))
        if suffix:
            labels[suffix[-1]] = _safe_snmp_text(row.get("value"))

    for row in _snmp_walk_column(ip, community, LLDP_LOC_PORT_ID_OID, max_rows=TOPOLOGY_SNMP_MAX_PORT_ROWS):
        suffix = _snmp_oid_suffix_parts(LLDP_LOC_PORT_ID_OID, row.get("oid"))
        if not suffix:
            continue
        port_index = suffix[-1]
        if not labels.get(port_index):
            labels[port_index] = _safe_snmp_text(row.get("value"))

    return labels


def _collect_lldp_topology_rows(switch_device, community, inventory_index):
    switch_device = switch_device or {}
    switch_ip = str(switch_device.get("ip") or "").strip()
    if not switch_ip or not community:
        return []

    local_port_labels = _build_lldp_local_port_map(switch_ip, community)
    row_map = {}
    column_defs = (
        ("chassis_id", LLDP_REM_CHASSIS_ID_OID),
        ("port_id", LLDP_REM_PORT_ID_OID),
        ("port_desc", LLDP_REM_PORT_DESC_OID),
        ("sys_name", LLDP_REM_SYS_NAME_OID),
    )

    for column_name, base_oid in column_defs:
        for row in _snmp_walk_column(switch_ip, community, base_oid, max_rows=TOPOLOGY_SNMP_MAX_ROWS):
            suffix = _snmp_oid_suffix_parts(base_oid, row.get("oid"))
            if len(suffix) < 3:
                continue
            row_key = ".".join(suffix[:3])
            entry = row_map.setdefault(row_key, {"local_port_num": suffix[1]})
            entry[column_name] = _safe_snmp_text(row.get("value"))

    rows = []
    for entry in row_map.values():
        local_port_num = str(entry.get("local_port_num") or "").strip()
        raw_hostname = _normalize_identity_hostname(entry.get("sys_name")) or _safe_snmp_text(entry.get("sys_name"))
        raw_mac = _snmp_text_to_mac(entry.get("chassis_id"))
        matched = _match_topology_neighbor(inventory_index, neighbor_mac=raw_mac, neighbor_hostname=raw_hostname)

        neighbor_hostname = raw_hostname
        if not neighbor_hostname and isinstance(matched, dict):
            neighbor_hostname = str(matched.get("name") or matched.get("hostname") or "").strip()

        port_label = (
            local_port_labels.get(local_port_num)
            or _safe_snmp_text(entry.get("port_desc"))
            or _safe_snmp_text(entry.get("port_id"))
            or (f"Port {local_port_num}" if local_port_num else "")
        )

        if not port_label or (not neighbor_hostname and not raw_mac):
            continue

        rows.append({
            "switch_ip": switch_ip,
            "switch_hostname": _switch_display_name(switch_device),
            "switch_vendor": str(switch_device.get("vendor") or "").strip(),
            "port": port_label,
            "neighbour_ip": "",
            "neighbour_mac": raw_mac,
            "neighbour_hostname": neighbor_hostname,
            "source_protocol": "lldp",
        })

    return rows


def _collect_cdp_topology_rows(switch_device, community, inventory_index):
    switch_device = switch_device or {}
    switch_ip = str(switch_device.get("ip") or "").strip()
    if not switch_ip or not community:
        return []

    if_name_map = _build_port_label_map(switch_ip, community, prefer_desc=False)
    if_descr_map = _build_port_label_map(switch_ip, community, prefer_desc=True)
    row_map = {}
    column_defs = (
        ("device_id", CDP_CACHE_DEVICE_ID_OID),
        ("device_port", CDP_CACHE_DEVICE_PORT_OID),
        ("address", CDP_CACHE_ADDRESS_OID),
    )

    for column_name, base_oid in column_defs:
        for row in _snmp_walk_column(switch_ip, community, base_oid, max_rows=TOPOLOGY_SNMP_MAX_ROWS):
            suffix = _snmp_oid_suffix_parts(base_oid, row.get("oid"))
            if len(suffix) < 2:
                continue
            row_key = ".".join(suffix[:2])
            entry = row_map.setdefault(row_key, {"local_if_index": suffix[0]})
            entry[column_name] = _safe_snmp_text(row.get("value"))

    rows = []
    for entry in row_map.values():
        local_if_index = str(entry.get("local_if_index") or "").strip()
        raw_device_id = _safe_snmp_text(entry.get("device_id"))
        raw_hostname = _normalize_identity_hostname(raw_device_id) or ""
        raw_mac = _snmp_text_to_mac(raw_device_id)
        raw_ip = _snmp_text_to_ip(entry.get("address"))
        matched = _match_topology_neighbor(
            inventory_index,
            neighbor_ip=raw_ip,
            neighbor_mac=raw_mac,
            neighbor_hostname=raw_hostname,
        )

        neighbor_hostname = raw_hostname
        if not neighbor_hostname and isinstance(matched, dict):
            neighbor_hostname = str(matched.get("name") or matched.get("hostname") or "").strip()

        port_label = (
            if_name_map.get(local_if_index)
            or if_descr_map.get(local_if_index)
            or (f"IfIndex {local_if_index}" if local_if_index else "")
        )

        if not port_label or (not neighbor_hostname and not raw_ip and not raw_mac):
            continue

        rows.append({
            "switch_ip": switch_ip,
            "switch_hostname": _switch_display_name(switch_device),
            "switch_vendor": str(switch_device.get("vendor") or "").strip(),
            "port": port_label,
            "neighbour_ip": raw_ip,
            "neighbour_mac": raw_mac,
            "neighbour_hostname": neighbor_hostname,
            "source_protocol": "cdp",
        })

    return rows


def _dedupe_topology_rows(rows):
    deduped = []
    seen = set()

    for row in rows or []:
        if not isinstance(row, dict):
            continue
        normalized = {
            "switch_ip": str(row.get("switch_ip") or "").strip(),
            "switch_hostname": str(row.get("switch_hostname") or "").strip(),
            "switch_vendor": str(row.get("switch_vendor") or "").strip(),
            "port": str(row.get("port") or "").strip(),
            "neighbour_ip": str(row.get("neighbour_ip") or "").strip(),
            "neighbour_mac": _normalize_mac_value(row.get("neighbour_mac")),
            "neighbour_hostname": str(row.get("neighbour_hostname") or "").strip(),
            "source_protocol": str(row.get("source_protocol") or "").strip().lower(),
        }
        row_key = (
            normalized["switch_ip"],
            normalized["port"],
            normalized["neighbour_ip"],
            normalized["neighbour_mac"],
            normalized["neighbour_hostname"].lower(),
            normalized["source_protocol"],
        )
        if row_key in seen:
            continue
        seen.add(row_key)
        deduped.append(normalized)

    return deduped


def _topology_response_payload(snapshot, **extra):
    snapshot = snapshot if isinstance(snapshot, dict) else _load_topology_defaults()
    payload = {
        "ok": True,
        "count": len(snapshot.get("topology") or []),
        "topology": list(snapshot.get("topology") or []),
        "generated_at": str(snapshot.get("generated_at") or "").strip(),
        "switches_considered": int(snapshot.get("switches_considered") or 0),
        "switches_queried": int(snapshot.get("switches_queried") or 0),
    }
    payload.update(extra)
    return payload


def generate_topology_snapshot():
    settings = load_settings()
    community = str((settings or {}).get("snmp_community") or "").strip()
    existing_snapshot = load_topology_snapshot()

    if not community:
        return _topology_response_payload(existing_snapshot, generated=False, note="SNMP community not configured; topology generation skipped.")
    if not SNMP_HLAPI_AVAILABLE:
        return _topology_response_payload(existing_snapshot, generated=False, note="SNMP helper unavailable; topology generation skipped.")

    devices = load_devices()
    eligible_switches = [device for device in devices if _device_is_switch_candidate(device)]
    inventory_index = _topology_inventory_index(devices)
    rows = []
    devices_changed = False
    switches_queried = 0

    for switch_device in eligible_switches:
        switch_ip = str(switch_device.get("ip") or "").strip()
        if not switch_ip:
            continue

        switches_queried += 1
        if _best_effort_snmp_enrich_device(switch_device, settings=settings):
            devices_changed = True

        lldp_rows = _collect_lldp_topology_rows(switch_device, community, inventory_index)
        protocol_rows = lldp_rows
        if not protocol_rows and _device_is_cisco_like(switch_device):
            protocol_rows = _collect_cdp_topology_rows(switch_device, community, inventory_index)
        rows.extend(protocol_rows)

    if devices_changed:
        save_devices_file(devices)

    snapshot = {
        "topology": _dedupe_topology_rows(rows),
        "generated_at": utc_now_iso(),
        "switches_considered": len(eligible_switches),
        "switches_queried": switches_queried,
    }
    save_topology_snapshot(snapshot)
    return _topology_response_payload(snapshot, generated=True)


def _load_multicast_groups_defaults():
    return {
        "generated_at": "",
        "groups": [],
        "switches_considered": 0,
        "switches_queried": 0,
    }


def load_multicast_groups_snapshot():
    defaults = _load_multicast_groups_defaults()
    multicast_file = _multicast_groups_file()
    if not os.path.exists(multicast_file):
        return copy.deepcopy(defaults)

    try:
        with open(multicast_file, encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return copy.deepcopy(defaults)

    if not isinstance(data, dict):
        return copy.deepcopy(defaults)

    payload = copy.deepcopy(defaults)
    payload["generated_at"] = str(data.get("generated_at") or "").strip()
    payload["switches_considered"] = int(data.get("switches_considered") or 0)
    payload["switches_queried"] = int(data.get("switches_queried") or 0)
    payload["groups"] = [copy.deepcopy(row) for row in (data.get("groups") or []) if isinstance(row, dict)]
    return payload


def save_multicast_groups_snapshot(data):
    payload = _load_multicast_groups_defaults()
    payload["generated_at"] = str((data or {}).get("generated_at") or "").strip()
    payload["switches_considered"] = int((data or {}).get("switches_considered") or 0)
    payload["switches_queried"] = int((data or {}).get("switches_queried") or 0)
    payload["groups"] = [copy.deepcopy(row) for row in ((data or {}).get("groups") or []) if isinstance(row, dict)]

    multicast_file = _multicast_groups_file()
    multicast_dir = os.path.dirname(multicast_file) or "."
    tmp_path = multicast_file + ".tmp"
    os.makedirs(multicast_dir, exist_ok=True)
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    try:
        os.replace(tmp_path, multicast_file)
    except PermissionError:
        with open(multicast_file, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def _multicast_groups_response_payload(snapshot, **extra):
    snapshot = snapshot if isinstance(snapshot, dict) else _load_multicast_groups_defaults()
    payload = {
        "ok": True,
        "count": len(snapshot.get("groups") or []),
        "groups": list(snapshot.get("groups") or []),
        "generated_at": str(snapshot.get("generated_at") or "").strip(),
        "switches_considered": int(snapshot.get("switches_considered") or 0),
        "switches_queried": int(snapshot.get("switches_queried") or 0),
    }
    payload.update(extra)
    return payload


def _multicast_group_address_from_suffix(suffix_parts):
    if not isinstance(suffix_parts, list) or len(suffix_parts) < 5:
        return ""
    address_parts = suffix_parts[:-1]
    if len(address_parts) != 4:
        return ""
    candidate = ".".join(address_parts)
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return candidate if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_multicast else ""


def _multicast_ifindex_from_suffix(suffix_parts):
    if not isinstance(suffix_parts, list) or len(suffix_parts) < 1:
        return ""
    return str(suffix_parts[-1] or "").strip()


def _match_inventory_device_strong(inventory_index, member_ip="", member_mac=""):
    inventory_index = inventory_index or {}
    normalized_mac = _normalize_mac_value(member_mac)
    ip_text = str(member_ip or "").strip()

    if normalized_mac and normalized_mac in (inventory_index.get("by_mac") or {}):
        return inventory_index["by_mac"][normalized_mac]
    if ip_text and ip_text in (inventory_index.get("by_ip") or {}):
        return inventory_index["by_ip"][ip_text]
    return None


def _build_multicast_member(member_ip="", member_mac="", matched_device=None):
    matched_device = matched_device if isinstance(matched_device, dict) else {}
    ip_text = str(member_ip or "").strip()
    mac_text = _normalize_mac_value(member_mac)
    hostname = ""
    if matched_device:
        hostname = str(
            matched_device.get("name")
            or matched_device.get("hostname")
            or ((matched_device.get("snmp_data") or {}).get("sys_name") if isinstance(matched_device.get("snmp_data"), dict) else "")
            or ""
        ).strip()
        if not mac_text:
            mac_text = _normalize_mac_value(
                matched_device.get("mac")
                or matched_device.get("mac_address")
                or matched_device.get("snmp_mac")
            )
    return {
        "member_ip": ip_text,
        "member_mac": mac_text,
        "member_hostname": hostname,
    }


def _normalize_multicast_groups(groups):
    normalized = []
    seen = set()

    for row in groups or []:
        if not isinstance(row, dict):
            continue
        group_address = str(row.get("group_address") or "").strip()
        if not group_address:
            continue

        members = []
        member_seen = set()
        for member in row.get("members") or []:
            if not isinstance(member, dict):
                continue
            normalized_member = {
                "member_ip": str(member.get("member_ip") or "").strip(),
                "member_mac": _normalize_mac_value(member.get("member_mac")),
                "member_hostname": str(member.get("member_hostname") or "").strip(),
            }
            member_key = (
                normalized_member["member_ip"],
                normalized_member["member_mac"],
                normalized_member["member_hostname"].lower(),
            )
            if member_key in member_seen:
                continue
            member_seen.add(member_key)
            if any(normalized_member.values()):
                members.append(normalized_member)

        normalized_row = {
            "group_address": group_address,
            "switch_ip": str(row.get("switch_ip") or "").strip(),
            "switch_hostname": str(row.get("switch_hostname") or "").strip(),
            "vlan": str(row.get("vlan") or "").strip(),
            "members": members,
            "member_count": int(row.get("member_count") or len(members)),
            "evidence_source": str(row.get("evidence_source") or "").strip(),
            "source_protocol": str(row.get("source_protocol") or "").strip(),
            "notes": str(row.get("notes") or "").strip(),
        }
        row_key = (
            normalized_row["group_address"],
            normalized_row["switch_ip"],
            normalized_row["switch_hostname"].lower(),
            normalized_row["vlan"],
            normalized_row["source_protocol"].lower(),
            json.dumps(normalized_row["members"], sort_keys=True),
        )
        if row_key in seen:
            continue
        seen.add(row_key)
        normalized.append(normalized_row)

    normalized.sort(key=lambda item: (
        str(item.get("group_address") or ""),
        str(item.get("switch_hostname") or ""),
        str(item.get("switch_ip") or ""),
    ))
    return normalized


def _aggregate_multicast_group_rows(rows):
    grouped = {}

    for row in rows or []:
        if not isinstance(row, dict):
            continue
        group_address = str(row.get("group_address") or "").strip()
        if not group_address:
            continue

        group_key = (
            group_address,
            str(row.get("switch_ip") or "").strip(),
            str(row.get("switch_hostname") or "").strip(),
            str(row.get("vlan") or "").strip(),
            str(row.get("source_protocol") or "").strip().lower(),
        )
        existing = grouped.get(group_key)
        if not existing:
            existing = {
                "group_address": group_address,
                "switch_ip": str(row.get("switch_ip") or "").strip(),
                "switch_hostname": str(row.get("switch_hostname") or "").strip(),
                "vlan": str(row.get("vlan") or "").strip(),
                "members": [],
                "member_count": 0,
                "evidence_source": str(row.get("evidence_source") or "").strip() or "snmp_igmp",
                "source_protocol": str(row.get("source_protocol") or "").strip().lower() or "igmp",
                "notes": str(row.get("notes") or "").strip(),
            }
            grouped[group_key] = existing

        for member in row.get("members") or []:
            if isinstance(member, dict):
                existing["members"].append(copy.deepcopy(member))

    for existing in grouped.values():
        unique_members = []
        seen_members = set()
        for member in existing.get("members") or []:
            member_key = (
                str(member.get("member_ip") or "").strip(),
                _normalize_mac_value(member.get("member_mac")),
                str(member.get("member_hostname") or "").strip().lower(),
            )
            if member_key in seen_members:
                continue
            seen_members.add(member_key)
            unique_members.append({
                "member_ip": member_key[0],
                "member_mac": member_key[1],
                "member_hostname": str(member.get("member_hostname") or "").strip(),
            })
        existing["members"] = unique_members
        existing["member_count"] = len(unique_members)
        if not existing["notes"] and not unique_members:
            existing["notes"] = "Group observed via switch IGMP cache; subscriber identity not exposed by the current SNMP view."

    return _normalize_multicast_groups(grouped.values())


def _collect_switch_multicast_groups(switch_device, community, inventory_index):
    switch_ip = str((switch_device or {}).get("ip") or "").strip()
    if not switch_ip or not community:
        return []

    switch_name = _switch_display_name(switch_device)
    port_labels = _build_port_label_map(switch_ip, community)
    row_map = {}

    for row in _snmp_walk_column(switch_ip, community, IGMP_CACHE_LAST_REPORTER_OID, max_rows=TOPOLOGY_SNMP_MAX_ROWS):
        suffix = _snmp_oid_suffix_parts(IGMP_CACHE_LAST_REPORTER_OID, row.get("oid"))
        group_address = _multicast_group_address_from_suffix(suffix)
        if_index = _multicast_ifindex_from_suffix(suffix)
        if not group_address or not if_index:
            continue
        row_key = ".".join(suffix)
        row_map[row_key] = {
            "group_address": group_address,
            "if_index": if_index,
            "last_reporter": _snmp_text_to_ip(row.get("value")),
        }

    if not row_map:
        return []

    for row in _snmp_walk_column(switch_ip, community, IGMP_CACHE_SELF_OID, max_rows=TOPOLOGY_SNMP_MAX_ROWS):
        suffix = _snmp_oid_suffix_parts(IGMP_CACHE_SELF_OID, row.get("oid"))
        if not suffix:
            continue
        row_key = ".".join(suffix)
        if row_key not in row_map:
            continue
        row_map[row_key]["self"] = _safe_snmp_text(row.get("value")).lower()

    groups = []
    for entry in row_map.values():
        group_address = str(entry.get("group_address") or "").strip()
        last_reporter = str(entry.get("last_reporter") or "").strip()
        if_index = str(entry.get("if_index") or "").strip()
        matched_device = _match_inventory_device_strong(inventory_index, member_ip=last_reporter)
        members = []
        if last_reporter or matched_device:
            members.append(_build_multicast_member(member_ip=last_reporter, matched_device=matched_device))

        notes = ""
        if not members:
            notes = "Switch reports multicast group presence but not an identifiable subscriber."
        elif str(entry.get("self") or "") in {"true", "1"}:
            notes = "Switch also reports local membership for this group."

        groups.append({
            "group_address": group_address,
            "switch_ip": switch_ip,
            "switch_hostname": switch_name,
            "vlan": "",
            "members": members,
            "member_count": len(members),
            "evidence_source": "snmp_igmp",
            "source_protocol": "igmp",
            "notes": notes or (port_labels.get(if_index) and f"Observed on {port_labels.get(if_index)}") or "",
        })

    return groups


def generate_multicast_groups_snapshot():
    settings = load_settings()
    community = str((settings or {}).get("snmp_community") or "").strip()
    existing_snapshot = load_multicast_groups_snapshot()

    if not community:
        return _multicast_groups_response_payload(existing_snapshot, generated=False, note="SNMP community not configured; multicast discovery skipped.")
    if not SNMP_HLAPI_AVAILABLE:
        return _multicast_groups_response_payload(existing_snapshot, generated=False, note="SNMP helper unavailable; multicast discovery skipped.")

    devices = load_devices()
    eligible_switches = [device for device in devices if _device_is_switch_candidate(device)]
    if not eligible_switches:
        empty_snapshot = {
            "generated_at": utc_now_iso(),
            "groups": [],
            "switches_considered": 0,
            "switches_queried": 0,
        }
        save_multicast_groups_snapshot(empty_snapshot)
        return _multicast_groups_response_payload(empty_snapshot, generated=True, note="No eligible managed switches found for multicast discovery.")

    inventory_index = _topology_inventory_index(devices)
    groups = []
    devices_changed = False
    switches_queried = 0

    for switch_device in eligible_switches:
        switch_ip = str(switch_device.get("ip") or "").strip()
        if not switch_ip:
            continue
        switches_queried += 1
        if _best_effort_snmp_enrich_device(switch_device, settings=settings):
            devices_changed = True
        groups.extend(_collect_switch_multicast_groups(switch_device, community, inventory_index))

    if devices_changed:
        save_devices_file(devices)

    snapshot = {
        "generated_at": utc_now_iso(),
        "groups": _aggregate_multicast_group_rows(groups),
        "switches_considered": len(eligible_switches),
        "switches_queried": switches_queried,
    }
    save_multicast_groups_snapshot(snapshot)
    return _multicast_groups_response_payload(snapshot, generated=True)


def _log_settings_load_once(message, level="info"):
    global _SETTINGS_LOAD_LOGGED
    if _SETTINGS_LOAD_LOGGED:
        return
    if level == "warning":
        app.logger.warning(message)
    elif level == "error":
        app.logger.error(message)
    else:
        app.logger.info(message)
    _SETTINGS_LOAD_LOGGED = True


def load_settings():
    settings_file = _settings_file()
    if not os.path.exists(settings_file):
        _log_settings_load_once(f"Using defaults because settings.json missing at {settings_file}")
        return _merge_settings_defaults({})

    try:
        with open(settings_file, encoding='utf-8') as f:
            loaded = json.load(f)
        _log_settings_load_once(f"Loaded settings from {settings_file}")
        return _merge_settings_defaults(loaded)
    except json.JSONDecodeError as exc:
        _log_settings_load_once(
            f"Recovered from invalid JSON in {settings_file}: {exc}",
            level="warning"
        )
        return _merge_settings_defaults({})
    except Exception as exc:
        _log_settings_load_once(
            f"Failed loading settings from {settings_file}; using defaults. Error: {exc}",
            level="error"
        )
        return _merge_settings_defaults({})


def save_settings(data):
    settings_file = _settings_file()
    settings_dir = os.path.dirname(settings_file) or "."
    tmp_path = settings_file + ".tmp"
    payload = _merge_settings_defaults(data or {})

    os.makedirs(settings_dir, exist_ok=True)
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    try:
        os.replace(tmp_path, settings_file)
    except PermissionError:
        # Windows/dev fallback when target file is temporarily locked.
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

    # Best-effort directory fsync so rename metadata is durable on Linux.
    try:
        dir_fd = os.open(settings_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        pass


def infer_vlan_from_ip(ip, settings=None):
    ip_text = (ip or "").strip()
    if not ip_text:
        return ""

    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except Exception:
        return ""

    vlan_sources = []
    if isinstance(settings, dict):
        vlan_sources.extend(settings.get("vlans", []))

    for vlan in vlan_sources:
        if not isinstance(vlan, dict):
            continue

        subnet = (vlan.get("subnet") or "").strip()
        name = (vlan.get("name") or "").strip()
        if not subnet or not name:
            continue

        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except Exception:
            continue

        if ip_obj in network:
            return name

    return ""


def assign_inferred_vlan(device, settings=None):
    item = dict(device or {})
    item["vlan"] = infer_vlan_from_ip(item.get("ip"), settings=settings)
    return item


def normalize_devices_for_save(devices_in, settings=None):
    normalized = []
    for device in devices_in or []:
        if isinstance(device, dict):
            item = _normalize_device_freshness(
                assign_inferred_vlan(device, settings=settings)
            )

            mac_value = _normalize_mac_value(item.get("mac") or item.get("mac_address"))
            if mac_value:
                item["mac"] = mac_value
                item["mac_address"] = mac_value
                item["mac_source"] = _canonicalize_mac_source(item.get("mac_source"), has_mac=True)
            else:
                item["mac"] = ""
                item["mac_address"] = None
                item["mac_source"] = "unknown"

            normalized.append(item)
    _apply_mac_conflict_flags(normalized)
    return normalized


def should_persist_fingerprinted_type(current_type, guessed_type):
    current = (current_type or "").strip().lower()
    guessed = (guessed_type or "").strip().lower()

    if not guessed or guessed in ("generic", "unknown"):
        return False

    if current == guessed:
        return False

    weak_types = {
        "", "generic", "unknown", "device", "other",
        "web-device", "network-device", "ssh-device",
        "telnet-device", "snmp-device", "rtsp-device",
        "windows-host", "mqtt-device"
    }

    return current in weak_types and guessed not in weak_types


def evaluate_safe_type_promotion(device, type_suggestion):
    device = device or {}
    type_suggestion = type_suggestion or {}

    current_type = (device.get("type") or "").strip().lower()
    suggested_type = (type_suggestion.get("suggested_type") or "").strip().lower()
    confidence_score = int(type_suggestion.get("confidence_score", 0) or 0)
    advisory_only = bool(type_suggestion.get("advisory_only"))
    suggestion_reasons = list(type_suggestion.get("suggestion_reasons") or [])
    allowed_current_types = {"generic", "web-device", "linux-web-device"}

    if current_type not in allowed_current_types:
        return {
            "should_apply": False,
            "reason": f"Current type {current_type or 'unknown'} is not eligible for weak-to-strong promotion",
            "current_type": current_type,
            "suggested_type": suggested_type,
            "confidence_score": confidence_score,
            "suggestion_reasons": suggestion_reasons,
        }

    if not suggested_type:
        return {
            "should_apply": False,
            "reason": "No suggested_type available",
            "current_type": current_type,
            "suggested_type": "",
            "confidence_score": confidence_score,
            "suggestion_reasons": suggestion_reasons,
        }

    if weak_device_type(suggested_type):
        return {
            "should_apply": False,
            "reason": f"Suggested type {suggested_type} is not a strong upgrade",
            "current_type": current_type,
            "suggested_type": suggested_type,
            "confidence_score": confidence_score,
            "suggestion_reasons": suggestion_reasons,
        }

    if advisory_only:
        return {
            "should_apply": False,
            "reason": "Suggestion is advisory_only",
            "current_type": current_type,
            "suggested_type": suggested_type,
            "confidence_score": confidence_score,
            "suggestion_reasons": suggestion_reasons,
        }

    if confidence_score < 60:
        return {
            "should_apply": False,
            "reason": f"Confidence score {confidence_score} is below promotion threshold",
            "current_type": current_type,
            "suggested_type": suggested_type,
            "confidence_score": confidence_score,
            "suggestion_reasons": suggestion_reasons,
        }

    if current_type and not weak_device_type(current_type):
        return {
            "should_apply": False,
            "reason": f"Current type {current_type} is already strong",
            "current_type": current_type,
            "suggested_type": suggested_type,
            "confidence_score": confidence_score,
            "suggestion_reasons": suggestion_reasons,
        }

    return {
        "should_apply": True,
        "reason": "Weak type safely promoted from high-confidence suggestion",
        "current_type": current_type,
        "suggested_type": suggested_type,
        "confidence_score": confidence_score,
        "suggestion_reasons": suggestion_reasons,
    }


def resolve_runtime_type_conflict_override(device, type_suggestion=None, validation=None):
    device = device or {}
    type_suggestion = type_suggestion or {}
    validation = validation or {}

    current_type = normalize_platform_name(device.get("type"))
    if not current_type or weak_device_type(current_type):
        return ""

    fingerprint = validation.get("fingerprint") if isinstance(validation.get("fingerprint"), dict) else {}
    observed_platform = validation.get("observed_platform") if isinstance(validation.get("observed_platform"), dict) else {}
    fingerprint_platform = normalize_platform_name(fingerprint.get("platform"))
    observed_type = normalize_platform_name(observed_platform.get("platform"))
    suggested_type = normalize_platform_name(type_suggestion.get("suggested_type"))
    fingerprint_confidence = (fingerprint.get("confidence") or "").strip().lower()
    observed_confidence = (observed_platform.get("confidence") or "").strip().lower()

    if not fingerprint_platform or fingerprint_confidence != "high":
        return ""
    if not observed_type or observed_confidence != "high":
        return ""
    if fingerprint_platform != observed_type:
        return ""
    if suggested_type != fingerprint_platform:
        return ""

    current_family = _candidate_family(current_type)
    live_family = _candidate_family(fingerprint_platform)
    if not current_family or not live_family or current_family == live_family:
        return ""

    return fingerprint_platform


def resolve_effective_type(device, guessed_type="", type_suggestion=None, validation=None):
    device = device or {}
    guessed_type = normalize_platform_name(guessed_type)
    current_type = normalize_platform_name(device.get("type"))
    type_suggestion = type_suggestion or {}

    if guessed_type and not weak_device_type(guessed_type):
        return guessed_type

    promotion = evaluate_safe_type_promotion(device, type_suggestion)
    if promotion.get("should_apply"):
        promoted_type = normalize_platform_name(promotion.get("suggested_type"))
        if promoted_type and not weak_device_type(promoted_type):
            return promoted_type

    runtime_override_type = resolve_runtime_type_conflict_override(device, type_suggestion, validation)
    if runtime_override_type:
        return runtime_override_type

    if current_type and not weak_device_type(current_type):
        return current_type

    if guessed_type and guessed_type != "unknown":
        return guessed_type

    return current_type or ""


def resolve_runtime_type(device, effective_type="", type_suggestion=None, validation=None):
    device = device or {}
    current_type = normalize_platform_name(device.get("type"))
    effective_type = normalize_platform_name(effective_type or device.get("effective_type"))

    runtime_override_type = resolve_runtime_type_conflict_override(device, type_suggestion, validation)
    if runtime_override_type:
        return runtime_override_type

    if current_type and not weak_device_type(current_type):
        return current_type

    if effective_type and not weak_device_type(effective_type):
        return effective_type

    return current_type or effective_type or ""


def enrich_device_runtime(device):
    item = dict(device or {})
    validation = run_validation(item)
    _best_effort_snmp_enrich_device(item, validation)
    auto_type = decide_auto_promoted_type(item, validation)
    type_suggestion = build_type_suggestion(item, validation)
    guessed_type = auto_type.get("proposed_type") or ""
    effective_type = resolve_effective_type(item, guessed_type, type_suggestion, validation)
    promotion = evaluate_safe_type_promotion(item, type_suggestion)
    runtime_override_type = resolve_runtime_type_conflict_override(item, type_suggestion, validation)

    item["guessed_type"] = guessed_type
    item["type_suggestion"] = type_suggestion
    item["suggested_type"] = type_suggestion.get("suggested_type") or ""
    item["effective_type"] = effective_type
    item["_resolved_type"] = resolve_runtime_type(item, effective_type, type_suggestion, validation)
    item["_runtime_promotion"] = promotion
    item["_runtime_override_reason"] = "live_high_conflict_override" if runtime_override_type else ""

    validation_context = dict(validation)
    validation_context["auto_type"] = auto_type
    validation_context["type_suggestion"] = type_suggestion
    validation_context["suggested_type"] = item["suggested_type"]
    validation_context["effective_type"] = effective_type
    validation_context["confidence_score"] = type_suggestion.get("confidence_score", 0)
    validation_context["confidence_label"] = type_suggestion.get("confidence_label") or "none"
    validation_context["suggestion_reasons"] = list(type_suggestion.get("suggestion_reasons") or [])

    role = infer_av_role(item, validation_context)
    if role:
        item["av_role"] = role
        validation_context["av_role"] = role

    item["_validation_result"] = validation_context
    return item


def build_runtime_system_groups(devices):
    if not isinstance(devices, list):
        return []

    family_type_map = {
        "qsys-core": "qsys",
        "qsys-touchpanel": "qsys",
        "qsys-nv-endpoint": "qsys",
        "crestron-processor": "crestron",
        "crestron-touchpanel": "crestron",
        "crestron-uc-engine": "crestron",
        "biamp-tesira": "biamp",
        "barco": "video",
        "nvx": "video",
        "svsi": "video",
    }
    role_type_map = {
        "qsys-core": "core",
        "qsys-touchpanel": "control",
        "qsys-nv-endpoint": "endpoint",
        "crestron-processor": "core",
        "crestron-touchpanel": "control",
        "crestron-uc-engine": "endpoint",
        "biamp-tesira": "dsp",
        "barco": "video",
        "nvx": "endpoint",
        "svsi": "endpoint",
    }

    def normalized_effective_type(device):
        if not isinstance(device, dict):
            return ""
        return normalize_platform_name(
            device.get("_resolved_type")
            or device.get("effective_type")
            or device.get("type")
        )

    def normalized_vlan(device):
        if not isinstance(device, dict):
            return ""
        return str(device.get("vlan") or "").strip().lower()

    def family_for_type(effective_type):
        return family_type_map.get(effective_type or "", "")

    group_records = []
    assigned_indexes = set()

    for index, device in enumerate(devices):
        if index in assigned_indexes or not isinstance(device, dict):
            continue

        effective_type = normalized_effective_type(device)
        device_vlan = normalized_vlan(device)
        device_family = family_for_type(effective_type)

        current_devices = [device]
        assigned_indexes.add(index)

        for other_index, other_device in enumerate(devices):
            if other_index == index or other_index in assigned_indexes or not isinstance(other_device, dict):
                continue

            other_type = normalized_effective_type(other_device)
            other_vlan = normalized_vlan(other_device)
            other_family = family_for_type(other_type)

            same_vlan = bool(device_vlan) and device_vlan == other_vlan
            same_family = bool(device_family) and device_family == other_family
            should_group = same_vlan and same_family

            if not should_group and same_family:
                should_group = True

            if should_group:
                current_devices.append(other_device)
                assigned_indexes.add(other_index)

        unique_types = []
        unique_roles = []
        for group_device in current_devices:
            group_type = normalized_effective_type(group_device)
            if group_type and group_type not in unique_types:
                unique_types.append(group_type)

            inferred_role = role_type_map.get(group_type, "")
            runtime_role = (group_device.get("av_role") or "").strip().lower()
            if not inferred_role and runtime_role in {"core", "endpoint", "control", "dsp", "video"}:
                inferred_role = runtime_role
            if inferred_role and inferred_role not in unique_roles:
                unique_roles.append(inferred_role)

        group_vlans = {
            normalized_vlan(group_device)
            for group_device in current_devices
            if normalized_vlan(group_device)
        }
        family_values = {
            family_for_type(normalized_effective_type(group_device))
            for group_device in current_devices
            if family_for_type(normalized_effective_type(group_device))
        }
        if len(current_devices) <= 1:
            confidence = "low"
        elif len(group_vlans) == 1 and len(family_values) == 1:
            confidence = "high"
        else:
            confidence = "medium"

        group_records.append({
            "devices": current_devices,
            "types": unique_types,
            "roles": unique_roles,
            "confidence": confidence,
        })

    system_groups = []
    for group_index, group_record in enumerate(group_records, start=1):
        system_groups.append({
            "system_id": f"system_{group_index}",
            "devices": group_record["devices"],
            "types": group_record["types"],
            "roles": group_record["roles"],
            "confidence": group_record["confidence"],
        })

    return system_groups


def build_system_group_results(system_groups, system_results):
    if not isinstance(system_groups, list):
        return []

    if not isinstance(system_results, list):
        system_results = []

    rule_map = {
        (rule.get("name") or "").strip(): rule
        for rule in (SYSTEM_VALIDATION_RULES or [])
        if isinstance(rule, dict) and (rule.get("name") or "").strip()
    }
    alias_map = {
        "crestron-processor": {"crestron-processor", "crestron_processor", "crestron-control", "crestron_control", "crestron"},
        "crestron-touchpanel": {"crestron-touchpanel", "crestron_touchpanel", "touchpanel", "tp1070"},
        "crestron-uc-engine": {"crestron-uc-engine", "crestron_uc", "crestron-uc", "uc-engine", "uc_engine"},
        "qsys-core": {"qsys-core", "qsys_core", "qsys"},
        "qsys-touchpanel": {"qsys-touchpanel", "qsys_touchpanel", "qsys"},
        "qsys-nv-endpoint": {"qsys-nv-endpoint", "qsys_nv_endpoint", "qsys-nv-decoder", "qsys_nv_decoder", "qsys"},
        "biamp-tesira": {"biamp-tesira", "biamp_tesira", "biamp", "tesira"},
        "video-wall-processor": {"video-wall-processor", "video_wall_processor", "video-wall"},
    }

    def device_ref(device):
        if not isinstance(device, dict):
            return {}
        return {
            "name": device.get("name") or "",
            "ip": device.get("ip") or "",
            "effective_type": device.get("effective_type") or "",
            "_resolved_type": device.get("_resolved_type") or "",
            "av_role": device.get("av_role") or "",
            "vlan": device.get("vlan") or "",
        }

    def type_variants(value):
        normalized = normalize_platform_name(str(value or "").strip().lower()).replace("_", "-")
        if not normalized:
            return set()

        variants = {
            normalized,
            normalized.replace("-", "_"),
        }
        variants.update(alias_map.get(normalized, set()))
        return {variant for variant in variants if variant}

    def group_matches_rule_types(group_devices, allowed_types):
        allowed_variants = set()
        for allowed_type in (allowed_types or []):
            allowed_variants.update(type_variants(allowed_type))

        if not allowed_variants:
            return False

        for device in (group_devices or []):
            device_type = device.get("effective_type") or device.get("_resolved_type") or device.get("type") or ""
            if type_variants(device_type).intersection(allowed_variants):
                return True

        return False

    grouped_results = []

    for group in system_groups:
        group_devices = list(group.get("devices") or [])
        group_ips = {
            (device.get("ip") or "").strip()
            for device in group_devices
            if (device.get("ip") or "").strip()
        }
        related_results = []

        for result in system_results:
            if not isinstance(result, dict):
                continue

            from_ip = (result.get("from_ip") or "").strip()
            to_ip = (result.get("to_ip") or "").strip()

            if from_ip and to_ip:
                if from_ip in group_ips and to_ip in group_ips:
                    related_results.append(dict(result, group_relevance="within_group"))
                continue

            if result.get("status") != "skipped":
                continue

            rule = rule_map.get((result.get("system_check") or "").strip(), {})
            source_match = group_matches_rule_types(group_devices, rule.get("source_types", []))
            target_match = group_matches_rule_types(group_devices, rule.get("target_types", []))

            if source_match or target_match:
                relevance = "source_and_target" if source_match and target_match else ("source" if source_match else "target")
                related_results.append(dict(result, group_relevance=relevance))

        grouped_results.append({
            "system_id": group.get("system_id") or "",
            "types": list(group.get("types") or []),
            "confidence": group.get("confidence") or "low",
            "devices": [device_ref(device) for device in group_devices],
            "results": related_results,
            "result_count": len(related_results),
        })

    return grouped_results


def build_system_topology_results(system_groups, system_group_results):
    if not isinstance(system_groups, list):
        return []

    if not isinstance(system_group_results, list):
        system_group_results = []

    ip_to_group = {}
    name_to_group = {}

    def normalized_name(value):
        return str(value or "").strip().lower()

    for group in system_groups:
        group_id = (group.get("system_id") or "").strip()
        for device in (group.get("devices") or []):
            device_ip = (device.get("ip") or "").strip()
            device_name = normalized_name(device.get("name"))
            if device_ip and group_id:
                ip_to_group[device_ip] = group_id
            if device_name and group_id:
                name_to_group[device_name] = group_id

    def resolve_group_id(side_ip, side_name):
        side_ip = (side_ip or "").strip()
        if side_ip and side_ip in ip_to_group:
            return ip_to_group[side_ip]

        side_name_key = normalized_name(side_name)
        if side_name_key and side_name_key in name_to_group:
            return name_to_group[side_name_key]

        if side_name_key and side_name_key in ip_to_group:
            return ip_to_group[side_name_key]

        return ""

    def relation_classification(result):
        relationship_type = (result.get("relationship_type") or "").strip().lower()
        if relationship_type in {"control", "media_flow", "ui", "peer"}:
            return relationship_type
        if relationship_type:
            return relationship_type
        return "unknown"

    topology_entries = []

    for group_result in system_group_results:
        system_id = (group_result.get("system_id") or "").strip()
        relevant_results = []
        cross_group_results = []
        unassigned_results = []

        for result in (group_result.get("results") or []):
            if not isinstance(result, dict):
                continue

            from_ip = (result.get("from_ip") or "").strip()
            to_ip = (result.get("to_ip") or "").strip()
            from_name = result.get("from_device")
            to_name = result.get("to_device")
            from_group = resolve_group_id(from_ip, from_name)
            to_group = resolve_group_id(to_ip, to_name)
            row_status = (result.get("status") or "").strip().lower()
            group_relevance = (result.get("group_relevance") or "").strip().lower()

            if from_group and to_group:
                scope = "intra_group" if from_group == to_group == system_id else "cross_group"
            elif row_status == "skipped" and group_relevance in {"source", "target", "both", "source_and_target"}:
                scope = "intra_group"
            else:
                scope = "unassigned"

            annotated = dict(result)
            annotated["topology_scope"] = scope
            annotated["relation_classification"] = relation_classification(result)

            if scope == "intra_group":
                relevant_results.append(annotated)
            elif scope == "cross_group":
                cross_group_results.append(annotated)
            else:
                unassigned_results.append(annotated)

        topology_entries.append({
            "system_id": system_id,
            "types": list(group_result.get("types") or []),
            "confidence": group_result.get("confidence") or "low",
            "relevant_results": relevant_results,
            "cross_group_results": cross_group_results,
            "unassigned_results": unassigned_results,
            "counts": {
                "intra_group": len(relevant_results),
                "cross_group": len(cross_group_results),
                "unassigned": len(unassigned_results),
            },
        })

    return topology_entries


def load_devices():
    devices_file = _devices_file()
    if not os.path.exists(devices_file):
        return []

    try:
        with open(devices_file) as f:
            data = json.load(f)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            devices = data.get('devices', [])
            if isinstance(devices, list):
                return devices

        return []
    except Exception:
        return []


def _clean_freshness_timestamp(value):
    return str(value or "").strip()


def _parse_freshness_timestamp(value):
    text = _clean_freshness_timestamp(value)
    if not text:
        return None

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _derive_device_freshness(device):
    item = dict(device or {})
    first_seen = _clean_freshness_timestamp(item.get("first_seen"))
    last_seen = _clean_freshness_timestamp(item.get("last_seen"))
    last_reachable = _clean_freshness_timestamp(item.get("last_reachable"))
    evidence = last_reachable or last_seen or first_seen
    evidence_dt = _parse_freshness_timestamp(evidence)
    evidence_source = "last_reachable" if last_reachable else ("last_seen" if last_seen else ("first_seen" if first_seen else ""))

    label = "unknown"
    age_days = None

    if evidence_dt:
        age_seconds = max(0, (datetime.utcnow() - evidence_dt.replace(tzinfo=None)).total_seconds())
        age_days = int(age_seconds // 86400)
        if evidence_source == "first_seen":
            if age_seconds <= 30 * 86400:
                label = "aging"
            else:
                label = "stale"
        elif age_seconds <= 7 * 86400:
            label = "fresh"
        elif age_seconds <= 30 * 86400:
            label = "aging"
        else:
            label = "stale"

    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "last_reachable": last_reachable,
        "freshness_label": label,
        "freshness_age_days": age_days,
    }


def _normalize_device_freshness(device, *, default_first_seen=""):
    item = dict(device or {})
    first_seen = _clean_freshness_timestamp(item.get("first_seen"))
    last_seen = _clean_freshness_timestamp(item.get("last_seen"))
    last_reachable = _clean_freshness_timestamp(item.get("last_reachable"))
    item.pop("freshness_label", None)
    item.pop("freshness_age_days", None)

    if not first_seen:
        first_seen = last_seen or last_reachable or _clean_freshness_timestamp(default_first_seen) or utc_now_iso()

    item["first_seen"] = first_seen

    if last_seen:
        item["last_seen"] = last_seen
    else:
        item.pop("last_seen", None)

    if last_reachable:
        item["last_reachable"] = last_reachable
    else:
        item.pop("last_reachable", None)

    return item


def _mark_device_freshness(device, *, seen=False, reachable=False, timestamp=None):
    seen_at = _clean_freshness_timestamp(timestamp) or utc_now_iso()
    item = _normalize_device_freshness(device, default_first_seen=seen_at)

    if seen or reachable:
        item["last_seen"] = seen_at
    if reachable:
        item["last_reachable"] = seen_at

    return item


def _validation_confirms_reachability(validation):
    if not validation:
        return False

    if str(validation.get("overall") or "").strip().lower() == "pass":
        return True

    if list(validation.get("open_ports") or []):
        return True

    for result in validation.get("results", []) or []:
        if result.get("check") == "ping" and result.get("status") == "pass":
            return True

    return False


def _normalize_mac_value(value):
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(raw) != 12:
        return ""
    return ":".join(raw[i:i+2] for i in range(0, 12, 2)).upper()


def _canonicalize_mac_source(value, *, has_mac=False):
    token = str(value or "").strip().lower()
    mapping = {
        "arp": "arp-cache",
        "arp-cache": "arp-cache",
        "snmp": "snmp-oid",
        "snmp-oid": "snmp-oid",
        "ifphysaddress": "snmp-oid",
        "lldp": "lldp",
        "cdp": "lldp",
        "lldp/cdp": "lldp",
        "manual": "user-entered",
        "user-entered": "user-entered",
        "user entered": "user-entered",
        "entered": "user-entered",
        "existing": "unknown",
        "unknown": "unknown",
    }
    canonical = mapping.get(token)
    if canonical:
        return canonical
    if not token:
        return "unknown"
    return "unknown"


def _apply_mac_conflict_flags(devices):
    mac_to_indices = {}

    for index, device in enumerate(devices or []):
        if not isinstance(device, dict):
            continue
        mac_value = _normalize_mac_value(device.get("mac") or device.get("mac_address"))
        if not mac_value:
            continue
        mac_to_indices.setdefault(mac_value, []).append(index)

    for device in devices or []:
        if isinstance(device, dict):
            device["mac_conflict"] = False

    for indices in mac_to_indices.values():
        if len(indices) < 2:
            continue
        for index in indices:
            if 0 <= index < len(devices) and isinstance(devices[index], dict):
                devices[index]["mac_conflict"] = True


def _apply_observed_mac(device, observed_mac, observed_source):
    if not isinstance(device, dict):
        return False

    normalized_observed_mac = _normalize_mac_value(observed_mac)
    if not normalized_observed_mac:
        return False

    desired_source = _canonicalize_mac_source(observed_source, has_mac=True)
    existing_mac = _normalize_mac_value(device.get("mac") or device.get("mac_address"))
    existing_source = _canonicalize_mac_source(device.get("mac_source"), has_mac=bool(existing_mac))
    changed = False

    if existing_mac != normalized_observed_mac:
        device["mac"] = normalized_observed_mac
        device["mac_address"] = normalized_observed_mac
        device["mac_source"] = desired_source
        changed = True
    else:
        if existing_source == "unknown" and desired_source != "unknown":
            device["mac_source"] = desired_source
            changed = True

        if device.get("mac") != normalized_observed_mac:
            device["mac"] = normalized_observed_mac
            changed = True
        if device.get("mac_address") != normalized_observed_mac:
            device["mac_address"] = normalized_observed_mac
            changed = True

    return changed


def save_devices_file(devices):
    devices = normalize_devices_for_save(devices, settings=load_settings())
    devices_file = _devices_file()
    os.makedirs(os.path.dirname(devices_file) or ".", exist_ok=True)
    with open(devices_file, 'w') as f:
        json.dump({'devices': devices}, f, indent=2)


def _devices_with_freshness_view(devices):
    enriched = []
    for device in devices or []:
        if isinstance(device, dict):
            item = dict(device)
            item.update(_derive_device_freshness(item))
            enriched.append(item)
    return enriched


def load_fingerprints():
    fingerprints_file = _fingerprints_file()
    if not os.path.exists(fingerprints_file):
        return {}

    try:
        with open(fingerprints_file) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_fingerprints(data):
    fingerprints_file = _fingerprints_file()
    os.makedirs(os.path.dirname(fingerprints_file) or ".", exist_ok=True)
    with open(fingerprints_file, 'w') as f:
        json.dump(data or {}, f, indent=2, sort_keys=True)


def load_device_evidence():
    evidence_file = _device_evidence_file()
    if not os.path.exists(evidence_file):
        return {}

    try:
        with open(evidence_file) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_device_evidence(data):
    evidence_file = _device_evidence_file()
    os.makedirs(os.path.dirname(evidence_file) or ".", exist_ok=True)
    with open(evidence_file, 'w') as f:
        json.dump(data or {}, f, indent=2, sort_keys=True)


def _fingerprint_confidence_rank(value):
    return {
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get((value or "").strip().lower(), 0)


def _normalize_identity_mac(value):
    mac = (value or "").strip().upper()
    if not mac or mac in ("â€”", "-", "UNKNOWN"):
        return ""
    return mac


def _normalize_identity_hostname(value):
    hostname = re.sub(r"[\s\.,;:]+$", "", str(value or "").strip())
    lowered = hostname.lower()
    if not hostname or lowered in ("unknown", "n/a", "none", "-", "â€”"):
        return ""
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname):
        return ""
    if "." not in hostname and "-" not in hostname and len(hostname) < 3:
        return ""
    return hostname


def _observation_hostname_candidates(observation):
    observation = observation or {}
    hostnames = []
    seen = set()

    for value in (
        observation.get("stable_hostname"),
        observation.get("hostname"),
        observation.get("reverse_dns"),
        observation.get("mdns_name"),
        observation.get("name"),
    ):
        hostname = _normalize_identity_hostname(value)
        if not hostname:
            continue
        lowered = hostname.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        hostnames.append(hostname)

    return hostnames


def _observation_identity_candidates(observation):
    observation = observation or {}
    mac = _normalize_identity_mac(observation.get("mac"))
    ip = (observation.get("ip") or "").strip()

    candidates = []
    if mac:
        candidates.append(("mac", f"mac:{mac}"))
    for hostname in _observation_hostname_candidates(observation):
        candidates.append(("hostname", f"hostname:{hostname.lower()}"))
    if ip:
        candidates.append(("ip", f"ip:{ip}"))
    return candidates


def _identity_kind_from_key(key):
    key = str(key or "")
    if key.startswith("mac:"):
        return "mac"
    if key.startswith("hostname:"):
        return "hostname"
    if key.startswith("ip:"):
        return "ip"
    return ""


def _identity_priority(key):
    kind = _identity_kind_from_key(key)
    if kind == "mac":
        return 3
    if kind == "hostname":
        return 2
    if kind == "ip":
        return 1
    return 0


def _identity_match_weight(match_kind):
    return {
        "mac": 1.0,
        "hostname": 0.7,
        "ip": 0.25,
    }.get((match_kind or "").strip().lower(), 0.0)


def _find_evidence_record_match(store, observation):
    store = store or {}
    observation = observation or {}
    candidates = _observation_identity_candidates(observation)
    if not candidates:
        return None

    strongest_identity = max((_identity_priority(key) for _, key in candidates), default=0)
    candidate_keys_by_kind = {}
    for kind, key in candidates:
        candidate_keys_by_kind.setdefault(kind, [])
        if key not in candidate_keys_by_kind[kind]:
            candidate_keys_by_kind[kind].append(key)

    matches = []
    for record_key, record in store.items():
        if not isinstance(record, dict):
            continue

        record_identity = record.get("identity") if isinstance(record.get("identity"), dict) else {}
        aliases = set(record_identity.get("aliases") or [])
        aliases.add(record_key)
        record_key_type = (record_identity.get("key_type") or _identity_kind_from_key(record_key)).strip().lower()

        matched_kind = ""
        matched_key = ""
        exact_match = False
        for kind in ("mac", "hostname", "ip"):
            keys = candidate_keys_by_kind.get(kind) or []
            if not keys:
                continue
            if kind == "ip" and strongest_identity > 1:
                continue
            hit = next((key for key in keys if key == record_key or key in aliases), "")
            if hit:
                matched_kind = kind
                matched_key = hit
                exact_match = (hit == record_key)
                break

        if not matched_kind:
            continue

        matches.append({
            "key": record_key,
            "record": copy.deepcopy(record),
            "match_kind": matched_kind,
            "matched_key": matched_key,
            "exact_match": exact_match,
            "match_priority": _identity_priority(f"{matched_kind}:match"),
            "record_priority": _identity_priority(record_identity.get("key") or record_key),
            "record_key_type": record_key_type,
            "seen_count": int(record.get("seen_count", 0) or 0),
        })

    if not matches:
        return None

    matches.sort(
        key=lambda item: (
            item["match_priority"],
            1 if item["exact_match"] else 0,
            item["record_priority"],
            item["seen_count"],
        ),
        reverse=True,
    )
    return matches[0]


def _merge_unique_strings(existing, *values):
    merged = []
    seen = set()

    for value in list(existing or []) + list(values):
        text = (value or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        merged.append(text)

    return merged


def _merge_unique_ports(existing, *values):
    ports = {int(port) for port in (existing or []) if str(port).isdigit()}
    for value in values:
        for port in (value or []):
            if str(port).isdigit():
                ports.add(int(port))
    return sorted(ports)


def _bump_count_map(counter_map, key, *, strength="", seen_at="", source="", reasons=None):
    key = (key or "").strip()
    if not key:
        return counter_map

    strength = (strength or "").strip().lower()
    source = (source or "").strip()
    reasons = [str(item).strip() for item in (reasons or []) if str(item).strip()]

    bucket = dict(counter_map.get(key) or {})
    bucket["count"] = int(bucket.get("count", 0) or 0) + 1
    bucket["best_strength"] = (
        strength
        if _fingerprint_confidence_rank(strength) >= _fingerprint_confidence_rank(bucket.get("best_strength"))
        else bucket.get("best_strength", "")
    )
    if seen_at:
        bucket["last_seen"] = seen_at
    bucket["sources"] = _merge_unique_strings(bucket.get("sources") or [], source)
    bucket["reasons"] = _merge_unique_strings(bucket.get("reasons") or [], *reasons)
    counter_map[key] = bucket
    return counter_map


def _strongest_candidate(candidates):
    best_type = ""
    best_data = {}
    best_rank = -1
    best_count = -1

    for candidate_type, data in (candidates or {}).items():
        strength_rank = _fingerprint_confidence_rank((data or {}).get("best_strength"))
        count = int((data or {}).get("count", 0) or 0)
        if strength_rank > best_rank or (strength_rank == best_rank and count > best_count):
            best_type = candidate_type
            best_data = data or {}
            best_rank = strength_rank
            best_count = count

    return best_type, best_data


def _candidate_map_count(counter_map, candidate_types, *, min_strength="low"):
    minimum_rank = _fingerprint_confidence_rank(min_strength)
    total = 0
    best_rank = -1
    reasons = []

    for candidate_type in (candidate_types or []):
        bucket = (counter_map or {}).get(candidate_type) if isinstance(counter_map, dict) else None
        if not isinstance(bucket, dict):
            continue
        strength = (bucket.get("best_strength") or "").strip().lower()
        strength_rank = _fingerprint_confidence_rank(strength)
        if strength_rank < minimum_rank:
            continue
        total += int(bucket.get("count", 0) or 0)
        best_rank = max(best_rank, strength_rank)
        reasons = _merge_unique_strings(reasons, *(bucket.get("reasons") or []))

    return {
        "count": total,
        "best_strength": {3: "high", 2: "medium", 1: "low"}.get(best_rank, ""),
        "reasons": reasons,
    }


def _history_text_blob(history):
    history = history if isinstance(history, dict) else {}
    return " ".join([
        " ".join(str(item or "") for item in (history.get("hostnames") or [])),
        " ".join(str(item or "") for item in (history.get("http_titles") or [])),
        " ".join(str(item or "") for item in (history.get("http_servers") or [])),
        " ".join(str(item or "") for item in (history.get("http_keywords") or [])),
        " ".join(str(item or "") for item in (history.get("ssh_banners") or [])),
        " ".join(str(item or "") for item in (history.get("vendors") or [])),
    ]).lower()


def _fingerprint_library_conflicts(candidate_type, candidate_count, learned_candidates):
    candidate_family = _candidate_family(candidate_type)
    for other_type, data in (learned_candidates or {}).items():
        if _candidate_family(other_type) == candidate_family:
            continue
        if not isinstance(data, dict):
            continue
        if _fingerprint_confidence_rank((data.get("best_strength") or "").strip().lower()) < 2:
            continue
        if int(data.get("count", 0) or 0) >= int(candidate_count or 0):
            return True
    return False


def _build_self_learning_fingerprint_library(history, learned_candidates):
    history = history if isinstance(history, dict) else {}
    learned_candidates = learned_candidates if isinstance(learned_candidates, dict) else {}
    validation_platforms = history.get("validation_fingerprint_platforms") if isinstance(history.get("validation_fingerprint_platforms"), dict) else {}
    observed_platforms = history.get("observed_platforms") if isinstance(history.get("observed_platforms"), dict) else {}
    signal_candidates = history.get("signal_candidates") if isinstance(history.get("signal_candidates"), dict) else {}
    ports = set(int(port) for port in (history.get("open_ports") or []) if str(port).isdigit())
    text = _history_text_blob(history)
    library_candidates = {}

    def add_library_candidate(candidate_type, *, confidence="", count=0, reasons=None):
        candidate_type = normalize_platform_name(candidate_type)
        if not candidate_type or int(count or 0) < 2:
            return
        if candidate_type in ("unknown", "generic", "web-device", "linux-web-device"):
            return
        if _fingerprint_confidence_rank(confidence) < 2:
            return
        if _fingerprint_library_conflicts(candidate_type, count, learned_candidates):
            return
        library_candidates[candidate_type] = {
            "count": int(count or 0),
            "best_strength": confidence,
            "reasons": _merge_unique_strings([], *(reasons or [])),
        }

    def signal_data(candidate_type):
        data = _candidate_map_count(signal_candidates, (candidate_type,), min_strength="medium")
        return data if int(data.get("count", 0) or 0) >= 3 else {"count": 0, "best_strength": "", "reasons": []}

    qsys_direct = _candidate_map_count(validation_platforms, ("qsys", "qsys-core", "qsys-touchpanel", "qsys-nv", "qsys-nv21", "qsys-nv32"), min_strength="medium")
    qsys_observed = _candidate_map_count(observed_platforms, ("qsys", "qsys-core", "qsys-touchpanel", "qsys-nv", "qsys-nv21", "qsys-nv32"), min_strength="medium")
    qsys_signals = signal_data("qsys")
    qsys_context = max(qsys_direct["count"], qsys_signals["count"]) >= 2 and (1710 in ports or _contains_any_token(text, ("q-sys", "qsys", "qsc")))
    if qsys_context:
        qsys_confidence = qsys_direct["best_strength"] or qsys_observed["best_strength"] or qsys_signals["best_strength"]
        qsys_count = max(qsys_direct["count"], qsys_observed["count"], qsys_signals["count"])
        qsys_reasons = qsys_direct["reasons"] + qsys_observed["reasons"] + qsys_signals["reasons"] + ["repeated strong Q-SYS family evidence"]
        add_library_candidate("qsys", confidence=qsys_confidence, count=qsys_count, reasons=qsys_reasons)
        if 1710 in ports and qsys_count >= 2:
            add_library_candidate("qsys-core", confidence=qsys_confidence, count=qsys_count, reasons=qsys_reasons + ["repeated strong evidence plus Q-SYS control port 1710"])
        if _contains_any_token(text, ("tsc-", "touchscreen controller", "qsys touch", "q-sys touch")) and qsys_count >= 2:
            add_library_candidate("qsys-touchpanel", confidence=qsys_confidence, count=qsys_count, reasons=qsys_reasons + ["repeated Q-SYS touchpanel naming evidence"])
        if _contains_any_token(text, ("nv-21", "nv21", "nv-32", "nv32", "nv-32-h", "nv32-h")) and qsys_count >= 2:
            add_library_candidate("qsys-nv", confidence=qsys_confidence, count=qsys_count, reasons=qsys_reasons + ["repeated Q-SYS NV endpoint naming evidence"])
            if _contains_any_token(text, ("nv-21", "nv21")):
                add_library_candidate("qsys-nv21", confidence=qsys_confidence, count=qsys_count, reasons=qsys_reasons + ["repeated Q-SYS NV-21 naming evidence"])
            if _contains_any_token(text, ("nv-32", "nv32", "nv-32-h", "nv32-h")):
                add_library_candidate("qsys-nv32", confidence=qsys_confidence, count=qsys_count, reasons=qsys_reasons + ["repeated Q-SYS NV-32 naming evidence"])

    biamp_direct = _candidate_map_count(validation_platforms, ("biamp", "biamp-tesira"), min_strength="medium")
    biamp_observed = _candidate_map_count(observed_platforms, ("biamp", "biamp-tesira"), min_strength="medium")
    biamp_signals = signal_data("biamp-tesira")
    biamp_context = max(biamp_direct["count"], biamp_signals["count"]) >= 2 and _contains_any_token(text, ("biamp", "tesira"))
    if biamp_context:
        biamp_confidence = biamp_direct["best_strength"] or biamp_observed["best_strength"] or biamp_signals["best_strength"]
        biamp_count = max(biamp_direct["count"], biamp_observed["count"], biamp_signals["count"])
        biamp_reasons = biamp_direct["reasons"] + biamp_observed["reasons"] + biamp_signals["reasons"] + ["repeated strong Biamp family evidence"]
        add_library_candidate("biamp", confidence=biamp_confidence, count=biamp_count, reasons=biamp_reasons)
        if _contains_any_token(text, ("tesira", "biamp-")):
            add_library_candidate("biamp-tesira", confidence=biamp_confidence, count=biamp_count, reasons=biamp_reasons + ["repeated Biamp/Tesira naming evidence"])

    crestron_direct = _candidate_map_count(validation_platforms, ("crestron", "crestron_control", "crestron_touchpanel", "crestron_uc"), min_strength="medium")
    crestron_observed = _candidate_map_count(observed_platforms, ("crestron", "crestron_control", "crestron_touchpanel", "crestron_uc"), min_strength="medium")
    crestron_signals = signal_data("crestron")
    crestron_context = max(crestron_direct["count"], crestron_signals["count"]) >= 2 and (any(port in ports for port in (41794, 41795, 41796)) or "crestron" in text)
    if crestron_context:
        crestron_confidence = crestron_direct["best_strength"] or crestron_observed["best_strength"] or crestron_signals["best_strength"]
        crestron_count = max(crestron_direct["count"], crestron_observed["count"], crestron_signals["count"])
        crestron_reasons = crestron_direct["reasons"] + crestron_observed["reasons"] + crestron_signals["reasons"] + ["repeated strong Crestron family evidence"]
        add_library_candidate("crestron", confidence=crestron_confidence, count=crestron_count, reasons=crestron_reasons)
        if _contains_any_token(text, ("cp4", "mc4", "rmc4", "pro4")) or any(port in ports for port in (41794, 41795, 41796)):
            add_library_candidate("crestron_control", confidence=crestron_confidence, count=crestron_count, reasons=crestron_reasons + ["repeated Crestron control processor evidence"])
        if _contains_any_token(text, ("tsw", "tss", "touchpanel", "touch panel")):
            add_library_candidate("crestron_touchpanel", confidence=crestron_confidence, count=crestron_count, reasons=crestron_reasons + ["repeated Crestron touchpanel evidence"])
        if _contains_any_token(text, ("uc-", "flex", "teams")):
            add_library_candidate("crestron_uc", confidence=crestron_confidence, count=crestron_count, reasons=crestron_reasons + ["repeated Crestron UC evidence"])

    video_direct = _candidate_map_count(validation_platforms, ("video-wall-processor",), min_strength="medium")
    video_observed = _candidate_map_count(observed_platforms, ("video-wall-processor",), min_strength="medium")
    video_signals = signal_data("video-wall-processor")
    video_context = max(video_direct["count"], video_observed["count"], video_signals["count"]) >= 2 and _is_video_processing_match(text) and any(port in ports for port in (80, 443, 8080, 22))
    if video_context:
        video_confidence = video_direct["best_strength"] or video_observed["best_strength"] or video_signals["best_strength"]
        video_count = max(video_direct["count"], video_observed["count"], video_signals["count"])
        video_reasons = video_direct["reasons"] + video_observed["reasons"] + video_signals["reasons"] + ["repeated strong video-wall processor evidence"]
        add_library_candidate("video-wall-processor", confidence=video_confidence, count=video_count, reasons=video_reasons)

    suggested_type, suggested_data = _strongest_candidate(library_candidates)
    return {
        "type_candidates": library_candidates,
        "suggested_type": suggested_type,
        "confidence": (suggested_data.get("best_strength") or "") if suggested_type else "",
        "observation_count": int(suggested_data.get("count", 0) or 0) if suggested_type else 0,
        "basis": copy.deepcopy(suggested_data.get("reasons") or []) if suggested_type else [],
        "note": "Reusable device-class patterns are promoted only from repeated strong evidence with identity safety still enforced.",
    }


def _build_device_observation(device, *, source="", result=None, extra=None):
    device = device or {}
    result = result or {}
    extra = extra or {}
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    fingerprint = result.get("fingerprint") if isinstance(result.get("fingerprint"), dict) else {}
    observed_platform = result.get("observed_platform") if isinstance(result.get("observed_platform"), dict) else {}
    http_summary = evidence.get("http") if isinstance(evidence.get("http"), dict) else {}
    ssh_summary = evidence.get("ssh") if isinstance(evidence.get("ssh"), dict) else {}

    stable_hostname = ""
    for candidate in (
        extra.get("stable_hostname"),
        extra.get("hostname"),
        extra.get("reverse_dns"),
        extra.get("mdns_name"),
        device.get("hostname"),
        device.get("name"),
    ):
        stable_hostname = _normalize_identity_hostname(candidate)
        if stable_hostname:
            break

    open_ports = list(evidence.get("open_ports") or result.get("open_ports") or extra.get("open_ports") or [])

    return {
        "name": (device.get("name") or "").strip(),
        "source": (source or extra.get("source") or "").strip(),
        "seen_at": utc_now_iso(),
        "ip": (device.get("ip") or result.get("ip") or evidence.get("ip") or extra.get("ip") or "").strip(),
        "mac": _normalize_identity_mac(device.get("mac") or evidence.get("mac") or extra.get("mac")),
        "vendor": (device.get("vendor") or evidence.get("vendor") or extra.get("vendor") or "").strip(),
        "hostname": (extra.get("hostname") or device.get("hostname") or "").strip(),
        "reverse_dns": (extra.get("reverse_dns") or "").strip(),
        "mdns_name": (extra.get("mdns_name") or "").strip(),
        "stable_hostname": stable_hostname,
        "open_ports": [int(port) for port in open_ports if str(port).isdigit()],
        "http_title": (http_summary.get("title") or extra.get("http_title") or "").strip(),
        "http_server": (http_summary.get("server") or extra.get("http_server") or "").strip(),
        "http_keywords": [str(item).strip().lower() for item in (http_summary.get("keywords") or extra.get("http_keywords") or []) if str(item).strip()],
        "ssh_banner": (ssh_summary.get("banner") or extra.get("ssh_banner") or "").strip(),
        "validation_fingerprint_platform": normalize_platform_name(fingerprint.get("platform")),
        "validation_fingerprint_confidence": (fingerprint.get("confidence") or "").strip().lower(),
        "observed_platform": normalize_platform_name(observed_platform.get("platform")),
        "observed_platform_confidence": (observed_platform.get("confidence") or "").strip().lower(),
        "guessed_type": (extra.get("guessed_type") or "").strip(),
        "inventory_type": (extra.get("inventory_type") or device.get("type") or "").strip(),
    }


def _merge_device_evidence_record(existing, observation, identity_key, identity_kind):
    existing = copy.deepcopy(existing or {})
    observation = copy.deepcopy(observation or {})
    seen_at = observation.get("seen_at") or utc_now_iso()

    latest = copy.deepcopy(existing.get("latest") or {})
    latest.update({k: v for k, v in observation.items() if k != "seen_at"})
    latest["open_ports"] = _merge_unique_ports([], observation.get("open_ports"))

    identity = copy.deepcopy(existing.get("identity") or {})
    identity["key"] = identity_key
    identity["key_type"] = identity_kind
    if observation.get("ip"):
        identity["ip"] = observation.get("ip")
    if observation.get("mac"):
        identity["mac"] = observation.get("mac")
    if observation.get("stable_hostname"):
        identity["stable_hostname"] = observation.get("stable_hostname")
    identity["aliases"] = _merge_unique_strings(
        identity.get("aliases") or [],
        identity_key,
        *(key for _, key in _observation_identity_candidates(observation)),
    )

    source = observation.get("source") or "unknown"
    sources = copy.deepcopy(existing.get("sources") or {})
    sources[source] = int(sources.get(source, 0) or 0) + 1

    history = copy.deepcopy(existing.get("history") or {})
    history["ips"] = _merge_unique_strings(history.get("ips") or [], observation.get("ip"))
    history["hostnames"] = _merge_unique_strings(
        history.get("hostnames") or [],
        observation.get("hostname"),
        observation.get("reverse_dns"),
        observation.get("mdns_name"),
        observation.get("stable_hostname"),
    )
    history["vendors"] = _merge_unique_strings(history.get("vendors") or [], observation.get("vendor"))
    history["open_ports"] = _merge_unique_ports(history.get("open_ports") or [], observation.get("open_ports"))
    history["http_titles"] = _merge_unique_strings(history.get("http_titles") or [], observation.get("http_title"))
    history["http_servers"] = _merge_unique_strings(history.get("http_servers") or [], observation.get("http_server"))
    history["http_keywords"] = _merge_unique_strings(history.get("http_keywords") or [], *(observation.get("http_keywords") or []))
    history["ssh_banners"] = _merge_unique_strings(history.get("ssh_banners") or [], observation.get("ssh_banner"))

    guessed_types = copy.deepcopy(history.get("guessed_types") or {})
    if observation.get("guessed_type"):
        _bump_count_map(
            guessed_types,
            observation.get("guessed_type"),
            strength="low",
            seen_at=seen_at,
            source=source,
            reasons=["observed guessed_type"],
        )
    history["guessed_types"] = guessed_types

    fingerprint_platforms = copy.deepcopy(history.get("validation_fingerprint_platforms") or {})
    if observation.get("validation_fingerprint_platform") and observation.get("validation_fingerprint_platform") != "unknown":
        _bump_count_map(
            fingerprint_platforms,
            observation.get("validation_fingerprint_platform"),
            strength=observation.get("validation_fingerprint_confidence"),
            seen_at=seen_at,
            source=source,
            reasons=["validation fingerprint"],
        )
    history["validation_fingerprint_platforms"] = fingerprint_platforms

    observed_platforms = copy.deepcopy(history.get("observed_platforms") or {})
    if observation.get("observed_platform") and observation.get("observed_platform") != "unknown":
        _bump_count_map(
            observed_platforms,
            observation.get("observed_platform"),
            strength=observation.get("observed_platform_confidence"),
            seen_at=seen_at,
            source=source,
            reasons=["observed platform"],
        )
    history["observed_platforms"] = observed_platforms

    learned_candidates = copy.deepcopy((existing.get("learned") or {}).get("type_candidates") or {})
    if observation.get("validation_fingerprint_platform") and observation.get("validation_fingerprint_platform") != "unknown":
        _bump_count_map(
            learned_candidates,
            observation.get("validation_fingerprint_platform"),
            strength=observation.get("validation_fingerprint_confidence"),
            seen_at=seen_at,
            source=source,
            reasons=["validation fingerprint"],
        )
    if observation.get("observed_platform") and observation.get("observed_platform") != "unknown":
        observed_strength = observation.get("observed_platform_confidence")
        if _fingerprint_confidence_rank(observed_strength) > 1:
            observed_strength = "medium"
        _bump_count_map(
            learned_candidates,
            observation.get("observed_platform"),
            strength=observed_strength,
            seen_at=seen_at,
            source=source,
            reasons=["observed platform"],
        )
    if observation.get("guessed_type"):
        _bump_count_map(
            learned_candidates,
            observation.get("guessed_type"),
            strength="low",
            seen_at=seen_at,
            source=source,
            reasons=["observed guessed_type"],
        )

    signal_candidates = copy.deepcopy(history.get("signal_candidates") or {})
    observation_text = " ".join([
        str(observation.get("stable_hostname") or ""),
        str(observation.get("hostname") or ""),
        str(observation.get("reverse_dns") or ""),
        str(observation.get("mdns_name") or ""),
        str(observation.get("http_title") or ""),
        str(observation.get("http_server") or ""),
        " ".join(str(item) for item in (observation.get("http_keywords") or [])),
        str(observation.get("ssh_banner") or ""),
    ]).lower()
    signal_defs = (
        ("biamp-tesira", ("biamp-", " biamp", "tesira"), "medium", "vendor fingerprint signal"),
        ("barco-device", ("barco", "clickshare", "barco ctrl"), "medium", "vendor fingerprint signal"),
        ("qsys", ("q-sys", "qsys", "qsc"), "medium", "vendor fingerprint signal"),
        ("crestron", ("crestron", "cp4", "mc4", "rmc4", "pro4", "tsw", "tss"), "medium", "vendor fingerprint signal"),
    )
    for candidate_type, tokens, strength, reason in signal_defs:
        matched = False
        for token in tokens:
            token = str(token or "").lower()
            if not token:
                continue
            if token.endswith("-") and (observation.get("stable_hostname") or "").lower().startswith(token):
                matched = True
                break
            if token in observation_text:
                matched = True
                break
        if matched:
            _bump_count_map(
                signal_candidates,
                candidate_type,
                strength=strength,
                seen_at=seen_at,
                source=source,
                reasons=[reason],
            )
    history["signal_candidates"] = signal_candidates

    suggested_type, suggested_data = _strongest_candidate(learned_candidates)
    learned = copy.deepcopy(existing.get("learned") or {})
    learned["type_candidates"] = learned_candidates
    learned["suggested_type"] = suggested_type
    learned["confidence"] = (suggested_data.get("best_strength") or "low") if suggested_type else ""
    learned["observation_count"] = int(suggested_data.get("count", 0) or 0) if suggested_type else 0
    learned["basis"] = copy.deepcopy(suggested_data.get("reasons") or []) if suggested_type else []
    learned["fingerprint_library"] = _build_self_learning_fingerprint_library(history, learned_candidates)
    learned["inventory_type"] = observation.get("inventory_type") or learned.get("inventory_type") or ""
    learned["will_override_inventory_type"] = False
    learned["note"] = "Conservative evidence only. Weak learned signals do not rewrite saved device truth."

    return {
        "identity": identity,
        "first_seen": existing.get("first_seen") or seen_at,
        "last_seen": seen_at,
        "seen_count": int(existing.get("seen_count", 0) or 0) + 1,
        "last_source": source,
        "sources": sources,
        "latest": latest,
        "history": history,
        "learned": learned,
    }


def record_device_observation(device, *, source="", result=None, extra=None):
    observation = _build_device_observation(device, source=source, result=result, extra=extra)
    candidates = _observation_identity_candidates(observation)
    if not candidates:
        return None

    primary_kind, primary_key = candidates[0]

    with DEVICE_EVIDENCE_LOCK:
        store = load_device_evidence()
        match = _find_evidence_record_match(store, observation)
        if match:
            matched_key = match.get("key") or ""
            matched_kind = match.get("match_kind") or _identity_kind_from_key(matched_key)
        else:
            matched_key = ""
            matched_kind = ""

        target_key = matched_key or primary_key
        target_kind = matched_kind or primary_kind

        if matched_key and primary_key != matched_key and _identity_priority(primary_key) > _identity_priority(matched_key):
            if matched_kind == "ip":
                base_record = {}
            else:
                base_record = copy.deepcopy(store.pop(matched_key, {}))
            target_key = primary_key
            target_kind = primary_kind
        else:
            base_record = copy.deepcopy(store.get(target_key, {}))

        store[target_key] = _merge_device_evidence_record(base_record, observation, target_key, target_kind)
        save_device_evidence(store)

    return target_key


def _stable_fingerprint_key(device, result=None):
    observation = _build_device_observation(device, source="fingerprint_store", result=result or {}, extra={})
    candidates = _observation_identity_candidates(observation)
    if candidates:
        return candidates[0][1]

    result = result or {}
    mac = (device.get("mac") or "").strip()
    evidence_mac = ((result.get("evidence") or {}).get("mac") or "").strip()
    candidate_mac = mac or evidence_mac

    if candidate_mac and candidate_mac not in ("â€”", "-", "unknown"):
        return f"mac:{candidate_mac.upper()}"

    ip = (device.get("ip") or result.get("ip") or "").strip()
    if ip:
        return f"ip:{ip}"

    return None


def _enforce_fingerprint_identity(key, record):
    fixed = copy.deepcopy(record or {})
    ip_value = (fixed.get("ip") or "").strip()
    evidence = fixed.get("evidence") if isinstance(fixed.get("evidence"), dict) else {}
    evidence_ip = (evidence.get("ip") or "").strip()

    if key.startswith("ip:"):
        key_ip = key.split(":", 1)[1].strip()
        fixed["ip"] = key_ip
        if evidence:
            evidence["ip"] = key_ip
            fixed["evidence"] = evidence
        return fixed

    if ip_value:
        fixed["ip"] = ip_value
    elif evidence_ip:
        fixed["ip"] = evidence_ip

    if evidence:
        evidence["ip"] = fixed.get("ip", "")
        fixed["evidence"] = evidence

    return fixed


def merge_fingerprint(existing, new):
    existing = copy.deepcopy(existing or {})
    new = copy.deepcopy(new or {})
    merged = copy.deepcopy(existing)

    merged["last_seen"] = new.get("last_seen") or existing.get("last_seen") or ""

    for field in ("ip", "mac", "vendor", "type", "av_role"):
        new_value = (new.get(field) or "").strip() if isinstance(new.get(field), str) else new.get(field)
        old_value = (existing.get(field) or "").strip() if isinstance(existing.get(field), str) else existing.get(field)
        if new_value:
            if field == "type" and old_value and old_value not in ("", "generic", "unknown") and new_value in ("", "generic", "unknown"):
                continue
            merged[field] = copy.deepcopy(new_value)
        elif field not in merged:
            merged[field] = copy.deepcopy(old_value)

    existing_ports = {int(port) for port in (existing.get("open_ports") or []) if str(port).isdigit()}
    new_ports = {int(port) for port in (new.get("open_ports") or []) if str(port).isdigit()}
    merged["open_ports"] = sorted(existing_ports.union(new_ports))

    service_map = {}
    for service in existing.get("services") or []:
        if isinstance(service, dict) and service.get("port") is not None:
            service_map[int(service.get("port"))] = service.get("name", "unknown")
    for service in new.get("services") or []:
        if isinstance(service, dict) and service.get("port") is not None:
            port = int(service.get("port"))
            name = service.get("name", "unknown")
            if port not in service_map or (service_map.get(port) in ("", "unknown") and name not in ("", "unknown")):
                service_map[port] = name
    merged["services"] = [{"port": port, "name": service_map[port]} for port in sorted(service_map.keys())]

    existing_http = existing.get("http") or {}
    new_http = new.get("http") or {}
    merged_http = {
        "title": (existing_http.get("title") or ""),
        "server": (existing_http.get("server") or ""),
        "headers": dict(existing_http.get("headers") or {}),
    }
    if new_http.get("title"):
        merged_http["title"] = new_http.get("title")
    if new_http.get("server"):
        merged_http["server"] = new_http.get("server")
    for key, value in (new_http.get("headers") or {}).items():
        if key and value:
            merged_http["headers"][key] = value
    merged["http"] = copy.deepcopy(merged_http)

    existing_fp = existing.get("fingerprint") or {}
    new_fp = new.get("fingerprint") or {}
    if _fingerprint_confidence_rank(new_fp.get("confidence")) >= _fingerprint_confidence_rank(existing_fp.get("confidence")):
        merged["fingerprint"] = {
            "platform": new_fp.get("platform", "") or existing_fp.get("platform", ""),
            "confidence": new_fp.get("confidence", "") or existing_fp.get("confidence", ""),
            "reasons": list(new_fp.get("reasons", []) or existing_fp.get("reasons", []) or []),
        }
    else:
        merged["fingerprint"] = copy.deepcopy(existing_fp)

    merged["evidence"] = copy.deepcopy(existing.get("evidence") or {})
    new_evidence = copy.deepcopy(new.get("evidence") or {})
    merged["evidence"].update(new_evidence)

    merged_ip = (merged.get("ip") or "").strip()
    evidence_ip = ((merged.get("evidence") or {}).get("ip") or "").strip()
    if merged_ip:
        merged["evidence"]["ip"] = merged_ip
    elif evidence_ip:
        merged["ip"] = evidence_ip

    return merged


def _build_fingerprint_entry(device, result, av_role=None):
    result = copy.deepcopy(result or {})
    evidence = copy.deepcopy(result.get("evidence") or {})
    device_ip = (device.get("ip") or result.get("ip") or evidence.get("ip") or "").strip()
    evidence["ip"] = device_ip
    return {
        "ip": device_ip,
        "mac": (device.get("mac") or evidence.get("mac") or "").strip(),
        "vendor": (device.get("vendor") or evidence.get("vendor") or "").strip(),
        "type": (result.get("type") or device.get("type") or evidence.get("type") or "").strip(),
        "av_role": (av_role or result.get("av_role") or "").strip(),
        "open_ports": list(evidence.get("open_ports") or result.get("open_ports") or []),
        "http": copy.deepcopy(evidence.get("http") or {}),
        "services": copy.deepcopy(evidence.get("services") or []),
        "fingerprint": copy.deepcopy(result.get("fingerprint") or evidence.get("fingerprint") or {}),
        "evidence": evidence,
        "last_seen": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }


def update_fingerprint_store(entries):
    fingerprints = load_fingerprints()

    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        key = entry.get("key")
        record = entry.get("record")
        if not key or not isinstance(record, dict):
            continue
        safe_record = _enforce_fingerprint_identity(key, record)
        fingerprints[key] = _enforce_fingerprint_identity(
            key,
            merge_fingerprint(fingerprints.get(key, {}), safe_record),
        )

    save_fingerprints(fingerprints)

def save_run(results):
    runs_dir = _runs_dir()
    os.makedirs(runs_dir, exist_ok=True)

    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    path = os.path.join(runs_dir, f'{ts}.json')

    with open(path, 'w') as f:
        json.dump(results, f, indent=2)

    return path



# â”€â”€ Pages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _project_root():
    return os.path.abspath(os.path.dirname(__file__))


def _normalize_snapshot_relpath(value):
    text = str(value or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    text = re.sub(r"/+", "/", text)
    return text


def _is_safe_snapshot_member(name):
    rel = _normalize_snapshot_relpath(name)
    if not rel or rel.endswith("/"):
        return False
    if rel.startswith("/") or rel.startswith("\\"):
        return False
    if re.match(r"^[A-Za-z]:", rel):
        return False

    parts = rel.split("/")
    for part in parts:
        if not part or part in {".", ".."}:
            return False
        if part.startswith("."):
            return False
    return True


def _rel_to_abs_project_path(relpath):
    rel = _normalize_snapshot_relpath(relpath)
    return get_project_path(rel)


def _is_within_project_root(path):
    try:
        active_root = _project_dir()
        return os.path.commonpath([active_root, os.path.abspath(path)]) == active_root
    except Exception:
        return False


def _safe_instance_metadata():
    return {
        "hostname": socket.gethostname(),
        "platform": platform.system(),
    }


def _collect_snapshot_files():
    included = {}
    missing_optional = []
    notes = []

    for rel in PROJECT_STATE_REQUIRED_FILES:
        target = _rel_to_abs_project_path(rel)
        if not _is_within_project_root(target):
            notes.append(f"Skipped unsafe required path mapping: {rel}")
            continue
        if os.path.isfile(target):
            included[rel] = target
        else:
            notes.append(f"Required state file unavailable: {rel}")

    for rel in PROJECT_STATE_OPTIONAL_FILES:
        target = _rel_to_abs_project_path(rel)
        if not _is_within_project_root(target):
            notes.append(f"Skipped unsafe optional path mapping: {rel}")
            continue
        if os.path.isfile(target):
            included[rel] = target
        else:
            missing_optional.append(rel)

    return included, sorted(set(missing_optional)), notes


def _atomic_write_bytes(path, payload):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    temp_path = path + f".restore_tmp_{int(time.time() * 1000)}"
    with open(temp_path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return temp_path


def _create_pre_restore_backup():
    backup_root = get_project_path(PROJECT_BACKUPS_DIRNAME, ensure_parent=True)
    os.makedirs(backup_root, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    backup_name = f"netpi_pre_restore_{timestamp}.avp"
    backup_path = os.path.join(backup_root, backup_name)

    files, _, notes = _collect_snapshot_files()
    included_files = []

    with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for rel, abs_path in files.items():
            try:
                archive.write(abs_path, arcname=rel)
                included_files.append(rel)
            except Exception as exc:
                notes.append(f"Backup skipped unreadable file {rel}: {exc}")

        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "schema_version": SNAPSHOT_SCHEMA_VERSION,
                    "created_at": utc_now_iso(),
                    "app_name": "NetPi",
                    "type": "pre_restore_backup",
                    "included_files": included_files,
                    "notes": notes,
                },
                indent=2
            ),
        )

    return backup_path, notes


def _get_uploaded_snapshot_file():
    if "snapshot" in request.files:
        return request.files["snapshot"]
    if "file" in request.files:
        return request.files["file"]
    for _, uploaded in request.files.items():
        return uploaded
    return None


def _read_uploaded_snapshot_archive(uploaded, label):
    if uploaded is None or not getattr(uploaded, "filename", ""):
        raise ValueError(f"{label}: snapshot file is required.")

    payload = uploaded.read()
    archive_handle = io.BytesIO(payload)
    try:
        archive = zipfile.ZipFile(archive_handle, "r")
    except zipfile.BadZipFile:
        raise ValueError(f"{label}: invalid archive format; expected .avp/.zip.")

    with archive:
        file_members = {}
        invalid_members = []
        duplicate_members = []

        for info in archive.infolist():
            if info.is_dir():
                continue
            normalized = _normalize_snapshot_relpath(info.filename)
            if not _is_safe_snapshot_member(normalized):
                invalid_members.append(info.filename)
                continue
            if normalized in file_members:
                duplicate_members.append(normalized)
                continue
            file_members[normalized] = info

        if invalid_members:
            raise ValueError(f"{label}: archive contains invalid file paths: {sorted(invalid_members)}")
        if duplicate_members:
            raise ValueError(f"{label}: archive contains duplicate file paths: {sorted(set(duplicate_members))}")
        if "manifest.json" not in file_members:
            raise ValueError(f"{label}: archive is missing manifest.json.")

        try:
            manifest_raw = archive.read(file_members["manifest.json"])
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except json.JSONDecodeError:
            raise ValueError(f"{label}: manifest.json is not valid JSON.")
        except UnicodeDecodeError:
            raise ValueError(f"{label}: manifest.json must be UTF-8 JSON.")

        if not isinstance(manifest, dict):
            raise ValueError(f"{label}: invalid manifest format.")

        schema_version = str(manifest.get("schema_version") or "").strip()
        if schema_version != SNAPSHOT_SCHEMA_VERSION:
            raise ValueError(
                f"{label}: unsupported schema_version '{schema_version}'. Expected '{SNAPSHOT_SCHEMA_VERSION}'."
            )

        disallowed_files = []
        files = {}
        for rel, info in file_members.items():
            if rel == "manifest.json":
                continue
            if rel not in PROJECT_RESTORE_ALLOWLIST:
                disallowed_files.append(rel)
                continue
            raw = archive.read(info)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise ValueError(f"{label}: file '{rel}' must be UTF-8 JSON.")
            except json.JSONDecodeError:
                raise ValueError(f"{label}: file '{rel}' is not valid JSON.")
            files[rel] = parsed

        if disallowed_files:
            raise ValueError(f"{label}: archive contains disallowed files: {sorted(disallowed_files)}")

        included_files = manifest.get("included_files")
        if not isinstance(included_files, list):
            included_files = sorted(files.keys())
        else:
            included_files = [str(item) for item in included_files]

        return {
            "schema_version": schema_version,
            "exported_at": str(manifest.get("exported_at") or ""),
            "included_files": included_files,
            "files": files,
        }


def _extract_snapshot_devices(files):
    payload = files.get("devices.json")
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows = payload.get("devices")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _extract_snapshot_settings(files):
    payload = files.get("settings.json")
    return payload if isinstance(payload, dict) else {}


def _snapshot_device_display(device):
    device = device if isinstance(device, dict) else {}
    return {
        "name": str(device.get("name") or "").strip(),
        "hostname": str(device.get("hostname") or device.get("stable_hostname") or "").strip(),
        "ip": str(device.get("ip") or "").strip(),
        "mac": _normalize_mac_value(device.get("mac") or device.get("mac_address")),
        "type": str(device.get("type") or device.get("effective_type") or "").strip(),
    }


def _snapshot_device_identity_mac(device):
    return _normalize_mac_value((device or {}).get("mac") or (device or {}).get("mac_address"))


def _snapshot_device_identity_ip(device):
    return str((device or {}).get("ip") or "").strip()


def _snapshot_device_identity_name(device):
    device = device if isinstance(device, dict) else {}
    for key in ("name", "hostname", "stable_hostname"):
        value = str(device.get(key) or "").strip()
        lowered = value.lower()
        if value and lowered not in {"unknown", "n/a", "none", "-", "â€”"}:
            return lowered
    return ""


def _normalize_compare_value(value):
    if isinstance(value, list):
        return sorted((_normalize_compare_value(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, dict):
        return {str(k): _normalize_compare_value(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, str):
        return value.strip()
    return value


def _snapshot_device_field_value(device, field):
    device = device if isinstance(device, dict) else {}
    if field == "open_ports":
        ports = []
        for port in (device.get("open_ports") or []):
            if str(port).isdigit():
                ports.append(int(port))
            else:
                ports.append(str(port))
        return sorted(set(ports), key=lambda item: str(item))
    if field in {"mac", "mac_address"}:
        return _normalize_mac_value(device.get("mac") or device.get("mac_address"))
    return _normalize_compare_value(device.get(field))


def _compare_snapshot_devices(baseline_devices, current_devices):
    baseline_records = [{"device": device, "matched": False} for device in baseline_devices]
    current_records = [{"device": device, "matched": False} for device in current_devices]
    matches = []

    def _match_unique(identity_name, extractor):
        baseline_map = {}
        current_map = {}
        for idx, record in enumerate(baseline_records):
            if record["matched"]:
                continue
            key = extractor(record["device"])
            if not key:
                continue
            baseline_map.setdefault(key, []).append(idx)
        for idx, record in enumerate(current_records):
            if record["matched"]:
                continue
            key = extractor(record["device"])
            if not key:
                continue
            current_map.setdefault(key, []).append(idx)

        for key in sorted(set(baseline_map.keys()) & set(current_map.keys())):
            if len(baseline_map[key]) != 1 or len(current_map[key]) != 1:
                continue
            left_idx = baseline_map[key][0]
            right_idx = current_map[key][0]
            baseline_records[left_idx]["matched"] = True
            current_records[right_idx]["matched"] = True
            matches.append((left_idx, right_idx, identity_name, key))

    _match_unique("mac", _snapshot_device_identity_mac)
    _match_unique("ip", _snapshot_device_identity_ip)
    _match_unique("name", _snapshot_device_identity_name)

    changed = []
    for left_idx, right_idx, identity_type, identity_value in matches:
        left = baseline_records[left_idx]["device"]
        right = current_records[right_idx]["device"]
        field_changes = []
        for field in SNAPSHOT_COMPARE_DEVICE_FIELDS:
            left_value = _snapshot_device_field_value(left, field)
            right_value = _snapshot_device_field_value(right, field)
            if left_value != right_value:
                field_changes.append({
                    "field": field,
                    "baseline": left_value,
                    "current": right_value,
                })
        if field_changes:
            changed.append({
                "identity": {
                    "type": identity_type,
                    "value": identity_value,
                },
                "baseline_ref": _snapshot_device_display(left),
                "current_ref": _snapshot_device_display(right),
                "fields": field_changes,
            })

    added = [_snapshot_device_display(r["device"]) for r in current_records if not r["matched"]]
    removed = [_snapshot_device_display(r["device"]) for r in baseline_records if not r["matched"]]

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _normalize_vlan_rows(vlans):
    normalized = []
    for vlan in vlans or []:
        if not isinstance(vlan, dict):
            continue
        row = {
            "name": str(vlan.get("name") or "").strip(),
            "vlan_id": str(vlan.get("vlan_id") or vlan.get("id") or "").strip(),
            "subnet": str(vlan.get("subnet") or "").strip(),
            "gateway": str(vlan.get("gateway") or "").strip(),
            "dhcp_range_start": str(vlan.get("dhcp_range_start") or "").strip(),
            "dhcp_range_end": str(vlan.get("dhcp_range_end") or "").strip(),
            "notes": str(vlan.get("notes") or "").strip(),
            "device_types": sorted([str(item).strip() for item in (vlan.get("device_types") or []) if str(item).strip()]),
        }
        normalized.append(row)
    normalized.sort(key=lambda item: (item.get("name") or "", item.get("vlan_id") or ""))
    return normalized


def _compare_snapshot_settings(baseline_settings, current_settings):
    baseline_settings = baseline_settings if isinstance(baseline_settings, dict) else {}
    current_settings = current_settings if isinstance(current_settings, dict) else {}
    changed = []

    for field in ("project_name", "job_number", "client_name", "site_location", "dns_suffix", "ntp_server"):
        baseline_value = str(baseline_settings.get(field) or "").strip()
        current_value = str(current_settings.get(field) or "").strip()
        if baseline_value != current_value:
            changed.append({
                "field": field,
                "baseline": baseline_value,
                "current": current_value,
            })

    baseline_vlans = _normalize_vlan_rows(baseline_settings.get("vlans") or [])
    current_vlans = _normalize_vlan_rows(current_settings.get("vlans") or [])
    if baseline_vlans != current_vlans:
        changed.append({
            "field": "vlans",
            "baseline_count": len(baseline_vlans),
            "current_count": len(current_vlans),
        })

    baseline_snmp_present = bool(str(baseline_settings.get("snmp_community") or "").strip())
    current_snmp_present = bool(str(current_settings.get("snmp_community") or "").strip())
    if baseline_snmp_present != current_snmp_present:
        changed.append({
            "field": "snmp_community_present",
            "baseline": baseline_snmp_present,
            "current": current_snmp_present,
        })

    return {"changed": changed}


def _select_snapshot_artifact_file(files, candidates):
    for rel in candidates or []:
        if rel in files:
            return rel
    return ""


def _extract_topology_rows(payload):
    if isinstance(payload, dict):
        rows = payload.get("topology")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _extract_multicast_rows(payload):
    if isinstance(payload, dict):
        rows = payload.get("groups")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _multicast_row_key(row):
    row = row if isinstance(row, dict) else {}
    return "|".join([
        str(row.get("group_address") or "").strip(),
        str(row.get("switch_ip") or "").strip(),
        str(row.get("switch_hostname") or "").strip().lower(),
        str(row.get("vlan") or "").strip(),
    ])


def _normalize_multicast_row(row):
    row = row if isinstance(row, dict) else {}
    members = []
    for member in row.get("members") or []:
        if not isinstance(member, dict):
            continue
        members.append({
            "member_ip": str(member.get("member_ip") or "").strip(),
            "member_mac": _normalize_mac_value(member.get("member_mac")),
            "member_hostname": str(member.get("member_hostname") or "").strip(),
        })
    members.sort(key=lambda item: (item.get("member_ip") or "", item.get("member_mac") or "", item.get("member_hostname") or ""))
    return {
        "group_address": str(row.get("group_address") or "").strip(),
        "switch_ip": str(row.get("switch_ip") or "").strip(),
        "switch_hostname": str(row.get("switch_hostname") or "").strip(),
        "vlan": str(row.get("vlan") or "").strip(),
        "member_count": int(row.get("member_count") or len(members)),
        "notes": str(row.get("notes") or "").strip(),
        "members": members,
    }


def _snapshot_payload_changed(left, right):
    return _normalize_compare_value(left) != _normalize_compare_value(right)


def _compare_snapshot_artifacts(baseline_files, current_files):
    required = set(PROJECT_STATE_REQUIRED_FILES)
    baseline_artifact_files = sorted([name for name in baseline_files.keys() if name not in required])
    current_artifact_files = sorted([name for name in current_files.keys() if name not in required])
    artifacts = {
        "added_files": sorted(set(current_artifact_files) - set(baseline_artifact_files)),
        "removed_files": sorted(set(baseline_artifact_files) - set(current_artifact_files)),
        "common_files": sorted(set(baseline_artifact_files) & set(current_artifact_files)),
    }

    topology = {"changed": []}
    baseline_topology_file = _select_snapshot_artifact_file(baseline_files, SNAPSHOT_COMPARE_ARTIFACT_PATHS["topology"])
    current_topology_file = _select_snapshot_artifact_file(current_files, SNAPSHOT_COMPARE_ARTIFACT_PATHS["topology"])
    if baseline_topology_file and current_topology_file:
        baseline_rows = _extract_topology_rows(baseline_files.get(baseline_topology_file))
        current_rows = _extract_topology_rows(current_files.get(current_topology_file))
        if _snapshot_payload_changed(baseline_rows, current_rows):
            topology["changed"].append({
                "field": "rows",
                "baseline_count": len(baseline_rows),
                "current_count": len(current_rows),
            })

    multicast = {"added": [], "removed": [], "changed": []}
    baseline_multicast_file = _select_snapshot_artifact_file(baseline_files, SNAPSHOT_COMPARE_ARTIFACT_PATHS["multicast_groups"])
    current_multicast_file = _select_snapshot_artifact_file(current_files, SNAPSHOT_COMPARE_ARTIFACT_PATHS["multicast_groups"])
    if baseline_multicast_file and current_multicast_file:
        baseline_rows = _extract_multicast_rows(baseline_files.get(baseline_multicast_file))
        current_rows = _extract_multicast_rows(current_files.get(current_multicast_file))
        baseline_map = {}
        current_map = {}
        for row in baseline_rows:
            key = _multicast_row_key(row)
            if key:
                baseline_map[key] = _normalize_multicast_row(row)
        for row in current_rows:
            key = _multicast_row_key(row)
            if key:
                current_map[key] = _normalize_multicast_row(row)

        for key in sorted(set(current_map.keys()) - set(baseline_map.keys())):
            multicast["added"].append(current_map[key])
        for key in sorted(set(baseline_map.keys()) - set(current_map.keys())):
            multicast["removed"].append(baseline_map[key])
        for key in sorted(set(baseline_map.keys()) & set(current_map.keys())):
            left = baseline_map[key]
            right = current_map[key]
            if left != right:
                field_changes = []
                for field in ("member_count", "notes", "members"):
                    if _normalize_compare_value(left.get(field)) != _normalize_compare_value(right.get(field)):
                        field_changes.append({
                            "field": field,
                            "baseline": left.get(field),
                            "current": right.get(field),
                        })
                multicast["changed"].append({
                    "group_address": right.get("group_address") or left.get("group_address") or "",
                    "switch_ip": right.get("switch_ip") or left.get("switch_ip") or "",
                    "fields": field_changes,
                })

    baseline_recommendations_file = _select_snapshot_artifact_file(
        baseline_files, SNAPSHOT_COMPARE_ARTIFACT_PATHS["recommendations"]
    )
    current_recommendations_file = _select_snapshot_artifact_file(
        current_files, SNAPSHOT_COMPARE_ARTIFACT_PATHS["recommendations"]
    )
    recommendations_changed = 0
    if baseline_recommendations_file and current_recommendations_file:
        if _snapshot_payload_changed(
            baseline_files.get(baseline_recommendations_file),
            current_files.get(current_recommendations_file),
        ):
            recommendations_changed = 1

    return {
        "artifacts": artifacts,
        "topology": topology,
        "multicast_groups": multicast,
        "recommendations_changed": recommendations_changed,
    }

@app.route('/tools/')
@app.route('/tools')
def index():
    return redirect('/tools/diagnostics')


@app.route('/tools/diagnostics')
def diagnostics():
    return render_template('diagnostics.html', s=load_settings())


@app.route('/tools/dashboard')
def dashboard():
    return render_template('dashboard.html', s=load_settings())


@app.route('/tools/devices')
def devices():
    return render_template('devices.html', s=load_settings(), devices=_devices_with_freshness_view(load_devices()))

@app.route('/tools/intake')
def intake():
    return render_template('intake.html', s=load_settings())

@app.route('/tools/requirements')
def requirements():
    return render_template('requirements.html', s=load_settings())

@app.route('/tools/validation')
def validation():
    return render_template('validation.html', s=load_settings())

@app.route('/tools/firewall')
def firewall():
    return render_template('firewall.html', s=load_settings())

@app.route('/tools/recommendations')
def recommendations():
    return render_template('recommendations.html', s=load_settings())

@app.route('/tools/ipschedule')
def ipschedule():
    return render_template('ipschedule.html', s=load_settings())


@app.route('/tools/settings', methods=['GET', 'POST'])
def settings():
    s = load_settings()
    saved = False

    if request.method == 'POST':
        s['project_name']  = request.form.get('project_name', '')
        s['job_number']    = request.form.get('job_number', '')
        s['client_name']   = request.form.get('client_name', '')
        s['site_location'] = request.form.get('site_location', '')
        s['dns_suffix']    = request.form.get('dns_suffix', '.av')
        s['ntp_server']    = request.form.get('ntp_server', '')

        vlans = []
        names  = request.form.getlist('vlan_name[]')
        tags   = request.form.getlist('vlan_tag[]')
        subs   = request.form.getlist('vlan_subnet[]')
        gws    = request.form.getlist('vlan_gateway[]')
        starts = request.form.getlist('vlan_dhcp_start[]')
        ends   = request.form.getlist('vlan_dhcp_end[]')
        notes  = request.form.getlist('vlan_notes[]')

        existing_vlans = s.get("vlans") if isinstance(s.get("vlans"), list) else []
        for i in range(len(names)):
            dt_raw = request.form.get(f'device_types_{i}[]', '')
            dt = [x.strip() for x in dt_raw.split(',') if x.strip()]
            existing_vlan = existing_vlans[i] if i < len(existing_vlans) and isinstance(existing_vlans[i], dict) else {}
            vlan_row = dict(existing_vlan)  # preserve unknown/custom VLAN keys
            vlan_row.update({
                'id': i + 1,
                'name': names[i],
                'vlan_id': tags[i],
                'subnet': subs[i],
                'dhcp_range_start': starts[i],
                'dhcp_range_end': ends[i],
                'gateway': gws[i],
                'device_types': dt,
                'notes': notes[i]
            })
            vlans.append(vlan_row)

        s['vlans'] = vlans
        save_settings(s)
        saved = True

        if request.accept_mimetypes.best == 'application/json':
            return jsonify({
                "success": True,
                "saved_to": _settings_file(),
                "timestamp": utc_now_iso(),
            })

    return render_template('settings.html', s=s, saved=saved)


@app.route('/tools/scanner')
def scanner():
    return render_template('scanner.html', s=load_settings())


@app.route('/tools/dns')
def dns():
    s = load_settings()
    try:
        raw = subprocess.check_output(
            ['sudo', 'sqlite3', '/etc/pihole/gravity.db',
             "SELECT domain,ip FROM local_dns_records;"],
            timeout=10
        ).decode()
        records = [
            {'domain': l.split('|')[0], 'ip': l.split('|')[1]}
            for l in raw.strip().splitlines() if '|' in l
        ]
    except Exception:
        records = []

    return render_template('dns.html', s=s, records=records)


@app.route('/tools/network')
def network():
    return render_template('tools.html', s=load_settings())


@app.route('/tools/dhcp')
def dhcp():
    s = load_settings()
    leases = []

    try:
        lease_file = find_dhcp_lease_file()
        if not lease_file:
            raise Exception("No DHCP lease file found")

        raw = subprocess.check_output(['cat', lease_file], timeout=5).decode()
        for line in raw.strip().splitlines():
            p = line.split()
            if len(p) >= 4:
                leases.append({
                    'expires': p[0],
                    'mac': p[1],
                    'ip': p[2],
                    'hostname': p[3]
                })
    except Exception:
        leases = []

    return render_template('dhcp.html', s=s, leases=leases)


@app.route('/tools/ntp')
def ntp():
    s = load_settings()
    try:
        status = subprocess.check_output(['timedatectl', 'show-timesync'], timeout=10).decode()
    except Exception:
        status = 'Unable to get NTP status'
    return render_template('ntp.html', s=s, status=status)


# â”€â”€ API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€



# --- Validation API (NetPi V3) ---
# =========================
# NetPi V5 â€” Auto Typing Helpers
# =========================

def normalize_platform_name(value):
    if not value:
        return ""
    s = str(value).strip().lower()

    aliases = {
        "q-sys": "qsys",
        "q sys": "qsys",
        "qsc": "qsys",
        "tesira": "biamp",
        "video-wall-splicer": "video-wall-processor",
    }
    return aliases.get(s, s)


def weak_device_type(device_type):
    s = (device_type or "").strip().lower()
    return s in (
        "", "generic", "unknown", "device", "other",
        "web-device", "linux-web-device", "network-device",
        "ssh-device", "telnet-device", "snmp-device",
        "rtsp-device", "windows-host", "mqtt-device",
    )


def _suggestion_score_label(score):
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    if score >= 35:
        return "low"
    return "none"


def _suggestion_port_set(validation):
    ports = set()
    for port in (validation.get("open_ports") or []):
        if str(port).isdigit():
            ports.add(int(port))
    evidence = validation.get("evidence") if isinstance(validation.get("evidence"), dict) else {}
    for port in (evidence.get("open_ports") or []):
        if str(port).isdigit():
            ports.add(int(port))
    return ports


def _suggestion_text_blob(device, validation, evidence_record=None):
    http = validation.get("http") if isinstance(validation.get("http"), dict) else {}
    title_text = " ".join(str(v.get("title", "")) for v in http.values()).lower()
    server_text = " ".join(str(v.get("server", "")) for v in http.values()).lower()
    keyword_text = " ".join(
        " ".join(str(keyword or "") for keyword in (value.get("keywords") or []))
        for value in http.values()
    ).lower()
    evidence = validation.get("evidence") if isinstance(validation.get("evidence"), dict) else {}
    http_summary = evidence.get("http") if isinstance(evidence.get("http"), dict) else {}
    ssh_summary = evidence.get("ssh") if isinstance(evidence.get("ssh"), dict) else {}
    latest = (evidence_record or {}).get("latest") if isinstance((evidence_record or {}).get("latest"), dict) else {}
    history = (evidence_record or {}).get("history") if isinstance((evidence_record or {}).get("history"), dict) else {}
    raw_parts = [
        device.get("name"),
        device.get("hostname"),
        device.get("vendor"),
        device.get("notes"),
        device.get("type"),
        title_text,
        server_text,
        keyword_text,
        http_summary.get("title"),
        http_summary.get("server"),
        " ".join(str(item or "") for item in (http_summary.get("keywords") or [])),
        ssh_summary.get("banner"),
        latest.get("stable_hostname"),
        latest.get("http_title"),
        latest.get("http_server"),
        " ".join(str(item or "") for item in (latest.get("http_keywords") or [])),
        latest.get("ssh_banner"),
        " ".join(str(item or "") for item in (history.get("hostnames") or [])),
        " ".join(str(item or "") for item in (history.get("http_titles") or [])),
        " ".join(str(item or "") for item in (history.get("http_servers") or [])),
        " ".join(str(item or "") for item in (history.get("http_keywords") or [])),
        " ".join(str(item or "") for item in (history.get("ssh_banners") or [])),
    ]
    return " ".join(str(part or "") for part in raw_parts).lower()


def _candidate_family(type_name):
    normalized = (type_name or "").strip().lower()
    if normalized.startswith("qsys-nv"):
        return "qsys-nv"
    if normalized.startswith("qsys"):
        return "qsys"
    if normalized.startswith("crestron"):
        return "crestron"
    if normalized in ("biamp", "tesira", "biamp-tesira"):
        return "biamp"
    if normalized.startswith("barco"):
        return "barco"
    if normalized.startswith("video-wall"):
        return "video-wall"
    return normalized


def _type_specificity(type_name):
    normalized = (type_name or "").strip().lower()
    if normalized in ("", "generic", "unknown", "web-device", "linux-web-device"):
        return 0
    if normalized in ("qsys", "crestron", "biamp", "barco-device", "video-wall-processor"):
        return 1
    if normalized in ("qsys-core", "qsys-touchpanel", "qsys-nv", "crestron_control", "crestron_touchpanel", "crestron_uc", "biamp-tesira"):
        return 2
    if normalized in ("qsys-nv21", "qsys-nv32"):
        return 3
    return 1


def _add_type_candidate(candidates, candidate_type, points, reason):
    candidate_type = normalize_platform_name(candidate_type)
    if not candidate_type or candidate_type in ("unknown", "generic", "web-device", "linux-web-device"):
        return

    entry = candidates.setdefault(candidate_type, {"score": 0, "reasons": []})
    entry["score"] += int(points)
    if reason and reason not in entry["reasons"]:
        entry["reasons"].append(reason)


def _suggestion_candidate_type(candidate_type):
    candidate_type = normalize_platform_name(candidate_type)
    if candidate_type == "barco":
        return "barco-device"
    return candidate_type


def _ranked_type_candidates(candidates):
    return sorted(
        (
            {
                "type": candidate_type,
                "score": min(int(data.get("score", 0) or 0), 100),
                "reasons": list(data.get("reasons") or []),
            }
            for candidate_type, data in (candidates or {}).items()
        ),
        key=lambda item: (item["score"], len(item["reasons"])),
        reverse=True,
    )


def _contains_any_token(text, tokens):
    return any(token in (text or "") for token in (tokens or []))


def _is_video_processing_match(text):
    text = (text or "").lower()
    return (
        "video wall splicer" in text or
        "video processor" in text or
        "wall processor" in text or
        "led controller" in text or
        "wall controller" in text or
        ("video wall" in text and _contains_any_token(text, ("splicer", "processor", "controller", "led")))
    )


def _add_grouped_av_candidates(candidates, text, stable_hostname, hostname_text, ports, fingerprint_platform):
    qsys_tokens = ("q-sys", "qsys", "qsc")
    qsys_touch_tokens = ("tsc-", "touchscreen controller", "qsys touch", "q-sys touch")
    qsys_nv21_tokens = ("nv-21", "nv21")
    qsys_nv32_tokens = ("nv-32", "nv32", "nv-32-h", "nv32-h")
    crestron_control_tokens = ("cp4", "mc4", "rmc4", "pro4")
    crestron_touch_tokens = ("tsw", "tss", "touchpanel", "touch panel")
    crestron_uc_tokens = ("uc-", "flex", "teams")

    qsys_context = 1710 in ports or _contains_any_token(text, qsys_tokens)
    if qsys_context:
        if 1710 in ports:
            _add_type_candidate(candidates, "qsys-core", 34, "Observed Q-SYS control port 1710")
            _add_type_candidate(candidates, "qsys", 20, "Observed Q-SYS control port 1710")
        if _contains_any_token(text, qsys_tokens):
            _add_type_candidate(candidates, "qsys", 16, "Hostname or HTTP evidence referenced Q-SYS")
        if "core" in text:
            _add_type_candidate(candidates, "qsys-core", 20, "Hostname or HTTP evidence matched Q-SYS Core naming")
            if fingerprint_platform == "qsys" or 1710 in ports:
                _add_type_candidate(candidates, "qsys-core", 30, "Q-SYS Core naming was reinforced by control-port or fingerprint evidence")
        if _contains_any_token(text, qsys_touch_tokens):
            _add_type_candidate(candidates, "qsys-touchpanel", 28, "Hostname or HTTP evidence matched Q-SYS touchpanel naming")
        if _contains_any_token(text, qsys_nv21_tokens):
            _add_type_candidate(candidates, "qsys-nv21", 42, "Hostname or HTTP evidence matched Q-SYS NV-21 naming")
            _add_type_candidate(candidates, "qsys-nv", 28, "Hostname or HTTP evidence matched Q-SYS NV endpoint naming")
            _add_type_candidate(candidates, "qsys", 10, "Hostname or HTTP evidence matched Q-SYS NV endpoint naming")
            if fingerprint_platform == "qsys":
                _add_type_candidate(candidates, "qsys-nv21", 20, "Q-SYS NV-21 naming was reinforced by fingerprint evidence")
        if _contains_any_token(text, qsys_nv32_tokens):
            _add_type_candidate(candidates, "qsys-nv32", 42, "Hostname or HTTP evidence matched Q-SYS NV-32 naming")
            _add_type_candidate(candidates, "qsys-nv", 28, "Hostname or HTTP evidence matched Q-SYS NV endpoint naming")
            _add_type_candidate(candidates, "qsys", 10, "Hostname or HTTP evidence matched Q-SYS NV endpoint naming")
            if fingerprint_platform == "qsys":
                _add_type_candidate(candidates, "qsys-nv32", 20, "Q-SYS NV-32 naming was reinforced by fingerprint evidence")

    crestron_context = any(port in ports for port in (41794, 41795, 41796)) or "crestron" in text
    if crestron_context:
        if any(port in ports for port in (41794, 41795, 41796)):
            _add_type_candidate(candidates, "crestron", 24, "Observed Crestron-like control ports 41794/41795/41796")
        if "crestron" in text:
            _add_type_candidate(candidates, "crestron", 16, "Hostname or HTTP evidence referenced Crestron")
        if _contains_any_token(text, crestron_control_tokens):
            _add_type_candidate(candidates, "crestron_control", 34, "Hostname pattern matched Crestron control processor naming")
            if fingerprint_platform == "crestron" or any(port in ports for port in (41794, 41795, 41796)):
                _add_type_candidate(candidates, "crestron_control", 32, "Crestron control naming was reinforced by live protocol evidence")
        if _contains_any_token(text, crestron_touch_tokens):
            _add_type_candidate(candidates, "crestron_touchpanel", 30, "Hostname or HTTP evidence matched Crestron touchpanel naming")
        if _contains_any_token(text, crestron_uc_tokens):
            _add_type_candidate(candidates, "crestron_uc", 26, "Hostname or HTTP evidence matched Crestron UC naming")

    if _contains_any_token(text, ("biamp", "tesira")):
        _add_type_candidate(candidates, "biamp", 26, "Hostname or HTTP evidence referenced Biamp/Tesira")
    if stable_hostname.startswith("biamp-"):
        _add_type_candidate(candidates, "biamp-tesira", 44, "Hostname starts with BIAMP-")
    elif _contains_any_token(stable_hostname, ("biamp", "tesira")):
        _add_type_candidate(candidates, "biamp-tesira", 36, "Hostname contains Biamp/Tesira marker")
    elif "biamp-" in hostname_text:
        _add_type_candidate(candidates, "biamp-tesira", 40, "Hostname starts with BIAMP-")
    elif _contains_any_token(hostname_text, ("biamp", "tesira")):
        _add_type_candidate(candidates, "biamp-tesira", 34, "Hostname contains Biamp/Tesira marker")
    if _contains_any_token(text, ("biamp", "tesira")):
        _add_type_candidate(candidates, "biamp-tesira", 24, "HTTP title/body evidence referenced Biamp/Tesira")
    if (stable_hostname.startswith("biamp-") or "biamp-" in hostname_text) and _contains_any_token(text, ("biamp", "tesira")):
        _add_type_candidate(candidates, "biamp-tesira", 18, "BIAMP hostname was reinforced by Biamp/Tesira HTTP evidence")

    if _contains_any_token(text, ("barco", "clickshare", "barco ctrl")):
        _add_type_candidate(candidates, "barco-device", 24, "HTTP title/body evidence referenced Barco/ClickShare")
    if _contains_any_token(stable_hostname, ("barco", "ctrl")):
        _add_type_candidate(candidates, "barco-device", 16, "Hostname referenced Barco/CTRL")

    if _is_video_processing_match(text) and (8080 in ports or 22 in ports or 80 in ports or 443 in ports):
        _add_type_candidate(candidates, "video-wall-processor", 34, "HTTP title/body evidence matched video/wall/LED processing patterns")
        if 8080 in ports:
            _add_type_candidate(candidates, "video-wall-processor", 12, "Port 8080 reinforced video processing appliance pattern")
        if 22 in ports:
            _add_type_candidate(candidates, "video-wall-processor", 8, "SSH access reinforced video processing appliance pattern")


def _resolve_evidence_record(device, validation=None):
    validation = validation or {}
    observation = _build_device_observation(device, source="suggestion_lookup", result=validation, extra={})
    store = load_device_evidence()
    match = _find_evidence_record_match(store, observation)
    if not match:
        return None

    resolved = copy.deepcopy(match.get("record") or {})
    resolved["_match_kind"] = match.get("match_kind") or ""
    resolved["_match_key"] = match.get("key") or ""
    return resolved


def build_type_suggestion(device, validation=None):
    device = device or {}
    validation = validation or {}
    current_observation = _build_device_observation(device, source="suggestion_lookup", result=validation, extra={})
    current_type = (device.get("type") or validation.get("type") or "").strip().lower()
    fingerprint = validation.get("fingerprint") if isinstance(validation.get("fingerprint"), dict) else {}
    observed = validation.get("observed_platform") if isinstance(validation.get("observed_platform"), dict) else {}
    evidence_record = _resolve_evidence_record(device, validation)
    ports = _suggestion_port_set(validation)
    text = _suggestion_text_blob(device, validation, evidence_record=evidence_record)
    vendor_guess = guess_type_from_vendor(device.get("vendor", ""))
    evidence_match_kind = ((evidence_record or {}).get("_match_kind") or "").strip().lower()
    evidence_match_weight = _identity_match_weight(evidence_match_kind)
    current_mac = _normalize_identity_mac(current_observation.get("mac"))
    current_stable_hostname = _normalize_identity_hostname(current_observation.get("stable_hostname"))
    current_ip = (current_observation.get("ip") or "").strip()
    record_identity = (evidence_record or {}).get("identity") if isinstance((evidence_record or {}).get("identity"), dict) else {}
    record_ip = (record_identity.get("ip") or ((evidence_record or {}).get("latest") or {}).get("ip") or "").strip()
    allow_learned = False
    if evidence_match_kind == "mac" and current_mac:
        allow_learned = True
    elif evidence_match_kind == "hostname" and current_stable_hostname:
        allow_learned = True
    elif evidence_match_kind == "ip" and current_ip and not current_mac and not current_stable_hostname and current_ip == record_ip:
        allow_learned = True
    stable_hostname = _normalize_identity_hostname(
        device.get("hostname") or
        ((evidence_record or {}).get("latest") or {}).get("stable_hostname") or
        ""
    ).lower()
    hostname_text = " ".join(
        str(part or "")
        for part in (
            device.get("hostname"),
            device.get("name"),
            ((evidence_record or {}).get("latest") or {}).get("hostname"),
            ((evidence_record or {}).get("latest") or {}).get("stable_hostname"),
        )
    ).lower()

    candidates = {}

    fingerprint_platform = normalize_platform_name(fingerprint.get("platform"))
    fingerprint_confidence = (fingerprint.get("confidence") or "").strip().lower()
    if fingerprint_platform and fingerprint_platform != "unknown":
        fingerprint_candidate = _suggestion_candidate_type(fingerprint_platform)
        _add_type_candidate(
            candidates,
            fingerprint_candidate,
            {"high": 58, "medium": 42, "low": 18}.get(fingerprint_confidence, 0),
            f"Validation fingerprint suggested {fingerprint_candidate} ({fingerprint_confidence or 'unknown'} confidence)",
        )

    observed_platform = normalize_platform_name(observed.get("platform"))
    observed_confidence = (observed.get("confidence") or "").strip().lower()
    if observed_platform and observed_platform != "unknown":
        observed_candidate = _suggestion_candidate_type(observed_platform)
        _add_type_candidate(
            candidates,
            observed_candidate,
            {"high": 34, "medium": 24, "low": 10}.get(observed_confidence, 0),
            f"Observed platform suggested {observed_candidate} ({observed_confidence or 'unknown'} confidence)",
        )

    if vendor_guess and not weak_device_type(vendor_guess):
        _add_type_candidate(candidates, vendor_guess, 14, f"Vendor/OUI matched {vendor_guess}")

    _add_grouped_av_candidates(candidates, text, stable_hostname, hostname_text, ports, fingerprint_platform)

    direct_ranked = _ranked_type_candidates(candidates)
    direct_best = direct_ranked[0] if direct_ranked else {}
    direct_best_type = direct_best.get("type", "")
    direct_best_score = int(direct_best.get("score", 0) or 0)

    if allow_learned:
        learned = evidence_record.get("learned") if isinstance(evidence_record, dict) else {}
        fingerprint_library = learned.get("fingerprint_library") if isinstance(learned.get("fingerprint_library"), dict) else {}
        learned_type = normalize_platform_name((learned or {}).get("suggested_type"))
        learned_confidence = ((learned or {}).get("confidence") or "").strip().lower()
        learned_count = int((learned or {}).get("observation_count", 0) or 0)
        if learned_type and learned_type not in ("unknown", "generic", "web-device", "linux-web-device"):
            learned_candidate = _suggestion_candidate_type(learned_type)
            conflicts_with_direct = (
                direct_best_type and
                direct_best_score >= 35 and
                _candidate_family(learned_candidate) != _candidate_family(direct_best_type)
            )
            if not conflicts_with_direct or evidence_match_kind == "mac":
                learned_points = {"high": 26, "medium": 18, "low": 10}.get(learned_confidence, 0)
                learned_points += min(max(learned_count - 1, 0) * 4, 16)
                learned_points = int(round(learned_points * evidence_match_weight))
                if learned_points > 0:
                    _add_type_candidate(
                        candidates,
                        learned_candidate,
                        learned_points,
                        f"Repeated learned evidence previously suggested {learned_candidate} across {learned_count or 1} observation(s)",
                    )

        library_type = normalize_platform_name((fingerprint_library or {}).get("suggested_type"))
        library_confidence = ((fingerprint_library or {}).get("confidence") or "").strip().lower()
        library_count = int((fingerprint_library or {}).get("observation_count", 0) or 0)
        if library_type and library_type not in ("unknown", "generic", "web-device", "linux-web-device"):
            library_candidate = _suggestion_candidate_type(library_type)
            conflicts_with_direct = (
                direct_best_type and
                direct_best_score >= 35 and
                _candidate_family(library_candidate) != _candidate_family(direct_best_type)
            )
            if not conflicts_with_direct or evidence_match_kind == "mac":
                library_points = {"high": 30, "medium": 22, "low": 0}.get(library_confidence, 0)
                library_points += min(max(library_count - 2, 0) * 5, 15)
                library_points = int(round(library_points * evidence_match_weight))
                if library_points > 0:
                    _add_type_candidate(
                        candidates,
                        library_candidate,
                        library_points,
                        f"Self-learning fingerprint library reinforced {library_candidate} from {library_count or 1} repeated strong observation(s)",
                    )

        guessed_types = ((evidence_record or {}).get("history") or {}).get("guessed_types") or {}
        for candidate_type, data in guessed_types.items():
            if not isinstance(data, dict):
                continue
            guess_count = int(data.get("count", 0) or 0)
            if guess_count >= 2:
                guessed_candidate = _suggestion_candidate_type(candidate_type)
                conflicts_with_direct = (
                    direct_best_type and
                    direct_best_score >= 35 and
                    _candidate_family(guessed_candidate) != _candidate_family(direct_best_type)
                )
                if conflicts_with_direct and evidence_match_kind != "mac":
                    continue
                guessed_points = int(round(min(guess_count * 4, 12) * evidence_match_weight))
                if guessed_points > 0:
                    _add_type_candidate(
                        candidates,
                        guessed_candidate,
                        guessed_points,
                        f"Repeated guessed type {guessed_candidate} seen across {guess_count} observations",
                    )

        signal_candidates = ((evidence_record or {}).get("history") or {}).get("signal_candidates") or {}
        dominant_signal = None
        dominant_count = 0
        conflicting_count = 0
        for candidate_type, data in signal_candidates.items():
            if not isinstance(data, dict):
                continue
            count = int(data.get("count", 0) or 0)
            if count > dominant_count:
                conflicting_count = dominant_count
                dominant_signal = candidate_type
                dominant_count = count
            elif count > conflicting_count:
                conflicting_count = count
        if dominant_signal and dominant_count >= 2 and dominant_count > conflicting_count:
            conflicts_with_direct = (
                direct_best_type and
                direct_best_score >= 35 and
                _candidate_family(dominant_signal) != _candidate_family(direct_best_type)
            )
            if not conflicts_with_direct or evidence_match_kind == "mac":
                signal_points = int(round(min(12 + ((dominant_count - 2) * 4), 20) * evidence_match_weight))
                if signal_points > 0:
                    _add_type_candidate(
                        candidates,
                        dominant_signal,
                        signal_points,
                        f"Repeated stored evidence pointed to {dominant_signal} across {dominant_count} observations",
                    )

    if 22 in ports and 80 in ports and 443 in ports:
        for candidate_type in list(candidates.keys()):
            if _candidate_family(candidate_type) in ("qsys", "crestron", "biamp", "barco"):
                _add_type_candidate(candidates, candidate_type, 6, "Port pattern 22/80/443 reinforced existing AV control evidence")

    if not candidates:
        return {
            "suggested_type": "",
            "confidence_score": 0,
            "confidence_label": "none",
            "suggestion_reasons": [],
            "advisory_only": True,
            "basis": "no_match",
        }

    ranked = _ranked_type_candidates(candidates)

    best = ranked[0]
    for candidate in ranked[1:]:
        if _candidate_family(candidate.get("type")) != _candidate_family(best.get("type")):
            continue
        if _type_specificity(candidate.get("type")) <= _type_specificity(best.get("type")):
            continue
        if int(candidate.get("score", 0)) + 18 < int(best.get("score", 0)):
            continue
        best = candidate
        break

    suggested_type = best["type"]
    confidence_score = best["score"]
    confidence_label = _suggestion_score_label(confidence_score)
    advisory_only = False

    if not weak_device_type(current_type):
        if current_type == suggested_type:
            suggested_type = ""
            advisory_only = True
        elif _candidate_family(current_type) == _candidate_family(best["type"]) and _type_specificity(current_type) >= _type_specificity(best["type"]):
            suggested_type = ""
            advisory_only = True
        elif _candidate_family(current_type) == _candidate_family(best["type"]) and confidence_score < 85:
            suggested_type = ""
            advisory_only = True
        elif confidence_score < 90:
            suggested_type = ""
            advisory_only = True
    elif weak_device_type(best["type"]) or confidence_score < 35:
        suggested_type = ""
        advisory_only = True

    return {
        "suggested_type": suggested_type,
        "confidence_score": confidence_score,
        "confidence_label": confidence_label,
        "suggestion_reasons": best["reasons"][:4],
        "advisory_only": advisory_only,
        "basis": best["type"],
        "current_type": current_type,
        "evidence_key": ((evidence_record or {}).get("identity") or {}).get("key", ""),
    }


def classify_platform_to_type(platform):
    p = normalize_platform_name(platform)

    if p == "qsys":
        return ("qsys", 0.98, "platform:qsys")

    if p == "biamp":
        return ("biamp", 0.98, "platform:biamp")

    if p == "crestron":
        return ("crestron", 0.95, "platform:crestron")

    if p == "shure":
        return ("shure", 0.92, "platform:shure")

    if p in ("artnet", "sacn", "lighting"):
        return ("lighting", 0.90, f"platform:{p}")

    if p == "dante":
        return ("dante", 0.75, "platform:dante")

    return (None, 0.0, "no_match")


def platform_confidence_multiplier(platform, confidence):
    p = normalize_platform_name(platform)
    c = (confidence or "").strip().lower()

    if p == "qsys":
        return {
            "high": 1.0,
            "medium": 0.82,
            "low": 0.35,
        }.get(c, 0.0)

    return {
        "high": 1.0,
        "medium": 0.92,
        "low": 0.5,
    }.get(c, 0.0)


def decide_auto_promoted_type(device, validation):
    current_type = (device.get("type") or "").strip().lower()

    observed_data = validation.get("observed_platform") or {}
    fingerprint_data = validation.get("fingerprint") or {}

    observed = (observed_data.get("platform") or "")
    fingerprint = (fingerprint_data.get("platform") or "")
    observed_confidence = platform_confidence_multiplier(observed, observed_data.get("confidence"))
    fingerprint_confidence = platform_confidence_multiplier(fingerprint, fingerprint_data.get("confidence"))

    primary_type, primary_conf, primary_reason = classify_platform_to_type(observed)
    secondary_type, secondary_conf, secondary_reason = classify_platform_to_type(fingerprint)

    primary_conf *= observed_confidence
    secondary_conf *= fingerprint_confidence

    if primary_conf >= secondary_conf:
        chosen_type, conf, reason, source = primary_type, primary_conf, primary_reason, "observed_platform"
    else:
        chosen_type, conf, reason, source = secondary_type, secondary_conf, secondary_reason, "fingerprint"

    if not chosen_type:
        return {
            "should_apply": False,
            "proposed_type": None,
            "confidence": 0.0,
            "reason": "no_match",
            "source": None
        }

    if weak_device_type(current_type) and conf >= 0.88:
        return {
            "should_apply": True,
            "proposed_type": chosen_type,
            "confidence": conf,
            "reason": reason,
            "source": source
        }

    if current_type != chosen_type and conf >= 0.96:
        return {
            "should_apply": True,
            "proposed_type": chosen_type,
            "confidence": conf,
            "reason": reason,
            "source": source
        }

    return {
        "should_apply": False,
        "proposed_type": chosen_type,
        "confidence": conf,
        "reason": "suggest_only",
        "source": source
    }


def infer_av_role(device, validation):
    name = (device.get("name") or "").lower()
    vendor = (device.get("vendor") or "").lower()
    notes = (device.get("notes") or "").lower()
    current_type = (
        device.get("_resolved_type")
        or device.get("effective_type")
        or device.get("type")
        or ""
    ).lower()
    observed = ((validation.get("observed_platform") or {}).get("platform") or "").lower()
    observed_confidence = ((validation.get("observed_platform") or {}).get("confidence") or "").lower()
    fingerprint = ((validation.get("fingerprint") or {}).get("platform") or "").lower()
    fingerprint_confidence = ((validation.get("fingerprint") or {}).get("confidence") or "").lower()
    http = validation.get("http") or {}
    title_text = " ".join(str(v.get("title", "")) for v in http.values()).lower()
    open_ports = set(validation.get("open_ports") or [])

    text = f"{name} {vendor} {notes} {current_type} {observed} {fingerprint} {title_text}"

    def has_any_token(value, tokens):
        return any(token in value for token in tokens)

    qsys_role_types = {
        "qsys-core",
        "qsys-touchpanel",
        "qsys-nv-endpoint",
        "qsys-nv-decoder",
        "qsys-peripheral",
    }
    qsys_name_signal = has_any_token(name, ["qsys", "q-sys"])
    qsys_notes_signal = has_any_token(notes, ["qsys", "q-sys"])
    qsys_vendor_signal = has_any_token(vendor, ["qsys", "q-sys", "qsc"])
    qsys_title_signal = has_any_token(title_text, ["qsys", "q-sys"])
    qsys_control_signal = 1710 in open_ports
    qsys_platform_signal = (
        (fingerprint == "qsys" and fingerprint_confidence in ("medium", "high"))
        or (observed == "qsys" and observed_confidence in ("medium", "high"))
    )
    qsys_context_signal = (
        qsys_name_signal
        or qsys_notes_signal
        or qsys_vendor_signal
        or qsys_title_signal
        or qsys_control_signal
        or current_type in qsys_role_types
    )

    # Strong name/model fallback first
    if current_type == "qsys-nv-decoder":
        return "qsys-nv-decoder"
    if current_type == "qsys-nv-endpoint":
        return "qsys-nv-endpoint"
    if current_type == "qsys-core":
        return "qsys-core"
    if current_type == "qsys-touchpanel":
        return "qsys-touchpanel"
    if current_type == "qsys-peripheral":
        return "qsys-peripheral"

    # Q-SYS
    if qsys_context_signal and has_any_token(text, ["nv-32-h", "nv32-h", "nv-32", "nv32"]):
        return "qsys-nv-decoder"
    if qsys_context_signal and has_any_token(text, ["nv-21", "nv21"]):
        return "qsys-nv-endpoint"
    if qsys_context_signal and has_any_token(text, ["tsc", "qsys-tp", "qsys tp", "touch panel", "touchpanel"]):
        return "qsys-touchpanel"
    if qsys_context_signal and "qio" in text:
        return "qsys-peripheral"
    if (qsys_control_signal or qsys_vendor_signal or qsys_name_signal or qsys_notes_signal) and "core" in text:
        return "qsys-core"
    if qsys_control_signal:
        return "qsys"
    if qsys_vendor_signal:
        return "qsys"
    if qsys_platform_signal and (qsys_name_signal or qsys_notes_signal or current_type in qsys_role_types):
        return "qsys"
    if qsys_name_signal and (qsys_title_signal or current_type in qsys_role_types):
        return "qsys"

    # Q-SYS legacy fallback only with meaningful corroboration
    if "qsc" in text or "q-sys" in text or "qsys" in text:
        if (qsys_control_signal or qsys_vendor_signal or qsys_platform_signal) and "core" in text:
            return "qsys-core"

    # Crestron
    if "crestron" in text:
        if any(x in text for x in ["cp4", "mc4", "rmc4", "pro4", "control"]):
            return "crestron_control"
        if any(x in text for x in ["tsw", "tss", "touch panel", "touchpanel"]):
            return "crestron_touchpanel"
        if any(x in text for x in ["uc-", "flex", "teams"]):
            return "crestron_uc"
        return "crestron"

    # Biamp
    if "biamp" in text or "tesira" in text:
        return "biamp"

    return None

@app.route("/tools/api/validate_device", methods=["POST"])
def api_validate_device():
    try:
        devices = load_devices()
        payload = request.get_json(silent=True) or {}

        target_ip = (payload.get("ip") or "").strip()
        target_name = (payload.get("name") or "").strip()

        device = None

        if target_ip:
            device = next((d for d in devices if d.get("ip", "").strip() == target_ip), None)

        if device is None and target_name:
            device = next((d for d in devices if d.get("name", "").strip() == target_name), None)

        if device is None:
            return jsonify({
                "ok": False,
                "error": "Device not found",
            }), 404

        result = run_validation(device)
        device_changed = False

        if _validation_confirms_reachability(result):
            refreshed_device = _mark_device_freshness(device, seen=True, reachable=True)
            if refreshed_device != device:
                device.clear()
                device.update(refreshed_device)
                device_changed = True
            if _best_effort_snmp_enrich_device(device, result):
                device_changed = True

        # Passive MAC harvest (best-effort, non-blocking): ARP -> SNMP-context -> LLDP/CDP-context.
        passive_mac = ""
        passive_source = "unknown"
        try:
            passive_mac, passive_source = resolve_passive_mac(device, result)
        except Exception:
            passive_mac, passive_source = ("", "unknown")

        existing_mac = _normalize_mac_value(device.get("mac") or device.get("mac_address"))
        resolved_mac = _normalize_mac_value(passive_mac)
        canonical_passive_source = _canonicalize_mac_source(passive_source, has_mac=bool(resolved_mac))

        if resolved_mac:
            current_source = _canonicalize_mac_source(device.get("mac_source"), has_mac=bool(existing_mac))
            if existing_mac != resolved_mac or current_source != canonical_passive_source:
                device["mac"] = resolved_mac
                device["mac_address"] = resolved_mac
                device["mac_source"] = canonical_passive_source
                device_changed = True
            result["mac"] = resolved_mac
            result["mac_address"] = resolved_mac
            result["mac_source"] = canonical_passive_source
        elif not existing_mac:
            if device.get("mac_address", "__missing__") is not None or _canonicalize_mac_source(device.get("mac_source"), has_mac=False) != "unknown":
                device["mac_address"] = None
                device["mac_source"] = "unknown"
                device_changed = True
            result["mac"] = ""
            result["mac_address"] = None
            result["mac_source"] = "unknown"
        else:
            existing_source = _canonicalize_mac_source(device.get("mac_source"), has_mac=True)
            if existing_source != str(device.get("mac_source") or ""):
                device["mac_source"] = existing_source
                device_changed = True
            result["mac"] = existing_mac
            result["mac_address"] = existing_mac
            result["mac_source"] = existing_source

        if isinstance(result.get("evidence"), dict):
            result["evidence"]["mac"] = result.get("mac") or ""

        if device_changed:
            save_devices_file(devices)

        auto_type = decide_auto_promoted_type(device, result)
        result["auto_type"] = auto_type
        type_suggestion = build_type_suggestion(device, result)
        result["type_suggestion"] = type_suggestion
        result["suggested_type"] = type_suggestion.get("suggested_type") or ""
        result["effective_type"] = resolve_effective_type(device, auto_type.get("proposed_type") or "", type_suggestion, result)
        result["confidence_score"] = type_suggestion.get("confidence_score", 0)
        result["confidence_label"] = type_suggestion.get("confidence_label") or "none"
        result["suggestion_reasons"] = list(type_suggestion.get("suggestion_reasons") or [])

        role = infer_av_role(device, result)
        if role:
            result["av_role"] = role

        try:
            record_device_observation(
                device,
                source="validate_device",
                result=result,
                extra={
                    "guessed_type": auto_type.get("proposed_type") or "",
                    "inventory_type": device.get("type") or "",
                },
            )
        except Exception:
            pass


        return jsonify({
            "ok": True,
            "result": result,
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/validate_all", methods=["POST"])
def api_validate_all():
    try:
        payload = request.get_json(silent=True) or {}
        vlan = str(payload.get("vlan") or "").strip()

        inventory_devices = load_devices()
        devices = inventory_devices
        if vlan:
            devices = [device for device in devices if str(device.get("vlan") or "").strip() == vlan]
        results = run_validation_for_all(devices)
        fingerprint_updates = []
        devices_changed = False

        for device, result in zip(devices, results):
            if _validation_confirms_reachability(result):
                refreshed_device = _mark_device_freshness(device, seen=True, reachable=True)
                if refreshed_device != device:
                    device.clear()
                    device.update(refreshed_device)
                    devices_changed = True
                if _best_effort_snmp_enrich_device(device, result):
                    devices_changed = True
            auto_type = decide_auto_promoted_type(device, result)
            type_suggestion = build_type_suggestion(device, result)
            result["type_suggestion"] = type_suggestion
            result["suggested_type"] = type_suggestion.get("suggested_type") or ""
            result["effective_type"] = resolve_effective_type(device, auto_type.get("proposed_type") or "", type_suggestion, result)
            result["confidence_score"] = type_suggestion.get("confidence_score", 0)
            result["confidence_label"] = type_suggestion.get("confidence_label") or "none"
            result["suggestion_reasons"] = list(type_suggestion.get("suggestion_reasons") or [])
            role = infer_av_role(device, result)
            key = _stable_fingerprint_key(device, result)
            if key:
                fingerprint_updates.append({
                    "key": key,
                    "record": _build_fingerprint_entry(device, result, av_role=role),
                })
            try:
                record_device_observation(
                    device,
                    source="validate_all",
                    result=result,
                    extra={
                        "guessed_type": auto_type.get("proposed_type") or "",
                        "inventory_type": device.get("type") or "",
                    },
                )
            except Exception:
                pass

        if fingerprint_updates:
            try:
                update_fingerprint_store(fingerprint_updates)
            except Exception:
                pass

        if devices_changed:
            save_devices_file(inventory_devices)

        detected = {
            "systems": [],
            "mode": "",
            "edge_count": 0,
        }

        return jsonify({
            "ok": True,
            "count": len(results),
            "results": results,
            "detected_systems": detected,
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/generate_requirements", methods=["POST"])
def api_generate_requirements():
    try:
        payload = request.get_json(silent=True) or {}
        vlan = str(payload.get("vlan") or "").strip()
        devices = payload.get("devices")
        explicit_devices = isinstance(devices, list) and bool(devices)

        if not explicit_devices:
            devices = load_devices()

        if vlan:
            devices = [d for d in devices if str(d.get("vlan") or "").strip() == vlan]

        config = load_requirements_config()
        enriched_devices = [enrich_device_runtime(device) for device in devices]

        results = []
        unmapped = []
        mapped_count = 0
        types_seen = set()

        for device in enriched_devices:
            requirement_row = generate_device_requirements(device, config)
            results.append(requirement_row)

            effective_type = str(requirement_row.get("effective_type") or "").strip().lower()
            if effective_type:
                types_seen.add(effective_type)

            if requirement_row.get("required_ports"):
                mapped_count += 1
            else:
                unmapped.append({
                    "device_id": requirement_row.get("device_id") or "",
                    "type": effective_type or "unknown",
                })

        summary = {
            "mapped": mapped_count,
            "unmapped": len(unmapped),
            "types_seen": len(types_seen),
        }

        return jsonify({
            "ok": True,
            "count": len(results),
            "summary": summary,
            "results": results,
            "unmapped": unmapped,
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/apply_suggestions", methods=["POST"])
def api_apply_suggestions():
    try:
        devices = load_devices()
        if not devices:
            return jsonify({
                "ok": True,
                "devices_updated": 0,
                "updated_devices": [],
                "skipped_devices": [],
            })

        validation_results = run_validation_for_all(devices)
        updated_devices = []
        skipped_devices = []
        devices_changed = False

        for device, result in zip(devices, validation_results):
            type_suggestion = build_type_suggestion(device, result)
            promotion = evaluate_safe_type_promotion(device, type_suggestion)

            if promotion.get("should_apply"):
                original_type = (device.get("type") or "").strip()
                new_type = promotion.get("suggested_type") or ""
                device["type"] = new_type
                devices_changed = True
                updated_devices.append({
                    "name": (device.get("name") or "").strip(),
                    "ip": (device.get("ip") or "").strip(),
                    "original_type": original_type,
                    "new_type": new_type,
                    "confidence_score": promotion.get("confidence_score", 0),
                    "reason": promotion.get("reason") or "",
                    "suggestion_reasons": list(promotion.get("suggestion_reasons") or []),
                })
            else:
                skipped_devices.append({
                    "name": (device.get("name") or "").strip(),
                    "ip": (device.get("ip") or "").strip(),
                    "current_type": promotion.get("current_type") or "",
                    "suggested_type": promotion.get("suggested_type") or "",
                    "confidence_score": promotion.get("confidence_score", 0),
                    "reason": promotion.get("reason") or "Promotion skipped",
                    "suggestion_reasons": list(promotion.get("suggestion_reasons") or []),
                })

        if devices_changed:
            save_devices_file(devices)

        return jsonify({
            "ok": True,
            "devices_updated": len(updated_devices),
            "updated_devices": updated_devices,
            "skipped_devices": skipped_devices,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500

@app.route('/tools/api/project-name')
def api_project_name():
    s = load_settings()
    name = s.get('project_name', '')
    if s.get('job_number'):
        name += ' â€” ' + s['job_number']
    return jsonify({'name': name or ''})



@app.route("/tools/api/projects", methods=["GET"])
def api_projects_list():
    return jsonify({
        "ok": True,
        "active_project_id": get_active_project_id(),
        "projects": _list_project_ids(),
    })


@app.route("/tools/api/projects/create", methods=["POST"])
def api_projects_create():
    payload = request.get_json(silent=True) if request.is_json else {}
    payload = payload if isinstance(payload, dict) else {}
    project_id = (
        payload.get("project_id")
        or request.form.get("project_id")
        or request.values.get("project_id")
        or ""
    )
    normalized = _sanitize_project_id(project_id)
    if not normalized:
        return jsonify({
            "ok": False,
            "error": "Invalid project_id. Use letters, numbers, dot, underscore, or dash.",
        }), 400

    if normalized in _list_project_ids():
        return jsonify({
            "ok": False,
            "error": f"Project '{normalized}' already exists.",
        }), 400

    _project_dir(normalized, ensure=True)
    return jsonify({
        "ok": True,
        "project_id": normalized,
        "active_project_id": get_active_project_id(),
    })


@app.route("/tools/api/projects/switch", methods=["POST"])
def api_projects_switch():
    payload = request.get_json(silent=True) if request.is_json else {}
    payload = payload if isinstance(payload, dict) else {}
    project_id = (
        payload.get("project_id")
        or request.form.get("project_id")
        or request.values.get("project_id")
        or ""
    )
    normalized = _sanitize_project_id(project_id)
    if not normalized:
        return jsonify({
            "ok": False,
            "error": "Invalid project_id. Use letters, numbers, dot, underscore, or dash.",
        }), 400

    _project_dir(normalized, ensure=True)
    active = _set_active_project_id(normalized, persist=True)
    return jsonify({
        "ok": True,
        "active_project_id": active,
        "projects": _list_project_ids(),
    })
@app.route("/tools/api/project/snapshot", methods=["GET"])
def api_project_snapshot():
    files, missing_optional, notes = _collect_snapshot_files()
    archive_io = io.BytesIO()
    included_files = []

    with zipfile.ZipFile(archive_io, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for rel, abs_path in files.items():
            try:
                archive.write(abs_path, arcname=rel)
                included_files.append(rel)
            except Exception as exc:
                notes.append(f"Skipped unreadable file {rel}: {exc}")

        manifest = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "exported_at": utc_now_iso(),
            "app_name": "NetPi",
            "included_files": included_files,
            "missing_optional_files": missing_optional,
            "source_instance": _safe_instance_metadata(),
            "notes": notes,
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))

    archive_io.seek(0)
    filename = f"netpi_project_snapshot_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.avp"
    try:
        return send_file(
            archive_io,
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream",
        )
    except TypeError:
        archive_io.seek(0)
        return send_file(
            archive_io,
            as_attachment=True,
            attachment_filename=filename,
            mimetype="application/octet-stream",
        )


@app.route("/tools/api/project/restore", methods=["POST"])
def api_project_restore():
    uploaded = _get_uploaded_snapshot_file()
    if uploaded is None or not getattr(uploaded, "filename", ""):
        return jsonify({
            "ok": False,
            "restored_files": [],
            "skipped_files": [],
            "backup_path": "",
            "schema_version": "",
            "notes": ["No snapshot file uploaded. Use multipart form file field 'snapshot' or 'file'."],
        }), 400

    try:
        payload = uploaded.read()
        archive_handle = io.BytesIO(payload)
        with zipfile.ZipFile(archive_handle, "r") as archive:
            file_members = {}
            invalid_members = []
            duplicate_members = []

            for info in archive.infolist():
                if info.is_dir():
                    continue
                normalized = _normalize_snapshot_relpath(info.filename)
                if not _is_safe_snapshot_member(normalized):
                    invalid_members.append(info.filename)
                    continue
                if normalized in file_members:
                    duplicate_members.append(normalized)
                    continue
                file_members[normalized] = info

            if invalid_members:
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": [],
                    "backup_path": "",
                    "schema_version": "",
                    "notes": [f"Archive contains invalid file paths: {sorted(invalid_members)}"],
                }), 400

            if duplicate_members:
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": [],
                    "backup_path": "",
                    "schema_version": "",
                    "notes": [f"Archive contains duplicate file paths: {sorted(set(duplicate_members))}"],
                }), 400

            if "manifest.json" not in file_members:
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": [],
                    "backup_path": "",
                    "schema_version": "",
                    "notes": ["Archive is missing manifest.json."],
                }), 400

            manifest_raw = archive.read(file_members["manifest.json"])
            manifest = json.loads(manifest_raw.decode("utf-8"))
            if not isinstance(manifest, dict):
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": [],
                    "backup_path": "",
                    "schema_version": "",
                    "notes": ["Invalid manifest format."],
                }), 400

            schema_version = str(manifest.get("schema_version") or "").strip()
            if schema_version != SNAPSHOT_SCHEMA_VERSION:
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": [],
                    "backup_path": "",
                    "schema_version": schema_version,
                    "notes": [f"Unsupported schema_version '{schema_version}'. Expected '{SNAPSHOT_SCHEMA_VERSION}'."],
                }), 400

            restore_payloads = {}
            disallowed_files = []
            for rel, info in file_members.items():
                if rel == "manifest.json":
                    continue
                if rel not in PROJECT_RESTORE_ALLOWLIST:
                    disallowed_files.append(rel)
                    continue
                restore_payloads[rel] = archive.read(info)

            if disallowed_files:
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": sorted(disallowed_files),
                    "backup_path": "",
                    "schema_version": schema_version,
                    "notes": ["Archive includes non-restorable files; restore was blocked to avoid unsafe partial apply."],
                }), 400

            if not restore_payloads:
                return jsonify({
                    "ok": False,
                    "restored_files": [],
                    "skipped_files": [],
                    "backup_path": "",
                    "schema_version": schema_version,
                    "notes": ["No approved project-state files found in archive."],
                }), 400

            backup_path, backup_notes = _create_pre_restore_backup()
            notes = list(backup_notes or [])
            staged_writes = []

            for rel, content in restore_payloads.items():
                target = _rel_to_abs_project_path(rel)
                if not _is_within_project_root(target):
                    notes.append(f"Skipped unsafe restore target: {rel}")
                    continue
                temp_path = _atomic_write_bytes(target, content)
                staged_writes.append((rel, temp_path, target))

            restored_files = []
            skipped_files = []

            for rel, temp_path, target in staged_writes:
                try:
                    os.replace(temp_path, target)
                    restored_files.append(rel)
                except PermissionError:
                    # Windows/dev fallback when target file is temporarily locked.
                    with open(temp_path, "rb") as src:
                        content = src.read()
                    with open(target, "wb") as dst:
                        dst.write(content)
                        dst.flush()
                        os.fsync(dst.fileno())
                    restored_files.append(rel)
                except Exception as exc:
                    skipped_files.append(rel)
                    notes.append(f"Failed restoring {rel}: {exc}")
                finally:
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except Exception:
                        pass

            ok = len(restored_files) > 0 and len(skipped_files) == 0
            if not restored_files:
                notes.append("No files were restored.")

            return jsonify({
                "ok": ok,
                "restored_files": restored_files,
                "skipped_files": skipped_files,
                "backup_path": backup_path,
                "schema_version": schema_version,
                "notes": notes,
            }), (200 if ok else 500)
    except zipfile.BadZipFile:
        return jsonify({
            "ok": False,
            "restored_files": [],
            "skipped_files": [],
            "backup_path": "",
            "schema_version": "",
            "notes": ["Invalid archive format. Expected a .avp/.zip snapshot archive."],
        }), 400
    except json.JSONDecodeError:
        return jsonify({
            "ok": False,
            "restored_files": [],
            "skipped_files": [],
            "backup_path": "",
            "schema_version": "",
            "notes": ["manifest.json is not valid JSON."],
        }), 400
    except Exception as e:
        return jsonify({
            "ok": False,
            "restored_files": [],
            "skipped_files": [],
            "backup_path": "",
            "schema_version": "",
            "notes": [str(e)],
        }), 500


@app.route("/tools/api/project/snapshot/compare", methods=["POST"])
def api_project_snapshot_compare():
    baseline_upload = request.files.get("baseline")
    current_upload = request.files.get("current")

    if baseline_upload is None or current_upload is None:
        return jsonify({
            "ok": False,
            "notes": ["Both 'baseline' and 'current' snapshot files are required."],
        }), 400

    try:
        baseline_snapshot = _read_uploaded_snapshot_archive(baseline_upload, "baseline")
        current_snapshot = _read_uploaded_snapshot_archive(current_upload, "current")

        baseline_files = baseline_snapshot.get("files") or {}
        current_files = current_snapshot.get("files") or {}

        device_diff = _compare_snapshot_devices(
            _extract_snapshot_devices(baseline_files),
            _extract_snapshot_devices(current_files),
        )
        settings_diff = _compare_snapshot_settings(
            _extract_snapshot_settings(baseline_files),
            _extract_snapshot_settings(current_files),
        )
        artifact_diff = _compare_snapshot_artifacts(baseline_files, current_files)

        summary = {
            "devices_added": len(device_diff.get("added") or []),
            "devices_removed": len(device_diff.get("removed") or []),
            "devices_changed": len(device_diff.get("changed") or []),
            "settings_changed": len(settings_diff.get("changed") or []),
            "topology_changed": len((artifact_diff.get("topology") or {}).get("changed") or []),
            "multicast_changed": (
                len((artifact_diff.get("multicast_groups") or {}).get("added") or [])
                + len((artifact_diff.get("multicast_groups") or {}).get("removed") or [])
                + len((artifact_diff.get("multicast_groups") or {}).get("changed") or [])
            ),
            "recommendations_changed": int(artifact_diff.get("recommendations_changed") or 0),
        }

        return jsonify({
            "ok": True,
            "baseline": {
                "schema_version": baseline_snapshot.get("schema_version") or "",
                "exported_at": baseline_snapshot.get("exported_at") or "",
                "included_files": baseline_snapshot.get("included_files") or [],
            },
            "current": {
                "schema_version": current_snapshot.get("schema_version") or "",
                "exported_at": current_snapshot.get("exported_at") or "",
                "included_files": current_snapshot.get("included_files") or [],
            },
            "summary": summary,
            "diff": {
                "devices": device_diff,
                "settings": settings_diff,
                "topology": artifact_diff.get("topology") or {"changed": []},
                "multicast_groups": artifact_diff.get("multicast_groups") or {"added": [], "removed": [], "changed": []},
                "artifacts": artifact_diff.get("artifacts") or {"added_files": [], "removed_files": [], "common_files": []},
            },
            "notes": [],
        })
    except ValueError as exc:
        return jsonify({
            "ok": False,
            "notes": [str(exc)],
        }), 400
    except Exception as exc:
        return jsonify({
            "ok": False,
            "notes": [str(exc)],
        }), 500


@app.route("/tools/api/ipschedule", methods=["GET"])
def api_ipschedule():
    try:
        devices = _devices_with_freshness_view(load_devices())
        return jsonify({
            "ok": True,
            "count": len(devices),
            "devices": devices,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/topology", methods=["GET"])
def api_topology():
    return jsonify(_topology_response_payload(load_topology_snapshot(), generated=False))


@app.route("/tools/api/topology/generate", methods=["POST"])
def api_generate_topology():
    try:
        return jsonify(generate_topology_snapshot())
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/multicast_groups", methods=["GET"])
def api_multicast_groups():
    return jsonify(_multicast_groups_response_payload(load_multicast_groups_snapshot(), generated=False))


@app.route("/tools/api/multicast_groups/generate", methods=["POST"])
def api_generate_multicast_groups():
    try:
        return jsonify(generate_multicast_groups_snapshot())
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/checks/run", methods=["POST"])
def api_checks_run():
    s = load_settings()
    data = request.json or {}

    selected_vlan = data.get("vlan")

    gateway = None
    subnet = None

    if selected_vlan:
        for vlan in s.get("vlans", []):
            if vlan.get("name") == selected_vlan:
                gateway = vlan.get("gateway")
                subnet = vlan.get("subnet")
                break

    if not gateway:
        gateway = resolve_gateway(s)

    if not subnet:
        subnet = resolve_subnet(s)

    base = run_base_checks(gateway, subnet)
    devices = load_devices()
    if selected_vlan:
        devices = [d for d in devices if (d.get("vlan") or "") == selected_vlan]

    devs = run_device_checks(devices)

    results = {
        "timestamp": datetime.now().isoformat(),
        "selected_vlan": selected_vlan or "",
        "gateway": gateway,
        "subnet": subnet,
        "base": base,
        "devices": devs
    }
    run_path = save_run(results)
    results["saved_to"] = run_path

    return jsonify(results)



@app.route("/tools/report/latest")
def report_latest():
    runs_dir = _runs_dir()
    files = sorted([f for f in os.listdir(runs_dir) if f.endswith('.json')], reverse=True)
    if not files:
        return "No saved runs found", 404

    latest = os.path.join(runs_dir, files[0])
    data = json.load(open(latest))
    s = load_settings()

    all_checks = list(data.get("base", []))
    for d in data.get("devices", []):
        all_checks.extend(d.get("checks", []))

    passed = len([c for c in all_checks if c.get("status") == "ok"])
    warned = len([c for c in all_checks if c.get("status") == "warn"])
    failed = len([c for c in all_checks if c.get("status") in ("fail", "error")])

    if failed > 0:
        overall = "NOT READY"
        overall_class = "fail"
    elif warned > 0:
        overall = "READY WITH WARNINGS"
        overall_class = "warn"
    else:
        overall = "READY"
        overall_class = "ok"

    summary = {
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "overall": overall,
        "overall_class": overall_class
    }

    return render_template("report.html", s=s, data=data, summary=summary)

@app.route("/tools/api/checks/download_csv")
def download_csv():
    runs_dir = _runs_dir()
    files = sorted([f for f in os.listdir(runs_dir) if f.endswith('.csv')], reverse=True)
    if not files:
        return jsonify({"error": "no csv runs found"}), 404

    latest = os.path.join(runs_dir, files[0])
    return send_file(latest, as_attachment=True)


@app.route("/tools/api/discover_hosts", methods=["POST"])
def discover_hosts():
    s = load_settings()
    data = request.json or {}
    subnets, is_auto_mode = _resolve_discovery_subnets(s, data.get("vlan"))
    subnet = subnets[0] if len(subnets) == 1 else ("configured VLAN subnets" if subnets else "")

    if not subnets:
        return jsonify({"error": "No subnet available"}), 400

    try:
        if is_auto_mode:
            devices, subnet_errors = _discover_hosts_across_subnets(subnets)
        else:
            devices = _discover_hosts_for_subnet(subnet)
            subnet_errors = []

        return jsonify({
            "subnet": subnet,
            "subnets": subnets,
            "count": len(devices),
            "devices": devices,
            "subnet_errors": subnet_errors
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tools/api/discover_hosts/start", methods=["POST"])
def start_discover_hosts():
    s = load_settings()
    data = request.json or {}
    subnets, is_auto_mode = _resolve_discovery_subnets(s, data.get("vlan"))
    subnet = subnets[0] if len(subnets) == 1 else ("configured VLAN subnets" if subnets else "")

    if not subnets:
        return jsonify({"error": "No subnet available"}), 400

    job = _create_discovery_job(subnet)
    _update_background_job(
        job["job_id"],
        progress_updates={
            "current_subnet": subnets[0] if subnets else "",
            "current_subnet_index": 1 if subnets else 0,
            "total_subnets": len(subnets),
            "progress_message": _discovery_progress_message(subnets[0] if subnets else "", 1 if subnets else 0, len(subnets))
        },
        results_updates={
            "subnet": subnet,
            "subnets": subnets
        },
        auto_mode=is_auto_mode
    )
    _start_background_job(_run_discovery_job, job["job_id"])

    return jsonify(_snapshot_discovery_job(_get_discovery_job(job["job_id"]))), 202


@app.route("/tools/api/discover_hosts/status/<job_id>")
def discover_hosts_status(job_id):
    job = _get_discovery_job(job_id)
    if not job:
        return jsonify({"error": "Discovery job not found"}), 404

    return jsonify(_snapshot_discovery_job(job))


@app.route("/tools/api/discover_hosts/cancel/<job_id>", methods=["POST"])
def cancel_discover_hosts(job_id):
    job = _get_discovery_job(job_id)
    if not job:
        return jsonify({"error": "Discovery job not found"}), 404

    count = ((job.get("progress") or {}).get("devices_found_count", 0))
    subnet = ((job.get("results") or {}).get("subnet") or "")
    _cancel_background_job(
        job_id,
        expected_kind="discover_hosts",
        message=_discovery_status_message("cancelled", count, subnet)
    )

    job = _get_discovery_job(job_id)
    return jsonify(_snapshot_discovery_job(job))



@app.route("/tools/api/fingerprint_host", methods=["POST"])
def fingerprint_host():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    vendor = (data.get("vendor") or "").lower()
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    try:
        devices = load_devices()
        device = next((d for d in devices if (d.get("ip") or "").strip() == ip), None)
        if device is None:
            device = {
                "name": ip,
                "ip": ip,
                "type": guess_type_from_vendor(vendor) or "generic",
                "vendor": vendor,
                "vlan": "",
                "notes": ""
            }

        validation = run_validation(device)
        open_ports = sorted(set(validation.get("open_ports") or []))
        open_set = set(open_ports)

        guessed = 'generic'
        fingerprint_platform = normalize_platform_name((validation.get("fingerprint") or {}).get("platform"))
        observed_platform = normalize_platform_name((validation.get("observed_platform") or {}).get("platform"))

        def has_any(*ports):
            return any(p in open_set for p in ports)

        if fingerprint_platform and fingerprint_platform != "unknown":
            guessed = fingerprint_platform
        elif observed_platform and observed_platform != "unknown":
            guessed = observed_platform
        elif has_any(41794, 41795, 41796):
            guessed = 'crestron'
        elif has_any(319, 320, 4440):
            guessed = 'dante'
        elif has_any(5200):
            guessed = 'novastar'
        elif has_any(6454):
            guessed = 'artnet'
        elif has_any(5568):
            guessed = 'sacn'
        elif has_any(7001, 7002, 8000, 8001):
            guessed = 'grandma'
        elif has_any(47808):
            guessed = 'bacnet'
        elif has_any(5060, 5061):
            guessed = 'voip-device'
        elif has_any(1883):
            guessed = 'mqtt-device'
        elif has_any(8554, 554):
            guessed = 'rtsp-device'
        elif has_any(161, 162) and has_any(22, 80, 443, 8080, 8443):
            guessed = 'network-device'
        elif has_any(161, 162):
            guessed = 'snmp-device'
        elif has_any(135, 139, 445, 3389, 5985, 5986):
            guessed = 'windows-host'
        elif has_any(9100, 631, 515):
            guessed = 'printer'
        elif has_any(22) and has_any(80, 443, 8080, 8443):
            guessed = 'network-device'
        elif has_any(23):
            guessed = 'telnet-device'
        elif has_any(22):
            guessed = 'ssh-device'
        elif has_any(80, 81, 88, 443, 8080, 8081, 8088, 8090, 8443, 10443):
            guessed = 'web-device'

        updated_device = None
        device_updated = False
        matched_inventory_device = None

        for inventory_device in devices:
            if (inventory_device.get("ip") or "").strip() != ip:
                continue

            matched_inventory_device = inventory_device
            if should_persist_fingerprinted_type(inventory_device.get("type"), guessed):
                inventory_device["type"] = guessed
                updated_device = dict(inventory_device)
                device_updated = True
            else:
                updated_device = dict(inventory_device)
            break

        if _validation_confirms_reachability(validation):
            if matched_inventory_device is not None:
                if _best_effort_snmp_enrich_device(matched_inventory_device, validation):
                    updated_device = dict(matched_inventory_device)
                    device_updated = True
            else:
                _best_effort_snmp_enrich_device(device, validation)

        type_suggestion = build_type_suggestion(updated_device or device, validation)
        promotion = evaluate_safe_type_promotion(updated_device or device, type_suggestion)
        if matched_inventory_device is not None and promotion.get("should_apply"):
            matched_inventory_device["type"] = promotion.get("suggested_type") or matched_inventory_device.get("type") or ""
            updated_device = dict(matched_inventory_device)
            device_updated = True
        effective_type = resolve_effective_type(updated_device or device, guessed, type_suggestion, validation)

        if matched_inventory_device is not None and _validation_confirms_reachability(validation):
            refreshed_device = _mark_device_freshness(matched_inventory_device, seen=True, reachable=True)
            if refreshed_device != matched_inventory_device:
                matched_inventory_device.clear()
                matched_inventory_device.update(refreshed_device)
                updated_device = dict(matched_inventory_device)
                device_updated = True

        if device_updated:
            save_devices_file(devices)

        try:
            record_device_observation(
                updated_device or device,
                source="fingerprint_host",
                result=validation,
                extra={
                    "ip": ip,
                    "vendor": vendor,
                    "guessed_type": guessed,
                    "inventory_type": ((updated_device or device) or {}).get("type", ""),
                },
            )
        except Exception:
            pass

        return jsonify({
            "ip": ip,
            "open_ports": open_ports,
            "guessed_type": guessed,
            "effective_type": effective_type,
            "type_suggestion": type_suggestion,
            "suggested_type": type_suggestion.get("suggested_type") or "",
            "confidence_score": type_suggestion.get("confidence_score", 0),
            "confidence_label": type_suggestion.get("confidence_label") or "none",
            "suggestion_reasons": list(type_suggestion.get("suggestion_reasons") or []),
            "device_updated": device_updated,
            "updated_device": updated_device
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/tools/api/devices/add_bulk", methods=["POST"])
def add_bulk_devices():
    data = request.json or {}
    devices_in = data.get("devices", [])

    devices, summary = add_discovered_devices_to_inventory(devices_in)
    save_devices_file(devices)

    return jsonify({"success": True, "added": summary["added"]})


def add_discovered_devices_to_inventory(devices_in):
    devices = load_devices()
    settings = load_settings()
    added = 0
    skipped_existing = 0
    added_ips = []

    for d in devices_in:
        normalized = assign_inferred_vlan(d, settings=settings)
        ip = (normalized.get("ip") or "").strip()
        if not ip:
            continue

        existing_device = next((existing for existing in devices if existing.get("ip") == ip), None)
        if existing_device is not None:
            mac_updated = _apply_observed_mac(
                existing_device,
                normalized.get("mac") or normalized.get("mac_address"),
                normalized.get("mac_source") or "arp-cache",
            )
            if not (existing_device.get("vendor") or "").strip():
                vendor_value = (normalized.get("vendor") or "").strip()
                if vendor_value:
                    existing_device["vendor"] = vendor_value
                    mac_updated = True
            refreshed_device = _mark_device_freshness(existing_device, seen=True, reachable=True)
            if refreshed_device != existing_device or mac_updated:
                existing_device.clear()
                existing_device.update(refreshed_device)
            _best_effort_snmp_enrich_device(existing_device)
            skipped_existing += 1
            continue

        device_type = (normalized.get("type") or "generic").strip() or "generic"
        preferred_name = (normalized.get("name") or normalized.get("hostname") or "").strip()
        vendor = (normalized.get("vendor") or "").strip()
        notes = (normalized.get("notes") or "").strip()
        normalized_mac = _normalize_mac_value(normalized.get("mac") or normalized.get("mac_address"))
        generated_name = generate_device_name(devices, device_type, preferred_name)

        new_device = _mark_device_freshness({
            "name": generated_name,
            "ip": ip,
            "type": device_type,
            "vlan": (normalized.get("vlan") or "").strip(),
            "notes": notes or (f"Auto-discovered ({vendor})" if vendor else "Auto-discovered"),
            "mac": normalized_mac or "",
            "mac_address": normalized_mac or None,
            "mac_source": "arp-cache" if normalized_mac else "unknown",
            "vendor": vendor
        }, seen=True, reachable=True)
        _best_effort_snmp_enrich_device(new_device)
        devices.append(new_device)
        added += 1
        added_ips.append(ip)

    return devices, {
        "added": added,
        "skipped_existing": skipped_existing,
        "skipped": skipped_existing,
        "added_ips": added_ips,
        "total_seen": len(devices_in)
    }


@app.route("/tools/api/devices/add_discovered", methods=["POST"])
def add_discovered_device():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    hostname = data.get("hostname", "").strip()
    device_type = data.get("type", "generic").strip()
    mac = data.get("mac", "").strip()
    vendor = data.get("vendor", "").strip()

    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    devices = load_devices()

    existing_device = next((d for d in devices if d.get("ip") == ip), None)
    if existing_device is not None:
        _apply_observed_mac(
            existing_device,
            data.get("mac") or data.get("mac_address"),
            data.get("mac_source") or "arp-cache",
        )
        if not (existing_device.get("vendor") or "").strip() and vendor:
            existing_device["vendor"] = vendor
        refreshed_device = _mark_device_freshness(existing_device, seen=True, reachable=True)
        existing_device.clear()
        existing_device.update(refreshed_device)
        _best_effort_snmp_enrich_device(existing_device)
        save_devices_file(devices)
        return jsonify({"success": True, "message": "Device already exists"})

    normalized = assign_inferred_vlan(data, settings=load_settings())
    vlan = (normalized.get("vlan") or "").strip()
    name = generate_device_name(devices, device_type, hostname)
    normalized_mac = _normalize_mac_value(mac or normalized.get("mac_address"))

    new_device = _mark_device_freshness({
        "name": name,
        "ip": ip,
        "type": device_type,
        "vlan": vlan,
        "notes": f"Auto-discovered ({vendor})" if vendor else "Auto-discovered",
        "mac": normalized_mac or "",
        "mac_address": normalized_mac or None,
        "mac_source": "arp-cache" if normalized_mac else "unknown",
        "vendor": vendor
    }, seen=True, reachable=True)
    _best_effort_snmp_enrich_device(new_device)
    devices.append(new_device)

    save_devices_file(devices)
    return jsonify({"success": True, "message": f"Device added as {name}"})


@app.route("/tools/api/devices/add_all_discovered", methods=["POST"])
def add_all_discovered_devices():
    data = request.json or {}
    devices_in = data.get("devices", [])

    if not isinstance(devices_in, list):
        return jsonify({"error": "devices must be a list"}), 400

    devices, summary = add_discovered_devices_to_inventory(devices_in)
    save_devices_file(devices)

    return jsonify({
        "success": True,
        "added": summary["added"],
        "skipped_existing": summary["skipped_existing"],
        "skipped": summary["skipped"],
        "added_ips": summary["added_ips"],
        "total_seen": summary["total_seen"]
    })

@app.route("/tools/api/checks/export_csv")
def export_csv():
    runs_dir = _runs_dir()
    files = sorted(os.listdir(runs_dir), reverse=True)
    if not files:
        return jsonify({"error": "no runs found"})

    latest = os.path.join(runs_dir, files[0])
    data = json.load(open(latest))

    csv_path = latest.replace(".json", ".csv")

    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)

        writer.writerow(["Section", "Name", "Status", "Detail"])

        for b in data.get("base", []):
            writer.writerow(["base", b.get("name"), b.get("status"), b.get("detail")])

        for d in data.get("devices", []):
            for c in d.get("checks", []):
                writer.writerow([
                    d.get("name"),
                    c.get("check"),
                    c.get("status"),
                    c.get("detail")
                ])

    return jsonify({"csv": csv_path})


@app.route('/tools/api/devices/save', methods=['POST'])
def api_devices_save():
    devices = request.json.get('devices', [])
    existing_devices = load_devices()
    existing_by_ip = {str((d or {}).get("ip") or "").strip(): d for d in existing_devices if isinstance(d, dict)}

    patched_devices = []
    for device in devices or []:
        if not isinstance(device, dict):
            continue
        item = dict(device)
        ip = str(item.get("ip") or "").strip()
        existing = existing_by_ip.get(ip) or {}

        incoming_mac = _normalize_mac_value(item.get("mac") or item.get("mac_address"))
        incoming_source = _canonicalize_mac_source(item.get("mac_source"), has_mac=bool(incoming_mac))
        existing_mac = _normalize_mac_value(existing.get("mac") or existing.get("mac_address"))
        existing_source = _canonicalize_mac_source(existing.get("mac_source"), has_mac=bool(existing_mac))

        if incoming_mac:
            if incoming_source in {"arp-cache", "snmp-oid", "lldp"}:
                item["mac_source"] = incoming_source
            elif existing_mac and incoming_mac == existing_mac and existing_source in {"arp-cache", "snmp-oid", "lldp", "user-entered"}:
                item["mac_source"] = existing_source
            else:
                item["mac_source"] = "user-entered"
            item["mac"] = incoming_mac
            item["mac_address"] = incoming_mac
        else:
            item["mac"] = ""
            item["mac_address"] = None
            item["mac_source"] = "unknown"

        patched_devices.append(item)

    normalized_devices = normalize_devices_for_save(patched_devices, settings=load_settings())
    save_devices_file(normalized_devices)
    return jsonify({'success': True, 'devices': normalized_devices})


@app.route('/tools/api/scan', methods=['POST'])
def api_scan():
    subnet = request.json.get('subnet')
    if not subnet:
        return jsonify({'error': 'No subnet'}), 400

    try:
        result = subprocess.check_output(
            build_nmap_host_discovery_command(subnet, output_flag='--oG'),
            timeout=90
        ).decode()

        devices = []
        for line in result.splitlines():
            if 'Host:' in line:
                p = line.split()
                ip = p[1]
                hostname = p[2].strip('()') if len(p) > 2 else ''
                mac = ""
                if "MAC Address:" in line:
                    try:
                        mac_part = line.split("MAC Address:", 1)[1].strip()
                        mac = _normalize_mac_value(mac_part.split(" (", 1)[0].strip())
                    except Exception:
                        mac = ""
                devices.append({'ip': ip, 'hostname': hostname, 'mac': mac, 'status': 'online'})

        _persist_discovery_macs(devices)
        return jsonify({'devices': devices, 'count': len(devices)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/ping', methods=['POST'])
def api_ping():
    host = request.json.get('host')
    if not host:
        return jsonify({'error': 'No host'}), 400

    try:
        out = subprocess.check_output(
            build_ping_command(host),
            timeout=15,
            stderr=subprocess.STDOUT
        ).decode(errors='replace')
        return jsonify({'output': out})
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output.decode(errors='replace'), 'error': 'Host unreachable'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/portscan', methods=['POST'])
def api_portscan():
    host = request.json.get('host')
    if not host:
        return jsonify({'error': 'No host'}), 400

    try:
        out = subprocess.check_output(
            build_nmap_command(host),
            timeout=60,
            stderr=subprocess.STDOUT
        ).decode(errors='replace')
        return jsonify({'output': out})
    except FileNotFoundError:
        return jsonify({'error': 'nmap not installed or not available in PATH on this platform'}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output.decode(errors='replace'), 'error': 'Port scan failed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/traceroute', methods=['POST'])
def api_traceroute():
    host = request.json.get('host')
    if not host:
        return jsonify({'error': 'No host'}), 400

    try:
        trace_spec = build_traceroute_command(host)

        out = subprocess.check_output(
            trace_spec['command'],
            timeout=trace_spec['timeout'],
            stderr=subprocess.STDOUT
        ).decode(errors='replace')
        return jsonify({'output': out})
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output.decode(errors='replace'), 'error': 'Traceroute failed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/dns/add', methods=['POST'])
def api_dns_add():
    domain = request.json.get('domain')
    ip = request.json.get('ip')
    if not domain or not ip:
        return jsonify({'error': 'Missing fields'}), 400

    try:
        with open('/etc/pihole/custom.list', 'a') as f:
            f.write(f'{ip} {domain}\n')
        subprocess.check_output(['pihole', 'restartdns'], timeout=10)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/dns/delete', methods=['POST'])
def api_dns_delete():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400

    try:
        with open('/etc/pihole/custom.list', 'r') as f:
            lines = f.readlines()
        with open('/etc/pihole/custom.list', 'w') as f:
            f.writelines(l for l in lines if domain not in l)
        subprocess.check_output(['pihole', 'restartdns'], timeout=10)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# =========================
# Pasted device list import
# =========================

HEADER_ALIASES = {
    "name": {"name", "device", "device name", "hostname", "host", "host name", "friendly name"},
    "ip": {"ip", "ip address", "address", "ipv4", "ipv4 address"},
    "vlan": {"vlan", "vlan id", "network", "subnet"},
    "type": {"type", "device type", "role", "category", "class"},
    "mac": {"mac", "mac address", "macaddr", "mac addr", "ethernet", "hw address"},
    "vendor": {"vendor", "manufacturer", "make", "brand"},
    "notes": {"notes", "note", "comment", "comments", "description", "remarks"},
}

DEFAULT_COLUMN_ORDER = ["name", "ip", "vlan", "type", "mac", "vendor", "notes"]


def _norm_header(value):
    value = (value or "").strip().lower()
    value = re.sub(r"[_\-]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value


def _valid_ip(value):
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except Exception:
        return False


def _normalise_mac(value):
    raw = re.sub(r"[^0-9A-Fa-f]", "", (value or ""))
    if len(raw) == 12:
        return ":".join(raw[i:i+2] for i in range(0, 12, 2)).upper()
    return (value or "").strip()


def _detect_delimiter(text):
    sample = "\n".join((text or "").splitlines()[:5])
    if "\t" in sample:
        return "\t"
    if ";" in sample and sample.count(";") > sample.count(","):
        return ";"
    return ","


def _read_pasted_rows(text):
    delimiter = _detect_delimiter(text or "")
    reader = csv.reader(io.StringIO(text or ""), delimiter=delimiter)
    rows = []
    for row in reader:
        cleaned = [c.strip() for c in row]
        while cleaned and cleaned[-1] == "":
            cleaned.pop()
        if any(c != "" for c in cleaned):
            rows.append(cleaned)
    return rows


def _detect_headers(first_row):
    mapping = {}
    for idx, cell in enumerate(first_row):
        norm = _norm_header(cell)
        for canonical, aliases in HEADER_ALIASES.items():
            if norm in aliases:
                mapping[idx] = canonical
                break
    return mapping if len(mapping) >= 2 else None


def _row_to_device_by_position(row):
    vals = [str(c).strip() for c in row]
    out = {
        "name": "",
        "ip": "",
        "vlan": "",
        "type": "",
        "mac": "",
        "vendor": "",
        "notes": "",
    }

    if len(vals) >= 1 and _valid_ip(vals[0]):
        out["ip"] = vals[0]
        if len(vals) >= 2: out["name"] = vals[1]
        if len(vals) >= 3: out["vlan"] = vals[2]
        if len(vals) >= 4: out["type"] = vals[3]
        if len(vals) >= 5: out["mac"] = vals[4]
        if len(vals) >= 6: out["vendor"] = vals[5]
        if len(vals) >= 7: out["notes"] = vals[6]
        return out

    if len(vals) >= 2 and _valid_ip(vals[1]):
        out["name"] = vals[0]
        out["ip"] = vals[1]
        if len(vals) >= 3: out["vlan"] = vals[2]
        if len(vals) >= 4: out["type"] = vals[3]
        if len(vals) >= 5: out["mac"] = vals[4]
        if len(vals) >= 6: out["vendor"] = vals[5]
        if len(vals) >= 7: out["notes"] = vals[6]
        return out

    for i, key in enumerate(DEFAULT_COLUMN_ORDER):
        if i < len(vals):
            out[key] = vals[i]

    return out


def _preview_name_for_row(row, row_index):
    device_type = (row.get("type") or "").strip() or "generic"
    ip = (row.get("ip") or "").strip()
    suffix = ip.split(".")[-1] if ip else str(row_index + 1)
    return f"{device_name_prefix(device_type)}-{suffix}"


def parse_pasted_device_text(text):
    rows = _read_pasted_rows(text or "")
    parsed = []
    invalid_rows = []

    if not rows:
        return {
            "headers_detected": False,
            "header_map": {},
            "devices": [],
            "invalid_rows": [],
            "row_count": 0,
        }

    header_map = _detect_headers(rows[0])
    data_rows = rows[1:] if header_map else rows

    for idx, row in enumerate(data_rows, start=1):
        if header_map:
            item = {"name": "", "ip": "", "vlan": "", "type": "", "mac": "", "vendor": "", "notes": ""}
            for col_idx, canonical in header_map.items():
                if col_idx < len(row):
                    item[canonical] = row[col_idx].strip()
        else:
            item = _row_to_device_by_position(row)

        item["name"] = (item.get("name") or "").strip()
        item["ip"] = (item.get("ip") or "").strip()
        item["vlan"] = (item.get("vlan") or "").strip()
        item["type"] = (item.get("type") or "").strip()
        item["mac"] = _normalise_mac(item.get("mac"))
        item["vendor"] = (item.get("vendor") or "").strip()
        item["notes"] = (item.get("notes") or "").strip()

        if not item["ip"] or not _valid_ip(item["ip"]):
            invalid_rows.append({
                "row_index": idx,
                "raw": row,
                "reason": "Missing or invalid IP",
            })
            continue

        if not item["type"]:
            item["type"] = guess_type_from_vendor(item.get("vendor", ""))

        if not item["name"]:
            item["name"] = _preview_name_for_row(item, idx)

        parsed.append(item)

    return {
        "headers_detected": bool(header_map),
        "header_map": header_map or {},
        "devices": parsed,
        "invalid_rows": invalid_rows,
        "row_count": len(rows),
    }


@app.route("/tools/api/devices/preview_pasted", methods=["POST"])
def preview_pasted_devices():
    payload = request.get_json(silent=True) or {}
    pasted_text = payload.get("text", "")

    result = parse_pasted_device_text(pasted_text)
    existing_devices = load_devices()
    settings = load_settings()
    existing_ips = { (d.get("ip") or "").strip() for d in existing_devices if d.get("ip") }

    preview_devices = []
    simulated_devices = list(existing_devices)

    for row in result["devices"]:
        row_copy = assign_inferred_vlan(row, settings=settings)
        row_ip = (row_copy.get("ip") or "").strip()
        row_copy["duplicate"] = row_ip in existing_ips

        if not row_copy["duplicate"]:
            final_name = generate_device_name(
                simulated_devices,
                row_copy.get("type", "generic"),
                row_copy.get("name", "")
            )
            row_copy["name"] = final_name
            simulated_devices.append({
                "name": final_name,
                "ip": row_copy.get("ip", ""),
                "type": row_copy.get("type", "generic"),
                "vlan": row_copy.get("vlan", ""),
                "notes": row_copy.get("notes", ""),
                "mac": row_copy.get("mac", ""),
                "vendor": row_copy.get("vendor", "")
            })

        preview_devices.append(row_copy)

    return jsonify({
        "ok": True,
        "headers_detected": result["headers_detected"],
        "header_map": result["header_map"],
        "rows_total": result["row_count"],
        "rows_valid": len(preview_devices),
        "rows_invalid": len(result["invalid_rows"]),
        "rows_duplicate": sum(1 for r in preview_devices if r.get("duplicate")),
        "devices": preview_devices,
        "invalid_rows": result["invalid_rows"],
    })


@app.route("/tools/api/devices/import_pasted", methods=["POST"])
def import_pasted_devices():
    payload = request.get_json(silent=True) or {}
    devices_in = payload.get("devices")

    if not isinstance(devices_in, list):
        pasted_text = payload.get("text", "")
        parsed = parse_pasted_device_text(pasted_text)
        devices_in = parsed["devices"]

    devices = load_devices()
    settings = load_settings()
    added = 0
    skipped = []

    for d in devices_in:
        normalized = assign_inferred_vlan(d, settings=settings)
        ip = (normalized.get("ip") or "").strip()
        if not ip or not _valid_ip(ip):
            skipped.append({"ip": ip, "reason": "invalid_ip"})
            continue

        if any(existing.get("ip") == ip for existing in devices):
            skipped.append({"ip": ip, "reason": "duplicate_ip"})
            continue

        device_type = (normalized.get("type") or "").strip() or guess_type_from_vendor(normalized.get("vendor", ""))
        preferred_name = (normalized.get("name") or "").strip()
        generated_name = generate_device_name(devices, device_type, preferred_name)

        devices.append({
            "name": generated_name,
            "ip": ip,
            "type": device_type,
            "vlan": (normalized.get("vlan") or "").strip(),
            "notes": (normalized.get("notes") or "").strip() or f"Pasted import ({normalized.get('vendor', '')})".strip(),
            "mac": (normalized.get("mac") or "").strip(),
            "vendor": (normalized.get("vendor") or "").strip()
        })
        added += 1

    save_devices_file(devices)

    return jsonify({
        "ok": True,
        "success": True,
        "added": added,
        "skipped": skipped,
        "skipped_count": len(skipped)
    })


# =========================
# NetPi V5 â€” System Graph Builder
# =========================

def build_basic_type_groups(devices):
    groups = {}

    ignore_types = {
        "", "unknown", "generic", "device", "other",
        "web-device", "network-device", "firewall",
        "printer", "display", "camera", "projector",
        "voip-device", "snmp-device", "ssh-device", "telnet-device"
    }

    av_types = {
        "crestron", "crestron_uc", "crestron_control",
        "qsys", "biamp", "shure", "dante", "nvx",
        "lighting", "artnet", "sacn", "grandma",
        "novastar", "barco_ctrl", "audio-device"
    }

    for d in devices:
        if not isinstance(d, dict):
            continue

        role = (d.get("av_role") or "").strip().lower()
        stored_type = (d.get("type") or "unknown").strip().lower()
        resolved_type = (d.get("_resolved_type") or d.get("effective_type") or "").strip().lower()
        if stored_type and not weak_device_type(stored_type):
            base_type = stored_type
        else:
            base_type = resolved_type or stored_type
        t = role or base_type

        if t.startswith("qsys") and not role:
            continue
        if t in ignore_types:
            continue
        if t not in av_types:
            continue
        groups.setdefault(t, []).append(d)

    return groups


def build_detected_systems(devices, system_results):
    systems = []
    edges = []

    if not isinstance(devices, list):
        devices = []

    if not isinstance(system_results, list):
        system_results = []

    def rel_label(system_check):
        mapping = {
            "crestron_control_to_qsys": "control",
            "crestron_control_to_biamp": "control",
            "crestron_uc_to_touchpanel": "ui",
        }
        return mapping.get(system_check, "link")

    def make_edge(from_name, to_name, rel_type, source_check=None, inferred=False):
        return {
            "from": from_name,
            "to": to_name,
            "type": rel_type,
            "source_check": source_check or "",
            "inferred": bool(inferred),
        }

    # 1. Real rule-based edges first
    for r in system_results:
        if not isinstance(r, dict):
            continue

        from_name = r.get("from_device")
        to_name = r.get("to_device")
        system_check = r.get("system_check")
        status = (r.get("status") or "").strip().lower()

        if not from_name or not to_name:
            continue

        # Skip unresolved placeholder rows
        if from_name == "?" or to_name == "?":
            continue

        # Only treat actual evaluated pairs as graph edges
        if status in ("pass", "fail"):
            relationship_type = (r.get("relationship_type") or "").strip()
            edges.append(
                make_edge(
                    from_name,
                    to_name,
                    relationship_type or rel_label(system_check),
                    source_check=system_check,
                    inferred=False
                )
            )

    # 2. Fallback inferred edges only if no real rule edges exist
    if not edges:
        groups = build_basic_type_groups(devices)
        active_role_groups = [devs for devs in groups.values() if isinstance(devs, list) and devs]

        # Avoid weak inferred systems when only one AV role is present.
        if len(active_role_groups) <= 1:
            return {
                "systems": [],
                "mode": "type_grouping",
                "edge_count": 0
            }

        idx = 1
        for t, devs in groups.items():
            if len(devs) < 2:
                continue

            names = []
            for d in devs:
                if isinstance(d, dict):
                    names.append(d.get("name") or d.get("ip") or "unnamed-device")

            rels = []
            if len(names) >= 2:
                for i in range(len(names) - 1):
                    rels.append(
                        make_edge(
                            names[i],
                            names[i + 1],
                            "peer",
                            source_check=f"inferred_{t}",
                            inferred=True
                        )
                    )

            summary_parts = []
            if rels:
                for e in rels:
                    summary_parts.append(f'{e["from"]} â†’ {e["to"]} ({e["type"]})')
                summary_chain = " | ".join(summary_parts)
            else:
                summary_chain = " â†’ ".join(names)

            systems.append({
                "system_id": f"type_group_{idx}",
                "devices": names,
                "relationships": rels,
                "summary_chain": summary_chain
            })
            idx += 1

        return {
            "systems": systems,
            "mode": "type_grouping",
            "edge_count": sum(len(s.get("relationships", [])) for s in systems)
        }

    # 3. Build connected components from edges
    graph = {}
    for e in edges:
        if not isinstance(e, dict):
            continue
        if not e.get("from") or not e.get("to"):
            continue
        graph.setdefault(e["from"], set()).add(e["to"])
        graph.setdefault(e["to"], set()).add(e["from"])

    visited = set()
    idx = 1

    for node in graph:
        if node in visited:
            continue

        stack = [node]
        comp = set()

        while stack:
            n = stack.pop()
            if n in visited:
                continue
            visited.add(n)
            comp.add(n)
            stack.extend(graph.get(n, set()) - visited)

        comp_list = sorted(comp)
        comp_edges = [
            e for e in edges
            if isinstance(e, dict) and e.get("from") in comp and e.get("to") in comp
        ]

        if comp_edges:
            summary_chain = " | ".join(
                f'{e["from"]} â†’ {e["to"]} ({e["type"]})'
                for e in comp_edges
            )
        else:
            summary_chain = " â†’ ".join(comp_list)

        systems.append({
            "system_id": f"system_{idx}",
            "devices": comp_list,
            "relationships": comp_edges,
            "summary_chain": summary_chain
        })
        idx += 1

    return {
        "systems": systems,
        "mode": "graph",
        "edge_count": len(edges)
    }


@app.route("/tools/api/auto_type_devices", methods=["POST"])
def api_auto_type_devices():
    try:
        devices = load_devices()
        changed = []

        for device in devices:
            try:
                result = run_validation(device)
                auto_type = decide_auto_promoted_type(device, result)
                if auto_type.get("should_apply") and auto_type.get("proposed_type"):
                    old_type = (device.get("type") or "").strip()
                    new_type = auto_type.get("proposed_type")
                    if old_type != new_type:
                        device["type"] = new_type
                        changed.append({
                            "name": device.get("name"),
                            "ip": device.get("ip"),
                            "old_type": old_type,
                            "new_type": new_type,
                            "confidence": auto_type.get("confidence"),
                            "source": auto_type.get("source"),
                            "reason": auto_type.get("reason"),
                        })
            except Exception:
                pass

        save_devices_file(devices)

        return jsonify({
            "ok": True,
            "count": len(changed),
            "changed": changed,
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/validate_systems", methods=["POST"])
def api_validate_systems():
    try:
        payload = request.get_json(silent=True) or {}
        vlan = str(payload.get("vlan") or "").strip()

        devices = payload.get("devices")
        explicit_devices = isinstance(devices, list) and bool(devices)

        if not explicit_devices:
            inventory_devices = load_devices()
            devices = inventory_devices
        else:
            inventory_devices = None

        if vlan:
            devices = [device for device in devices if str(device.get("vlan") or "").strip() == vlan]

        large_inventory_threshold = 25
        skip_expensive_stages = (not explicit_devices) and (not vlan) and len(devices) > large_inventory_threshold
        if skip_expensive_stages:
            connectivity_summary = {
                "pass": 0,
                "fail": 0,
                "warn": 0,
                "info": 0,
                "skipped": len(devices),
            }
            connectivity_note = f"Large inventory system validation was abbreviated for {len(devices)} devices; select a VLAN or smaller device scope to run connectivity matrix and detected systems."
            detected = {
                "systems": [],
                "mode": "large_inventory_skipped",
                "edge_count": 0,
            }
            return jsonify({
                "ok": True,
                "count": 0,
                "results": [],
                "system_groups": [],
                "system_group_results": [],
                "topology_results": [],
                "connectivity": [],
                "connectivity_summary": connectivity_summary,
                "connectivity_note": connectivity_note,
                "detected_systems": detected,
                "multicast_groups": load_multicast_groups_snapshot(),
            })

        enriched_devices = [enrich_device_runtime(device) for device in devices]
        validations_by_ip = {}
        fingerprint_updates = []
        devices_changed = False

        for device, item in zip(devices, enriched_devices):
            result = dict(item.get("_validation_result") or {})
            if not explicit_devices and _validation_confirms_reachability(result):
                refreshed_device = _mark_device_freshness(device, seen=True, reachable=True)
                if refreshed_device != device:
                    device.clear()
                    device.update(refreshed_device)
                    devices_changed = True
                if isinstance(item.get("snmp_data"), dict):
                    if _merge_snmp_enrichment(device, item.get("snmp_data")):
                        devices_changed = True
                    _apply_snmp_to_validation_result(result, device)
            auto_type = result.get("auto_type") or {}
            role = item.get("av_role")
            validations_by_ip[result.get("ip", "")] = result
            key = _stable_fingerprint_key(device, result)
            if key:
                fingerprint_updates.append({
                    "key": key,
                    "record": _build_fingerprint_entry(item, result, av_role=role),
                })
            try:
                record_device_observation(
                    item,
                    source="validate_systems",
                    result=result,
                    extra={
                        "guessed_type": auto_type.get("proposed_type") or "",
                        "inventory_type": device.get("type") or "",
                    },
                )
            except Exception:
                pass

        if fingerprint_updates:
            try:
                update_fingerprint_store(fingerprint_updates)
            except Exception:
                pass

        if devices_changed and not explicit_devices and inventory_devices is not None:
            save_devices_file(inventory_devices)

        system_groups = build_runtime_system_groups(enriched_devices)
        results = run_system_validation(enriched_devices, validations_by_ip)
        system_group_results = build_system_group_results(system_groups, results)
        topology_results = build_system_topology_results(system_groups, system_group_results)
        connectivity_results = []
        connectivity_summary = {
            "pass": 0,
            "fail": 0,
            "warn": 0,
            "info": 0,
            "skipped": 0,
        }
        connectivity_note = ""
        try:
            connectivity_results = run_connectivity_validation(enriched_devices, validations_by_ip)
            connectivity_summary = summarize_connectivity_results(connectivity_results)
        except Exception as connectivity_error:
            connectivity_results = []
            connectivity_summary = {
                "pass": 0,
                "fail": 0,
                "warn": 1,
                "info": 0,
                "skipped": 0,
                "error": str(connectivity_error),
            }
            connectivity_note = "Connectivity matrix evaluation failed; base system validation results remain available."

        detected = build_detected_systems(enriched_devices, results)
        multicast_groups = load_multicast_groups_snapshot()

        return jsonify({
            "ok": True,
            "count": len(results),
            "results": results,
            "system_groups": system_groups,
            "system_group_results": system_group_results,
            "topology_results": topology_results,
            "connectivity": connectivity_results,
            "connectivity_summary": connectivity_summary,
            "connectivity_note": connectivity_note,
            "detected_systems": detected,
            "multicast_groups": multicast_groups,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/generate_flows", methods=["POST"])
def api_generate_flows():
    try:
        payload = request.get_json(silent=True) or {}
        vlan = str(payload.get("vlan") or "").strip()
        devices = payload.get("devices")
        explicit_devices = isinstance(devices, list) and bool(devices)

        if not explicit_devices:
            devices = load_devices()

        if vlan:
            devices = [device for device in devices if str(device.get("vlan") or "").strip() == vlan]

        enriched_devices = [enrich_device_runtime(device) for device in devices]
        validations_by_ip = {}
        ip_to_device = {}
        for item in enriched_devices:
            validation_result = dict(item.get("_validation_result") or {})
            ip = str(validation_result.get("ip") or item.get("ip") or "").strip()
            if ip:
                validations_by_ip[ip] = validation_result
                ip_to_device[ip] = {
                    "name": item.get("name") or "",
                    "type": item.get("effective_type") or item.get("_resolved_type") or item.get("type") or "",
                }

        system_results = run_system_validation(enriched_devices, validations_by_ip)
        connectivity_results = []
        try:
            connectivity_results = run_connectivity_validation(enriched_devices, validations_by_ip)
        except Exception:
            connectivity_results = []

        system_groups = build_runtime_system_groups(enriched_devices)
        ip_to_system_id = {}
        for group in (system_groups or []):
            group_id = str(group.get("system_id") or "").strip()
            for device in (group.get("devices") or []):
                ip = str(device.get("ip") or "").strip()
                if ip and group_id:
                    ip_to_system_id[ip] = group_id

        system_flow_pack = generate_flows_from_system_results(
            system_results,
            ip_to_system_id=ip_to_system_id,
            ip_to_device=ip_to_device,
        )
        connectivity_flow_pack = generate_flows_from_connectivity_results(
            connectivity_results,
            ip_to_system_id=ip_to_system_id,
            ip_to_device=ip_to_device,
        )

        deduped_flows = {}
        for flow in (system_flow_pack.get("flows") or []) + (connectivity_flow_pack.get("flows") or []):
            if not isinstance(flow, dict):
                continue
            flow_id = str(flow.get("flow_id") or "").strip()
            if not flow_id:
                continue

            existing = deduped_flows.get(flow_id)
            if not existing:
                deduped_flows[flow_id] = flow
                continue

            existing_confidence = int(existing.get("confidence") or 0)
            next_confidence = int(flow.get("confidence") or 0)
            if next_confidence > existing_confidence:
                deduped_flows[flow_id] = flow

        results = list(deduped_flows.values())
        unmapped_relationships = (system_flow_pack.get("unmapped") or []) + (connectivity_flow_pack.get("unmapped") or [])

        relationship_types = set()
        relationship_types.update(system_flow_pack.get("relationship_types") or set())
        relationship_types.update(connectivity_flow_pack.get("relationship_types") or set())

        systems_seen = set()
        for row in results:
            system_id = str(row.get("system_id") or "").strip()
            if system_id:
                systems_seen.add(system_id)

        summary = {
            "flows": len(results),
            "systems_seen": len(systems_seen),
            "relationship_types": len(relationship_types),
            "derived_from": ["system_results", "connectivity"],
        }

        return jsonify({
            "ok": True,
            "count": len(results),
            "summary": summary,
            "results": results,
            "unmapped_relationships": unmapped_relationships,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


def _build_system_requirements_payload(payload):
    payload = payload if isinstance(payload, dict) else {}
    vlan = str(payload.get("vlan") or "").strip()

    direct_flows = payload.get("flows")
    if isinstance(direct_flows, list):
        ip_to_device = {}
        for flow in direct_flows:
            if not isinstance(flow, dict):
                continue
            src_ip = str(flow.get("src_ip") or "").strip()
            dst_ip = str(flow.get("dst_ip") or "").strip()
            if src_ip and src_ip not in ip_to_device:
                ip_to_device[src_ip] = {
                    "name": flow.get("src_device") or "",
                    "type": flow.get("src_type") or "",
                    "vlan": flow.get("src_vlan") or "",
                }
            if dst_ip and dst_ip not in ip_to_device:
                ip_to_device[dst_ip] = {
                    "name": flow.get("dst_device") or "",
                    "type": flow.get("dst_type") or "",
                    "vlan": flow.get("dst_vlan") or "",
                }

        aggregated = aggregate_flows_by_system(direct_flows, ip_to_device=ip_to_device)
        return {
            "ok": True,
            "count": len(aggregated.get("results") or []),
            "summary": aggregated.get("summary") or {},
            "results": aggregated.get("results") or [],
            "ungrouped_flows": aggregated.get("ungrouped_flows") or [],
        }

    devices = payload.get("devices")
    explicit_devices = isinstance(devices, list) and bool(devices)
    if not explicit_devices:
        devices = load_devices()

    if vlan:
        devices = [device for device in devices if str(device.get("vlan") or "").strip() == vlan]

    enriched_devices = [enrich_device_runtime(device) for device in devices]
    validations_by_ip = {}
    ip_to_device = {}
    for item in enriched_devices:
        validation_result = dict(item.get("_validation_result") or {})
        ip = str(validation_result.get("ip") or item.get("ip") or "").strip()
        if not ip:
            continue
        validations_by_ip[ip] = validation_result
        ip_to_device[ip] = {
            "name": item.get("name") or "",
            "type": item.get("effective_type") or item.get("_resolved_type") or item.get("type") or "",
            "vlan": item.get("vlan") or "",
        }

    system_results = run_system_validation(enriched_devices, validations_by_ip)
    connectivity_results = []
    try:
        connectivity_results = run_connectivity_validation(enriched_devices, validations_by_ip)
    except Exception:
        connectivity_results = []

    system_groups = build_runtime_system_groups(enriched_devices)
    ip_to_system_id = {}
    for group in (system_groups or []):
        group_id = str(group.get("system_id") or "").strip()
        for device in (group.get("devices") or []):
            ip = str(device.get("ip") or "").strip()
            if ip and group_id:
                ip_to_system_id[ip] = group_id

    system_flow_pack = generate_flows_from_system_results(
        system_results,
        ip_to_system_id=ip_to_system_id,
        ip_to_device=ip_to_device,
    )
    connectivity_flow_pack = generate_flows_from_connectivity_results(
        connectivity_results,
        ip_to_system_id=ip_to_system_id,
        ip_to_device=ip_to_device,
    )

    deduped_flows = {}
    for flow in (system_flow_pack.get("flows") or []) + (connectivity_flow_pack.get("flows") or []):
        if not isinstance(flow, dict):
            continue
        flow_id = str(flow.get("flow_id") or "").strip()
        if not flow_id:
            continue

        existing = deduped_flows.get(flow_id)
        if not existing:
            deduped_flows[flow_id] = flow
            continue

        existing_confidence = int(existing.get("confidence") or 0)
        next_confidence = int(flow.get("confidence") or 0)
        if next_confidence > existing_confidence:
            deduped_flows[flow_id] = flow

    flows = list(deduped_flows.values())
    aggregated = aggregate_flows_by_system(flows, ip_to_device=ip_to_device)
    ungrouped = list(aggregated.get("ungrouped_flows") or [])
    ungrouped.extend((system_flow_pack.get("unmapped") or []))
    ungrouped.extend((connectivity_flow_pack.get("unmapped") or []))

    return {
        "ok": True,
        "count": len(aggregated.get("results") or []),
        "summary": aggregated.get("summary") or {},
        "results": aggregated.get("results") or [],
        "ungrouped_flows": ungrouped,
    }


def _looks_like_system_requirement_rows(rows):
    if not isinstance(rows, list):
        return False
    if not rows:
        return True
    for row in rows:
        if isinstance(row, dict):
            return isinstance(row.get("categories"), dict)
    return False


def _normalize_zone_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").strip().lower())


def _build_vlan_zone_lookup(settings):
    lookup = {}
    vlans = (settings or {}).get("vlans") or []
    for vlan in vlans:
        if not isinstance(vlan, dict):
            continue
        zone_name = str(vlan.get("name") or "").strip()
        if not zone_name:
            continue

        aliases = [
            zone_name,
            vlan.get("vlan_id"),
            vlan.get("id"),
            vlan.get("subnet"),
        ]
        for alias in aliases:
            token = _normalize_zone_key(alias)
            if token:
                lookup[token] = zone_name
    return lookup


def _resolve_firewall_zone(zone_hint, endpoint_ip, settings, zone_lookup):
    zone_hint = str(zone_hint or "").strip()
    if zone_hint:
        zone_name = zone_lookup.get(_normalize_zone_key(zone_hint))
        if zone_name:
            return zone_name
        return zone_hint

    inferred_zone = str(infer_vlan_from_ip(endpoint_ip, settings=settings) or "").strip()
    if inferred_zone:
        zone_name = zone_lookup.get(_normalize_zone_key(inferred_zone))
        return zone_name or inferred_zone
    return ""


def _normalize_protocol(value):
    protocol = str(value or "").strip().upper()
    if protocol in {"TCP", "UDP", "ICMP"}:
        return protocol
    if protocol == "":
        return "TCP"
    return protocol


def _normalize_direction(value):
    token = str(value or "").strip().lower()
    if token in {"src_to_dst", "source_to_destination"}:
        return "source_to_destination"
    if token in {"dst_to_src", "destination_to_source"}:
        return "destination_to_source"
    return "source_to_destination"


def _coerce_confidence(value, category):
    if isinstance(value, int):
        return max(0, min(100, value))
    if isinstance(value, str) and value.isdigit():
        return max(0, min(100, int(value)))
    default_map = {
        "control": 80,
        "media": 80,
        "service": 70,
        "management": 55,
        "unknown": 45,
    }
    return default_map.get(str(category or "").strip().lower(), 50)


def _classify_requirement_level(category, confidence, derived_sources, has_port):
    category = str(category or "").strip().lower()
    derived = {str(item or "").strip().lower() for item in (derived_sources or []) if str(item or "").strip()}
    has_direct_system_signal = "validate_systems.results" in derived

    if not has_port:
        return "recommended"
    if category in {"control", "media"} and confidence >= 65:
        return "min_required"
    if category == "service" and confidence >= 75 and has_direct_system_signal:
        return "min_required"
    return "recommended"


def _build_business_justification(category, requirement_level):
    category = str(category or "").strip().lower()
    if requirement_level == "min_required":
        if category == "control":
            return "Required for operator control and coordination between AV subsystems."
        if category == "media":
            return "Required for baseline AV media transport between system components."
        if category == "service":
            return "Required for essential AV service dependencies used during normal operation."
    if category == "management":
        return "Recommended to support monitoring, maintenance, and managed operations."
    if category == "service":
        return "Recommended to support advisory service dependencies in this environment."
    return "Recommended based on observed or inferred AV communication patterns."


def _build_av_justification(purpose, relationship_types, derived_sources):
    purpose_text = str(purpose or "").strip() or "Observed AV communication path."
    relation_text = ""
    relations = sorted({str(item or "").strip() for item in (relationship_types or []) if str(item or "").strip()})
    if relations:
        relation_text = f" Relationship context: {', '.join(relations)}."
    source_text = ""
    sources = sorted({str(item or "").strip() for item in (derived_sources or []) if str(item or "").strip()})
    if sources:
        source_text = f" Derived from: {', '.join(sources)}."
    return f"{purpose_text}.{relation_text}{source_text}".strip()


def _compose_firewall_plan(system_requirement_rows, settings):
    zone_lookup = _build_vlan_zone_lookup(settings or {})
    merged = {}
    candidate_count = 0

    category_order = ["control", "media", "service", "management", "unknown"]

    for system in (system_requirement_rows or []):
        if not isinstance(system, dict):
            continue

        system_id = str(system.get("system_id") or "").strip()
        categories = system.get("categories") or {}
        if not isinstance(categories, dict):
            continue

        for category in category_order:
            rows = categories.get(category) or []
            if not isinstance(rows, list):
                continue

            for row in rows:
                if not isinstance(row, dict):
                    continue

                devices = row.get("devices") or []
                src_device = devices[0] if len(devices) > 0 and isinstance(devices[0], dict) else {}
                dst_device = devices[1] if len(devices) > 1 and isinstance(devices[1], dict) else {}

                src_ip = str(src_device.get("ip") or "").strip()
                dst_ip = str(dst_device.get("ip") or "").strip()
                src_name = str(src_device.get("name") or src_ip or "Unknown source").strip()
                dst_name = str(dst_device.get("name") or dst_ip or "Unknown destination").strip()

                source_zone = _resolve_firewall_zone(
                    row.get("src_zone_hint") or row.get("src_vlan"),
                    src_ip,
                    settings,
                    zone_lookup,
                )
                destination_zone = _resolve_firewall_zone(
                    row.get("dst_zone_hint") or row.get("dst_vlan"),
                    dst_ip,
                    settings,
                    zone_lookup,
                )

                if not source_zone and not destination_zone:
                    source_zone = "Unassigned"
                    destination_zone = "Unassigned"
                elif source_zone and not destination_zone:
                    destination_zone = "Unknown"
                elif destination_zone and not source_zone:
                    source_zone = "Unknown"

                protocol = _normalize_protocol(row.get("protocol"))
                direction = _normalize_direction(row.get("direction"))
                purpose = str(row.get("purpose") or f"{category} network flow").strip()
                ports = sorted({int(p) for p in (row.get("ports") or []) if isinstance(p, int)})
                expanded_ports = ports if ports else [None]
                confidence = _coerce_confidence(row.get("confidence"), category)
                derived_sources = row.get("derived_from") or []
                relationship_types = row.get("contributing_relationship_types") or []
                requirement_level = _classify_requirement_level(
                    category,
                    confidence,
                    derived_sources,
                    has_port=bool(ports),
                )

                business_justification = _build_business_justification(category, requirement_level)
                av_justification = _build_av_justification(purpose, relationship_types, derived_sources)

                evidence = {"Derived from system requirements aggregation"}
                for source in (derived_sources or []):
                    source_text = str(source or "").strip()
                    if source_text:
                        evidence.add(f"Source: {source_text}")
                for flow_id in (row.get("source_flow_ids") or []):
                    flow_text = str(flow_id or "").strip()
                    if flow_text:
                        evidence.add(f"Flow: {flow_text}")
                for note in (row.get("notes") or []):
                    note_text = str(note or "").strip()
                    if note_text:
                        evidence.add(note_text)

                for port in expanded_ports:
                    candidate_count += 1
                    key = (
                        source_zone,
                        destination_zone,
                        direction,
                        protocol,
                        port,
                        str(category or "unknown").strip().lower() or "unknown",
                    )
                    existing = merged.get(key)
                    if not existing:
                        existing = {
                            "requirement_level": requirement_level,
                            "category": str(category or "unknown").strip().lower() or "unknown",
                            "source_zone": source_zone,
                            "destination_zone": destination_zone,
                            "direction": direction,
                            "protocol": protocol,
                            "port": port,
                            "purposes": set(),
                            "business_justifications": set(),
                            "av_justifications": set(),
                            "source_systems": set(),
                            "source_devices": set(),
                            "destination_devices": set(),
                            "evidence": set(),
                            "confidence_values": [],
                        }
                        merged[key] = existing

                    if requirement_level == "min_required":
                        existing["requirement_level"] = "min_required"
                    existing["purposes"].add(purpose)
                    existing["business_justifications"].add(business_justification)
                    existing["av_justifications"].add(av_justification)
                    existing["source_devices"].add(src_name)
                    existing["destination_devices"].add(dst_name)
                    if system_id:
                        existing["source_systems"].add(system_id)
                    existing["evidence"].update(evidence)
                    existing["confidence_values"].append(confidence)

    rules = []
    ordered_keys = sorted(
        merged.keys(),
        key=lambda item: (
            0 if merged[item]["requirement_level"] == "min_required" else 1,
            item[0],
            item[1],
            item[3],
            item[4] if item[4] is not None else -1,
            item[5],
        ),
    )

    for index, key in enumerate(ordered_keys, start=1):
        row = merged[key]
        confidence_values = row.get("confidence_values") or []
        confidence = min(confidence_values) if confidence_values else 0
        purpose_values = sorted(row.get("purposes") or [])
        business_values = sorted(row.get("business_justifications") or [])
        av_values = sorted(row.get("av_justifications") or [])
        port_value = row.get("port")

        rules.append({
            "rule_id": f"FW-{index:03d}",
            "requirement_level": row.get("requirement_level") or "recommended",
            "category": row.get("category") or "unknown",
            "source_zone": row.get("source_zone") or "Unknown",
            "destination_zone": row.get("destination_zone") or "Unknown",
            "direction": row.get("direction") or "source_to_destination",
            "protocol": row.get("protocol") or "TCP",
            "port": port_value,
            "ports": [port_value] if isinstance(port_value, int) else [],
            "purpose": "; ".join(purpose_values) if purpose_values else "Network flow",
            "business_justification": business_values[0] if business_values else "",
            "av_justification": av_values[0] if av_values else "",
            "confidence": confidence,
            "source_systems": sorted(row.get("source_systems") or []),
            "source_devices": sorted(row.get("source_devices") or []),
            "destination_devices": sorted(row.get("destination_devices") or []),
            "evidence": sorted(row.get("evidence") or []),
        })

    zones = sorted(
        {
            str(zone).strip()
            for rule in rules
            for zone in (rule.get("source_zone"), rule.get("destination_zone"))
            if str(zone or "").strip()
        }
    )
    protocols = sorted({str(rule.get("protocol") or "").strip() for rule in rules if str(rule.get("protocol") or "").strip()})
    categories = sorted({str(rule.get("category") or "").strip() for rule in rules if str(rule.get("category") or "").strip()})
    min_required_rules = sum(1 for rule in rules if rule.get("requirement_level") == "min_required")

    return {
        "rules": rules,
        "summary": {
            "total_rules": len(rules),
            "min_required_rules": min_required_rules,
            "recommended_rules": len(rules) - min_required_rules,
            "zones": zones,
            "protocols": protocols,
            "categories": categories,
            "duplicates_removed": max(0, candidate_count - len(rules)),
        },
    }


def _extract_results_from_payload(value, *, nested_key=""):
    if not isinstance(value, dict):
        return []
    if nested_key and isinstance(value.get(nested_key), dict):
        return list((value.get(nested_key) or {}).get("results") or [])
    return list(value.get("results") or [])


def _build_recommendation_context(payload):
    payload = payload if isinstance(payload, dict) else {}
    settings = load_settings()
    devices = payload.get("devices")
    explicit_devices = isinstance(devices, list) and bool(devices)
    if not explicit_devices:
        devices = load_devices()

    vlan = str(payload.get("vlan") or "").strip()
    if vlan:
        devices = [d for d in devices if str(d.get("vlan") or "").strip() == vlan]

    validate_all_payload = payload.get("validate_all")
    if isinstance(validate_all_payload, dict) and isinstance(validate_all_payload.get("results"), list):
        validate_all = validate_all_payload
    else:
        validation_results = run_validation_for_all(devices)
        for device, result in zip(devices, validation_results):
            auto_type = decide_auto_promoted_type(device, result)
            type_suggestion = build_type_suggestion(device, result)
            result["type_suggestion"] = type_suggestion
            result["suggested_type"] = type_suggestion.get("suggested_type") or ""
            result["effective_type"] = resolve_effective_type(device, auto_type.get("proposed_type") or "", type_suggestion, result)
            result["confidence_score"] = type_suggestion.get("confidence_score", 0)
            result["confidence_label"] = type_suggestion.get("confidence_label") or "none"
            result["suggestion_reasons"] = list(type_suggestion.get("suggestion_reasons") or [])
        validate_all = {
            "ok": True,
            "count": len(validation_results),
            "results": validation_results,
        }

    validate_systems_payload = payload.get("validate_systems")
    if isinstance(validate_systems_payload, dict) and isinstance(validate_systems_payload.get("results"), list):
        validate_systems = validate_systems_payload
    else:
        enriched_devices = [enrich_device_runtime(device) for device in devices]
        validations_by_ip = {}
        for item in enriched_devices:
            validation_result = dict(item.get("_validation_result") or {})
            ip = str(validation_result.get("ip") or item.get("ip") or "").strip()
            if ip:
                validations_by_ip[ip] = validation_result

        system_results = run_system_validation(enriched_devices, validations_by_ip)
        connectivity_results = []
        try:
            connectivity_results = run_connectivity_validation(enriched_devices, validations_by_ip)
        except Exception:
            connectivity_results = []

        validate_systems = {
            "ok": True,
            "count": len(system_results),
            "results": system_results,
            "connectivity": connectivity_results,
        }

    system_requirements_payload = payload.get("system_requirements")
    if isinstance(system_requirements_payload, dict) and isinstance(system_requirements_payload.get("results"), list):
        system_requirements = system_requirements_payload
    else:
        system_requirements = _build_system_requirements_payload(payload)

    firewall_payload = payload.get("firewall_plan")
    if isinstance(firewall_payload, dict):
        if isinstance(firewall_payload.get("firewall_plan"), dict):
            firewall_plan = firewall_payload.get("firewall_plan") or {}
        else:
            firewall_plan = firewall_payload
    else:
        firewall_plan = _compose_firewall_plan(system_requirements.get("results") or [], settings=settings)

    return {
        "devices": list(devices or []),
        "validate_all": validate_all,
        "validate_systems": validate_systems,
        "system_requirements": system_requirements,
        "firewall_plan": firewall_plan,
        "multicast_groups": load_multicast_groups_snapshot(),
    }


def _recommendation_sort_key(item):
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    category_order = {
        "integrity": 0,
        "design": 1,
        "segmentation": 2,
        "DHCP": 3,
        "multicast": 4,
        "security": 5,
        "commissioning_readiness": 6,
    }
    return (
        severity_order.get(str(item.get("severity") or "").strip().lower(), 99),
        category_order.get(str(item.get("category") or "").strip(), 99),
        str(item.get("title") or "").strip().lower(),
    )


def _build_recommendations(context):
    categories = ["integrity", "design", "segmentation", "DHCP", "multicast", "security", "commissioning_readiness"]
    by_key = {}

    def add_rec(category, severity, title, finding, why_it_matters, suggested_action, evidence_source=None, affected_devices=None):
        if category not in categories:
            return
        severity = str(severity or "info").strip().lower()
        if severity not in {"high", "medium", "low", "info"}:
            severity = "info"
        key = (category, severity, str(title or "").strip().lower())
        existing = by_key.get(key)
        if not existing:
            existing = {
                "category": category,
                "severity": severity,
                "title": str(title or "").strip(),
                "finding": str(finding or "").strip(),
                "why_it_matters": str(why_it_matters or "").strip(),
                "suggested_action": str(suggested_action or "").strip(),
                "_evidence_source": set(),
                "_affected_devices": set(),
            }
            by_key[key] = existing

        for source in (evidence_source or []):
            text = str(source or "").strip()
            if text:
                existing["_evidence_source"].add(text)
        for device_name in (affected_devices or []):
            text = str(device_name or "").strip()
            if text:
                existing["_affected_devices"].add(text)

    devices = list(context.get("devices") or [])
    validate_all_results = _extract_results_from_payload(context.get("validate_all"))
    validate_systems_results = _extract_results_from_payload(context.get("validate_systems"))
    connectivity_results = list((context.get("validate_systems") or {}).get("connectivity") or [])
    system_requirements_results = _extract_results_from_payload(context.get("system_requirements"))
    firewall_rules = list((context.get("firewall_plan") or {}).get("rules") or [])
    multicast_snapshot = context.get("multicast_groups") or {}
    multicast_groups = list(multicast_snapshot.get("groups") or [])
    multicast_generated_at = str(multicast_snapshot.get("generated_at") or "").strip()

    # 8) Missing metadata affecting commissioning readiness
    missing_mac = []
    missing_serial = []
    missing_vlan = []
    for device in devices:
        name = str(device.get("name") or device.get("ip") or "Unknown device").strip()
        if not str(device.get("mac") or device.get("mac_address") or "").strip():
            missing_mac.append(name)
        if not str(device.get("serial") or device.get("serial_number") or "").strip():
            missing_serial.append(name)
        if not str(device.get("vlan") or "").strip():
            missing_vlan.append(name)

    if missing_mac:
        add_rec(
            "commissioning_readiness",
            "high",
            "MAC address gaps are blocking inventory integrity",
            "One or more devices are missing MAC addresses in project inventory.",
            "MAC identity is required for reliable handover, reservations, and endpoint traceability.",
            "Capture MAC addresses for all listed devices and re-run validation and IP schedule export.",
            evidence_source=["devices.json"],
            affected_devices=missing_mac,
        )
    if missing_serial:
        add_rec(
            "commissioning_readiness",
            "medium",
            "Serial numbers are incomplete for handover records",
            "One or more devices are missing serial number metadata.",
            "Serial data supports warranty, support escalation, and long-term lifecycle tracking.",
            "Complete serial number fields for affected devices before final handover.",
            evidence_source=["devices.json"],
            affected_devices=missing_serial,
        )
    if missing_vlan:
        add_rec(
            "segmentation",
            "medium",
            "VLAN assignment metadata is incomplete",
            "One or more devices do not have a VLAN/zone assignment in inventory.",
            "Missing VLAN metadata reduces confidence in segmentation validation and firewall planning outputs.",
            "Assign VLAN labels to affected devices and regenerate validation and design artifacts.",
            evidence_source=["devices.json"],
            affected_devices=missing_vlan,
        )

    # 7) Low-confidence or weakly classified critical devices
    weak_type_names = []
    for row in validate_all_results:
        name = str(row.get("name") or row.get("ip") or "Unknown device").strip()
        type_name = str(row.get("type") or "").strip().lower()
        effective_type = str(row.get("effective_type") or "").strip().lower()
        confidence_score = int(row.get("confidence_score") or 0)
        confidence_label = str(row.get("confidence_label") or "").strip().lower()
        if weak_device_type(type_name) or weak_device_type(effective_type) or confidence_score < 60 or confidence_label in {"low", "none", "unknown"}:
            weak_type_names.append(name)
    if weak_type_names:
        add_rec(
            "integrity",
            "medium",
            "Device type confidence is low for key inventory rows",
            "Some devices remain weakly classified or low-confidence after validation.",
            "Weak classification reduces confidence in downstream requirements, flows, and consultant recommendations.",
            "Review affected device roles on the Devices screen and confirm final type assignments.",
            evidence_source=["validate_all.results", "devices.json"],
            affected_devices=weak_type_names,
        )

    # 1) Dante VLAN isolation + 5) Multicast policy coverage
    dante_device_names = set()
    dante_vlans = set()
    non_dante_by_vlan = {}
    for device in devices:
        name = str(device.get("name") or device.get("ip") or "").strip()
        vlan_name = str(device.get("vlan") or "").strip()
        dtype = str(device.get("type") or "").strip().lower()
        if "dante" in dtype:
            dante_device_names.add(name)
            if vlan_name:
                dante_vlans.add(vlan_name)
        elif vlan_name:
            non_dante_by_vlan.setdefault(vlan_name, set()).add(name)
    for row in validate_all_results:
        ports = [int(p) for p in (row.get("open_ports") or []) if isinstance(p, int)]
        if any(p in {319, 320, 4440} for p in ports):
            dante_device_names.add(str(row.get("name") or row.get("ip") or "").strip())

    if dante_device_names:
        mixed_vlan = any(vlan_name in non_dante_by_vlan for vlan_name in dante_vlans)
        if mixed_vlan or len(dante_vlans) != 1:
            add_rec(
                "segmentation",
                "high",
                "Dante devices should be isolated on a dedicated VLAN",
                "Dante-capable endpoints appear mixed across or within shared VLAN segments.",
                "Dante relies on predictable multicast behavior and low-latency transport; mixed segmentation increases instability risk.",
                "Move Dante endpoints to a dedicated VLAN and validate multicast/QoS policy after changes.",
                evidence_source=["devices.json", "validate_all.results"],
                affected_devices=sorted(dante_device_names),
            )
        if multicast_groups:
            add_rec(
                "multicast",
                "info",
                "Dante-capable endpoints have passive multicast evidence available",
                "Managed-switch multicast membership data is available for review alongside Dante-capable endpoints.",
                "Passive multicast evidence improves confidence when checking IGMP snooping, querier placement, and VLAN scoping.",
                "Review observed multicast groups against Dante design intent and confirm switch multicast policy remains aligned.",
                evidence_source=["validate_all.results", "devices.json", "multicast_groups.json"],
                affected_devices=sorted(dante_device_names),
            )
        else:
            add_rec(
                "multicast",
                "medium",
                "Validate multicast controls for Dante-capable endpoints",
                "Dante-capable devices were detected but passive multicast membership visibility is unavailable.",
                "Missing IGMP/multicast policy visibility can hide intermittent AV transport and clock stability issues.",
                "Confirm IGMP snooping/querier and multicast QoS policy on Dante VLANs, then generate multicast evidence from managed switches if available.",
                evidence_source=["validate_all.results", "devices.json", "multicast_groups.json"],
                affected_devices=sorted(dante_device_names),
            )

    if not multicast_groups and not multicast_generated_at:
        add_rec(
            "multicast",
            "info",
            "Managed switch multicast visibility has not been generated yet",
            "No saved multicast group snapshot is available for the current project.",
            "Without passive multicast evidence, switch-side IGMP state cannot be cross-checked against observed AV endpoints.",
            "Generate multicast group discovery from known managed switches when SNMP is available.",
            evidence_source=["multicast_groups.json"],
        )
    elif multicast_groups:
        groups_without_members = [
            str(group.get("group_address") or "").strip()
            for group in multicast_groups
            if int(group.get("member_count") or 0) <= 0
        ]
        if groups_without_members:
            add_rec(
                "multicast",
                "low",
                "Some multicast groups do not expose identifiable subscribers",
                "One or more observed multicast groups were present on managed switches without a strong subscriber identity.",
                "Groups without visible subscribers can indicate limited switch SNMP visibility or unwanted multicast publishers.",
                "Review the affected groups and confirm whether switch IGMP visibility, querier behavior, or publisher configuration needs attention.",
                evidence_source=["multicast_groups.json"],
                affected_devices=groups_without_members[:8],
            )

        if len(multicast_groups) >= 3:
            add_rec(
                "multicast",
                "low",
                "Multiple multicast groups are active on the managed switch estate",
                "Several multicast groups were observed from eligible managed switches.",
                "As multicast group count grows, querier placement, VLAN scoping, and snooping behavior become more important for stable AV transport.",
                "Confirm multicast design intent, querier placement, and VLAN boundaries against the observed group list.",
                evidence_source=["multicast_groups.json"],
            )

    # 2) DHCP reservations (explicit DHCP signal only)
    dhcp_critical = []
    critical_tokens = ("crestron", "qsys", "biamp", "dante", "barco")
    for device in devices:
        name = str(device.get("name") or device.get("ip") or "").strip()
        dtype = str(device.get("type") or "").strip().lower()
        assignment = str(device.get("addressing") or device.get("ip_assignment") or device.get("ip_mode") or "").strip().lower()
        if any(token in dtype for token in critical_tokens) and assignment in {"dhcp", "dynamic"}:
            dhcp_critical.append(name)
    if dhcp_critical:
        add_rec(
            "DHCP",
            "medium",
            "Critical AV endpoints should use controlled DHCP reservations",
            "Critical control/media endpoints are marked as dynamic DHCP clients.",
            "Dynamic addressing for core AV endpoints can break control path assumptions and increase commissioning risk.",
            "Create DHCP reservations for affected endpoints and confirm stable addressing in inventory.",
            evidence_source=["devices.json"],
            affected_devices=dhcp_critical,
        )

    # 3) VLAN fragmentation / mixed segmentation concerns
    family_to_vlans = {}
    for device in devices:
        dtype = str(device.get("type") or "").strip().lower()
        vlan_name = str(device.get("vlan") or "").strip()
        if not vlan_name:
            continue
        family = ""
        if "crestron" in dtype:
            family = "crestron"
        elif "qsys" in dtype:
            family = "qsys"
        elif "biamp" in dtype:
            family = "biamp"
        elif "barco" in dtype:
            family = "barco"
        elif "dante" in dtype:
            family = "dante"
        if family:
            family_to_vlans.setdefault(family, set()).add(vlan_name)
    for family, vlans in family_to_vlans.items():
        if len(vlans) > 2:
            family_devices = [
                str(device.get("name") or device.get("ip") or "").strip()
                for device in devices
                if family in str(device.get("type") or "").strip().lower()
            ]
            add_rec(
                "segmentation",
                "medium",
                "AV role appears fragmented across multiple VLANs",
                f"{family.upper()}-related devices appear spread across multiple VLAN segments.",
                "Over-fragmentation can complicate routing, ACL design, and troubleshooting for commissioning teams.",
                "Review segmentation intent and consolidate related AV roles where practical.",
                evidence_source=["devices.json"],
                affected_devices=family_devices,
            )

    # 4) Unvalidated control ports + 6) control-system communication concerns
    control_issue_devices = set()
    unvalidated_control_devices = set()
    for row in validate_systems_results:
        status = str(row.get("status") or "").strip().lower()
        relationship_type = str(row.get("relationship_type") or "").strip().lower()
        check_name = str(row.get("system_check") or "").strip().lower()
        from_device = str(row.get("from_device") or "").strip()
        to_device = str(row.get("to_device") or "").strip()
        required_ports = [int(p) for p in (row.get("required_target_ports") or []) if isinstance(p, int)]
        observed_ports = [int(p) for p in (row.get("observed_target_ports") or []) if isinstance(p, int)]
        missing_required = [p for p in required_ports if p not in observed_ports]

        is_control_relationship = relationship_type in {"control", "ui"} or "control" in check_name or "touchpanel" in check_name
        if is_control_relationship and status in {"warn", "fail", "skipped"}:
            if from_device:
                control_issue_devices.add(from_device)
            if to_device:
                control_issue_devices.add(to_device)
        if is_control_relationship and missing_required:
            if from_device:
                unvalidated_control_devices.add(from_device)
            if to_device:
                unvalidated_control_devices.add(to_device)

    if control_issue_devices:
        add_rec(
            "design",
            "high",
            "Control-system communication relationships require remediation",
            "One or more control/UI system relationships are unresolved or failing validation.",
            "Control-path instability directly impacts operator functionality and system coordination during commissioning.",
            "Review controller-to-endpoint pathing, ACL/firewall policy, and endpoint service readiness for affected relationships.",
            evidence_source=["validate_systems.results"],
            affected_devices=sorted(control_issue_devices),
        )
    if unvalidated_control_devices:
        add_rec(
            "design",
            "high",
            "Required control ports are not fully validated",
            "Expected control ports were not consistently observed on one or more required target relationships.",
            "Unvalidated control ports can block commissioning completion and create intermittent control failures.",
            "Verify required target ports are open and routable between intended control endpoints.",
            evidence_source=["validate_systems.results"],
            affected_devices=sorted(unvalidated_control_devices),
        )

    # 5) Barco-specific recommendation template
    barco_devices = [
        str(device.get("name") or device.get("ip") or "").strip()
        for device in devices
        if "barco" in str(device.get("type") or "").strip().lower()
        or "barco" in str(device.get("vendor") or "").strip().lower()
    ]
    if barco_devices:
        barco_concern = False
        for row in validate_systems_results:
            status = str(row.get("status") or "").strip().lower()
            names = {
                str(row.get("from_device") or "").strip(),
                str(row.get("to_device") or "").strip(),
            }
            if names.intersection(set(barco_devices)) and status in {"warn", "fail", "skipped"}:
                barco_concern = True
                break
        add_rec(
            "design",
            "medium" if barco_concern else "info",
            "Barco endpoints require explicit control and addressing review",
            "Barco endpoints were detected and should be reviewed for stable addressing and validated control pathing.",
            "Barco collaboration/video platforms are sensitive to inconsistent addressing or unresolved control/service dependencies.",
            "Confirm DHCP reservation strategy, management access policy, and required service path validation for Barco endpoints.",
            evidence_source=["devices.json", "validate_systems.results"],
            affected_devices=barco_devices,
        )

    # 9) Security-sensitive service exposure
    sensitive_exposure_devices = []
    high_risk_devices = []
    sensitive_ports = {22, 3389, 5900}
    high_risk_ports = {23}
    for row in validate_all_results:
        ports = [int(p) for p in (row.get("open_ports") or []) if isinstance(p, int)]
        name = str(row.get("name") or row.get("ip") or "").strip()
        if any(p in sensitive_ports for p in ports):
            sensitive_exposure_devices.append(name)
        if any(p in high_risk_ports for p in ports):
            high_risk_devices.append(name)
    if sensitive_exposure_devices or high_risk_devices:
        severity = "high" if high_risk_devices else "medium"
        affected = sorted(set(sensitive_exposure_devices + high_risk_devices))
        add_rec(
            "security",
            severity,
            "Review management-service exposure on AV endpoints",
            "Sensitive management/admin services were observed on one or more endpoints.",
            "Unnecessary management exposure increases security and change-control risk during production operation.",
            "Restrict management services to approved administration segments and disable unused legacy access methods.",
            evidence_source=["validate_all.results"],
            affected_devices=affected,
        )

    # Commissioning readiness from unresolved validation concerns
    unresolved = []
    for row in validate_all_results:
        status = str(row.get("overall") or "").strip().lower()
        if status in {"warn", "fail"}:
            unresolved.append(str(row.get("name") or row.get("ip") or "").strip())
    if unresolved:
        add_rec(
            "commissioning_readiness",
            "medium",
            "Project has unresolved validation findings",
            "Device-level validation still contains warnings/failures that should be closed before handover.",
            "Unresolved findings at handover increase post-commissioning support load and reduce operator trust.",
            "Prioritize failed findings, then resolve warning-level checks and re-run validation before sign-off.",
            evidence_source=["validate_all.results", "validate_systems.results"],
            affected_devices=unresolved,
        )

    normalized = []
    for item in by_key.values():
        normalized.append({
            "id": "",
            "category": item.get("category") or "commissioning_readiness",
            "severity": item.get("severity") or "info",
            "title": item.get("title") or "",
            "finding": item.get("finding") or "",
            "why_it_matters": item.get("why_it_matters") or "",
            "suggested_action": item.get("suggested_action") or "",
            "evidence_source": sorted(item.get("_evidence_source") or set()),
            "affected_devices": sorted(item.get("_affected_devices") or set()),
        })

    normalized.sort(key=_recommendation_sort_key)
    for idx, row in enumerate(normalized, start=1):
        row["id"] = f"REC-{idx:03d}"

    by_severity = {"high": 0, "medium": 0, "low": 0, "info": 0}
    by_category = {
        "integrity": 0,
        "design": 0,
        "segmentation": 0,
        "DHCP": 0,
        "multicast": 0,
        "security": 0,
        "commissioning_readiness": 0,
    }
    for row in normalized:
        severity = str(row.get("severity") or "").strip().lower()
        category = str(row.get("category") or "").strip()
        if severity in by_severity:
            by_severity[severity] += 1
        if category in by_category:
            by_category[category] += 1

    return {
        "recommendations": normalized,
        "summary": {
            "total": len(normalized),
            "by_severity": by_severity,
            "by_category": by_category,
        },
    }


def _normalize_validation_status(value):
    token = str(value or "").strip().lower()
    if token in {"pass", "ok"}:
        return "pass"
    if token in {"warn", "warning", "info"}:
        return "warn"
    if token in {"fail", "error"}:
        return "fail"
    return "unknown"


def _summarize_validation_results(validate_all_payload):
    summary = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}
    rows = _extract_results_from_payload(validate_all_payload)
    for row in rows:
        status = _normalize_validation_status((row or {}).get("overall"))
        if status in summary:
            summary[status] += 1
    return summary


def _build_requirements_payload_for_report(payload, devices):
    payload = payload if isinstance(payload, dict) else {}
    requirements_payload = payload.get("requirements")
    if isinstance(requirements_payload, dict) and isinstance(requirements_payload.get("results"), list):
        return requirements_payload

    vlan = str(payload.get("vlan") or "").strip()
    selected_devices = list(devices or [])
    if vlan:
        selected_devices = [d for d in selected_devices if str(d.get("vlan") or "").strip() == vlan]

    config = load_requirements_config()
    enriched_devices = [enrich_device_runtime(device) for device in selected_devices]

    results = []
    unmapped = []
    mapped_count = 0
    types_seen = set()
    for device in enriched_devices:
        requirement_row = generate_device_requirements(device, config)
        results.append(requirement_row)

        effective_type = str(requirement_row.get("effective_type") or "").strip().lower()
        if effective_type:
            types_seen.add(effective_type)

        if requirement_row.get("required_ports"):
            mapped_count += 1
        else:
            unmapped.append({
                "device_id": requirement_row.get("device_id") or "",
                "type": effective_type or "unknown",
            })

    return {
        "ok": True,
        "count": len(results),
        "summary": {
            "mapped": mapped_count,
            "unmapped": len(unmapped),
            "types_seen": len(types_seen),
        },
        "results": results,
        "unmapped": unmapped,
    }


def _build_report_sections(payload, context, requirements, ipschedule, recommendations):
    settings = load_settings()
    validate_all = context.get("validate_all") or {}
    validate_systems = context.get("validate_systems") or {}
    system_requirements = context.get("system_requirements") or {}
    firewall_plan = context.get("firewall_plan") or {}

    validate_all_results = _extract_results_from_payload(validate_all)
    validate_systems_results = _extract_results_from_payload(validate_systems)
    connectivity_results = list((validate_systems or {}).get("connectivity") or [])
    requirements_results = _extract_results_from_payload(requirements)
    system_requirement_rows = _extract_results_from_payload(system_requirements)
    firewall_rules = list((firewall_plan or {}).get("rules") or [])
    schedule_rows = list((ipschedule or {}).get("devices") or [])
    recommendation_rows = list((recommendations or {}).get("recommendations") or [])
    recommendation_summary = (recommendations or {}).get("summary") or {}

    validation_summary = _summarize_validation_results(validate_all)
    unresolved_systems = 0
    for row in validate_systems_results:
        state = _normalize_validation_status((row or {}).get("status"))
        if state in {"warn", "fail", "unknown"}:
            unresolved_systems += 1
    connectivity_summary = (validate_systems or {}).get("connectivity_summary") or {}
    connectivity_concerns = int(connectivity_summary.get("fail") or 0) + int(connectivity_summary.get("warn") or 0)

    requirements_category_breakdown = {
        "control": 0,
        "media": 0,
        "service": 0,
        "management": 0,
        "unknown": 0,
    }
    for system_row in system_requirement_rows:
        categories = (system_row or {}).get("categories") or {}
        if not isinstance(categories, dict):
            continue
        for key in requirements_category_breakdown:
            entries = categories.get(key) or []
            if isinstance(entries, list):
                requirements_category_breakdown[key] += len(entries)

    firewall_summary = (firewall_plan or {}).get("summary") or {}
    schedule_missing_mac = 0
    schedule_missing_serial = 0
    schedule_missing_vlan = 0
    schedule_manual_overrides = 0
    for row in schedule_rows:
        if not str((row or {}).get("mac") or (row or {}).get("mac_address") or "").strip():
            schedule_missing_mac += 1
        if not str((row or {}).get("serial") or (row or {}).get("serial_number") or "").strip():
            schedule_missing_serial += 1
        if not str((row or {}).get("vlan") or "").strip():
            schedule_missing_vlan += 1
        if (row or {}).get("manual_override") or (row or {}).get("is_manual"):
            schedule_manual_overrides += 1

    top_high_recommendations = [
        {
            "id": row.get("id") or "",
            "title": row.get("title") or "",
            "category": row.get("category") or "",
            "severity": row.get("severity") or "",
        }
        for row in recommendation_rows
        if str((row or {}).get("severity") or "").strip().lower() == "high"
    ][:5]

    outstanding_risks = []
    for row in recommendation_rows:
        severity = str((row or {}).get("severity") or "").strip().lower()
        if severity == "high":
            outstanding_risks.append(str((row or {}).get("title") or "High-severity recommendation").strip())
    if not outstanding_risks and (validation_summary["fail"] > 0 or unresolved_systems > 0):
        outstanding_risks.append("Validation failures remain unresolved.")
    if not outstanding_risks:
        outstanding_risks.append("No critical unresolved risks detected from current evidence.")
    outstanding_risks = outstanding_risks[:8]

    suggested_next_actions = []
    for row in recommendation_rows:
        action = str((row or {}).get("suggested_action") or "").strip()
        if action and action not in suggested_next_actions:
            suggested_next_actions.append(action)
    if not suggested_next_actions:
        suggested_next_actions = [
            "Review current validation scope and rerun validation after inventory updates.",
            "Confirm firewall rules and IP schedule against the latest project state before handover.",
        ]
    suggested_next_actions = suggested_next_actions[:8]

    total_devices = len(schedule_rows) if schedule_rows else len(context.get("devices") or [])
    system_groups = int((validate_systems or {}).get("count") or 0)
    overall_attention = (
        validation_summary["fail"]
        + validation_summary["warn"]
        + unresolved_systems
        + connectivity_concerns
        + int(recommendation_summary.get("total") or 0)
    )
    readiness = "ready"
    if validation_summary["fail"] > 0 or any(
        str((row or {}).get("severity") or "").strip().lower() == "high" for row in recommendation_rows
    ):
        readiness = "action_required"
    elif validation_summary["warn"] > 0 or unresolved_systems > 0:
        readiness = "ready_with_warnings"

    return {
        "project_summary": {
            "project_name": str(settings.get("project_name") or "NetPi Project").strip() or "NetPi Project",
            "generated_at": datetime.now().isoformat(),
            "total_devices": total_devices,
            "systems_count": system_groups,
            "overall_attention_items": overall_attention,
            "readiness": readiness,
        },
        "validation_summary": {
            "count": int((validate_all or {}).get("count") or len(validate_all_results)),
            "by_status": validation_summary,
            "system_unresolved": unresolved_systems,
            "connectivity_concerns": connectivity_concerns,
            "connectivity_note": str((validate_systems or {}).get("connectivity_note") or "").strip(),
        },
        "requirements_summary": {
            "count": int((system_requirements or {}).get("count") or len(system_requirement_rows)),
            "device_requirements_count": int((requirements or {}).get("count") or len(requirements_results)),
            "category_breakdown": requirements_category_breakdown,
            "unmapped_devices": int(((requirements or {}).get("summary") or {}).get("unmapped") or 0),
        },
        "firewall_plan_summary": {
            "total_rules": int(firewall_summary.get("total_rules") or len(firewall_rules)),
            "min_required_rules": int(firewall_summary.get("min_required_rules") or 0),
            "recommended_rules": int(firewall_summary.get("recommended_rules") or 0),
            "zones": list(firewall_summary.get("zones") or []),
            "top_rule_pairs": [
                {
                    "source_zone": row.get("source_zone") or "Unknown",
                    "destination_zone": row.get("destination_zone") or "Unknown",
                    "protocol": row.get("protocol") or "TCP",
                    "port": row.get("port"),
                    "requirement_level": row.get("requirement_level") or "recommended",
                }
                for row in firewall_rules[:10]
            ],
        },
        "ip_schedule_summary": {
            "count": int((ipschedule or {}).get("count") or len(schedule_rows)),
            "missing_mac": schedule_missing_mac,
            "missing_serial": schedule_missing_serial,
            "missing_vlan": schedule_missing_vlan,
            "manual_overrides": schedule_manual_overrides,
        },
        "recommendations_summary": {
            "total": int(recommendation_summary.get("total") or len(recommendation_rows)),
            "by_severity": recommendation_summary.get("by_severity") or {},
            "by_category": recommendation_summary.get("by_category") or {},
            "top_high_priority": top_high_recommendations,
        },
        "outstanding_risks": outstanding_risks,
        "suggested_next_actions": suggested_next_actions,
    }


def _build_report_payload(payload):
    payload = payload if isinstance(payload, dict) else {}
    context = _build_recommendation_context(payload)
    devices = list(context.get("devices") or [])
    requirements = _build_requirements_payload_for_report(payload, devices)

    ipschedule = payload.get("ipschedule")
    if not (isinstance(ipschedule, dict) and isinstance(ipschedule.get("devices"), list)):
        schedule_rows = _devices_with_freshness_view(devices if devices else load_devices())
        ipschedule = {
            "ok": True,
            "count": len(schedule_rows),
            "devices": schedule_rows,
        }

    recommendations_payload = payload.get("recommendations")
    if isinstance(recommendations_payload, dict) and isinstance(recommendations_payload.get("recommendations"), list):
        recommendations = recommendations_payload
    else:
        rec_result = _build_recommendations(context)
        recommendations = {
            "ok": True,
            "recommendations": rec_result.get("recommendations") or [],
            "summary": rec_result.get("summary") or {},
        }

    sections = _build_report_sections(payload, context, requirements, ipschedule, recommendations)
    project_summary = sections.get("project_summary") or {}
    settings = load_settings()

    report = {
        "generated_at": project_summary.get("generated_at") or datetime.now().isoformat(),
        "project_name": project_summary.get("project_name") or str(settings.get("project_name") or "NetPi Project"),
        "summary": project_summary,
        "sections": sections,
    }
    report["html"] = render_template("report.html", report=report, s=settings)
    return report


@app.route("/tools/report")
def tools_report():
    try:
        payload = {}
        vlan = str(request.args.get("vlan") or "").strip()
        if vlan:
            payload["vlan"] = vlan
        report = _build_report_payload(payload)
        return report.get("html") or "", 200, {"Content-Type": "text/html; charset=utf-8"}
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/generate_report", methods=["POST"])
def api_generate_report():
    try:
        payload = request.get_json(silent=True) or {}
        report = _build_report_payload(payload)
        return jsonify({
            "ok": True,
            "report": report,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/system_requirements", methods=["POST"])
def api_system_requirements():
    try:
        payload = request.get_json(silent=True) or {}
        result = _build_system_requirements_payload(payload)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/recommendations", methods=["POST"])
def api_recommendations():
    try:
        payload = request.get_json(silent=True) or {}
        context = _build_recommendation_context(payload)
        result = _build_recommendations(context)
        return jsonify({
            "ok": True,
            "recommendations": result.get("recommendations") or [],
            "summary": result.get("summary") or {},
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500


@app.route("/tools/api/generate_firewall_plan", methods=["POST"])
def api_generate_firewall_plan():
    try:
        payload = request.get_json(silent=True)
        if isinstance(payload, list):
            payload = {"results": payload}
        payload = payload if isinstance(payload, dict) else {}

        wrapper = payload.get("system_requirements")
        system_rows = []
        if isinstance(wrapper, dict) and _looks_like_system_requirement_rows(wrapper.get("results")):
            system_rows = wrapper.get("results") or []
        elif _looks_like_system_requirement_rows(payload.get("results")):
            system_rows = payload.get("results") or []
        else:
            built = _build_system_requirements_payload(payload)
            system_rows = built.get("results") or []

        firewall_plan = _compose_firewall_plan(system_rows, settings=load_settings())
        return jsonify({
            "ok": True,
            "firewall_plan": firewall_plan,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)


