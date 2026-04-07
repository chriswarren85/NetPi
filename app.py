from flask import Flask, render_template, request, jsonify, redirect, send_file
import json, os, subprocess, csv
from datetime import datetime
import copy
import socket
import threading
import uuid
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
)

app = Flask(__name__)
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
DEVICES_FILE  = os.path.join(os.path.dirname(__file__), 'devices.json')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
FINGERPRINTS_FILE = os.path.join(DATA_DIR, 'fingerprints.json')
DEVICE_EVIDENCE_FILE = os.path.join(DATA_DIR, 'device_evidence.json')
BACKGROUND_JOBS = {}
BACKGROUND_JOBS_LOCK = threading.Lock()
DEVICE_EVIDENCE_LOCK = threading.Lock()

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
        try:
            process.terminate()
        except Exception:
            pass

    return _snapshot_background_job(_get_background_job(job_id))


def _create_discovery_job(subnet):
    return _create_background_job(
        "discover_hosts",
        message=_discovery_status_message("queued", 0, subnet),
        progress={"devices_found_count": 0},
        results={
            "devices": [],
            "subnet": subnet
        },
        cancel_requested=False,
        process=None
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
        devices.append(device)
        count = len(devices)
        job.setdefault("progress", {})["devices_found_count"] = count
        subnet = results.get("subnet") or ""
        job["message"] = _discovery_status_message(job.get("status"), count, subnet)

    return _update_background_job(job_id, mutate_fn=mutate)


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

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "guessed_type": guess_type_from_vendor(vendor),
        "status": "online"
    }


def _discover_hosts_for_subnet(subnet, job_id=None):
    devices = []
    process = subprocess.Popen(
        ['sudo', 'nmap', '-sn', '--open', subnet, '-oG', '-'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    if job_id:
        _update_background_job(job_id, process=process)

    try:
        for raw_line in iter(process.stdout.readline, ''):
            if job_id:
                job = _get_discovery_job(job_id)
                if not job:
                    break
                if job.get("cancel_requested"):
                    try:
                        process.terminate()
                    except Exception:
                        pass
                    break

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
                return devices

        if returncode != 0:
            raise RuntimeError(stderr_output or f"nmap exited with status {returncode}")

        return devices
    finally:
        if job_id:
            _update_background_job(job_id, process=None)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def _run_discovery_job(job_id):
    job = _get_discovery_job(job_id)
    if not job:
        return

    subnet = ((job.get("results") or {}).get("subnet") or "")
    _update_background_job(
        job_id,
        status="running",
        message=_discovery_status_message("running", 0, subnet),
        error=""
    )

    try:
        devices = _discover_hosts_for_subnet(subnet, job_id=job_id)
        final_job = _get_discovery_job(job_id)
        if final_job and final_job.get("status") != "cancelled":
            _update_background_job(
                job_id,
                status="completed",
                message=_discovery_status_message("completed", len(devices), subnet),
                error=""
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


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {}
    with open(SETTINGS_FILE) as f:
        return json.load(f)


def save_settings(data):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


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
            normalized.append(assign_inferred_vlan(device, settings=settings))
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


def load_devices():
    if not os.path.exists(DEVICES_FILE):
        return []

    try:
        with open(DEVICES_FILE) as f:
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


def save_devices_file(devices):
    with open(DEVICES_FILE, 'w') as f:
        json.dump({'devices': devices}, f, indent=2)


def load_fingerprints():
    if not os.path.exists(FINGERPRINTS_FILE):
        return {}

    try:
        with open(FINGERPRINTS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_fingerprints(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(FINGERPRINTS_FILE, 'w') as f:
        json.dump(data or {}, f, indent=2, sort_keys=True)


def load_device_evidence():
    if not os.path.exists(DEVICE_EVIDENCE_FILE):
        return {}

    try:
        with open(DEVICE_EVIDENCE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_device_evidence(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(DEVICE_EVIDENCE_FILE, 'w') as f:
        json.dump(data or {}, f, indent=2, sort_keys=True)


def _fingerprint_confidence_rank(value):
    return {
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get((value or "").strip().lower(), 0)


def _normalize_identity_mac(value):
    mac = (value or "").strip().upper()
    if not mac or mac in ("—", "-", "UNKNOWN"):
        return ""
    return mac


def _normalize_identity_hostname(value):
    hostname = re.sub(r"[\s\.,;:]+$", "", str(value or "").strip())
    lowered = hostname.lower()
    if not hostname or lowered in ("unknown", "n/a", "none", "-", "—"):
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

    if candidate_mac and candidate_mac not in ("—", "-", "unknown"):
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
    runs_dir = os.path.join(os.path.dirname(__file__), 'runs')
    os.makedirs(runs_dir, exist_ok=True)

    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    path = os.path.join(runs_dir, f'{ts}.json')

    with open(path, 'w') as f:
        json.dump(results, f, indent=2)

    return path



# ── Pages ──────────────────────────────────────────────

@app.route('/tools/')
@app.route('/tools')
def index():
    return redirect('/tools/diagnostics')


@app.route('/tools/diagnostics')
def diagnostics():
    return render_template('diagnostics.html', s=load_settings())


@app.route('/tools/devices')
def devices():
    return render_template('devices.html', s=load_settings(), devices=load_devices())


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

        for i in range(len(names)):
            dt_raw = request.form.get(f'device_types_{i}[]', '')
            dt = [x.strip() for x in dt_raw.split(',') if x.strip()]
            vlans.append({
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

        s['vlans'] = vlans
        save_settings(s)
        saved = True

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


# ── API ────────────────────────────────────────────────



# --- Validation API (NetPi V3) ---
# =========================
# NetPi V5 — Auto Typing Helpers
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

        devices = load_devices()
        if vlan:
            devices = [device for device in devices if str(device.get("vlan") or "").strip() == vlan]
        results = run_validation_for_all(devices)
        fingerprint_updates = []

        for device, result in zip(devices, results):
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
        name += ' — ' + s['job_number']
    return jsonify({'name': name or ''})


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
    runs_dir = os.path.join(os.path.dirname(__file__), 'runs')
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
    runs_dir = os.path.join(os.path.dirname(__file__), 'runs')
    files = sorted([f for f in os.listdir(runs_dir) if f.endswith('.csv')], reverse=True)
    if not files:
        return jsonify({"error": "no csv runs found"}), 404

    latest = os.path.join(runs_dir, files[0])
    return send_file(latest, as_attachment=True)


@app.route("/tools/api/discover_hosts", methods=["POST"])
def discover_hosts():
    s = load_settings()
    data = request.json or {}
    subnet = resolve_selected_subnet(s, data.get("vlan"))

    if not subnet:
        return jsonify({"error": "No subnet available"}), 400

    try:
        devices = _discover_hosts_for_subnet(subnet)

        return jsonify({
            "subnet": subnet,
            "count": len(devices),
            "devices": devices
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tools/api/discover_hosts/start", methods=["POST"])
def start_discover_hosts():
    s = load_settings()
    data = request.json or {}
    subnet = resolve_selected_subnet(s, data.get("vlan"))

    if not subnet:
        return jsonify({"error": "No subnet available"}), 400

    job = _create_discovery_job(subnet)
    _start_background_job(_run_discovery_job, job["job_id"])

    return jsonify(job), 202


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

        type_suggestion = build_type_suggestion(updated_device or device, validation)
        promotion = evaluate_safe_type_promotion(updated_device or device, type_suggestion)
        if matched_inventory_device is not None and promotion.get("should_apply"):
            matched_inventory_device["type"] = promotion.get("suggested_type") or matched_inventory_device.get("type") or ""
            updated_device = dict(matched_inventory_device)
            device_updated = True
        effective_type = resolve_effective_type(updated_device or device, guessed, type_suggestion, validation)

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

        if any(existing.get("ip") == ip for existing in devices):
            skipped_existing += 1
            continue

        device_type = (normalized.get("type") or "generic").strip() or "generic"
        preferred_name = (normalized.get("name") or normalized.get("hostname") or "").strip()
        vendor = (normalized.get("vendor") or "").strip()
        notes = (normalized.get("notes") or "").strip()
        generated_name = generate_device_name(devices, device_type, preferred_name)

        devices.append({
            "name": generated_name,
            "ip": ip,
            "type": device_type,
            "vlan": (normalized.get("vlan") or "").strip(),
            "notes": notes or (f"Auto-discovered ({vendor})" if vendor else "Auto-discovered"),
            "mac": (normalized.get("mac") or "").strip(),
            "vendor": vendor
        })
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

    if any(d.get("ip") == ip for d in devices):
        return jsonify({"success": True, "message": "Device already exists"})

    normalized = assign_inferred_vlan(data, settings=load_settings())
    vlan = (normalized.get("vlan") or "").strip()
    name = generate_device_name(devices, device_type, hostname)

    devices.append({
        "name": name,
        "ip": ip,
        "type": device_type,
        "vlan": vlan,
        "notes": f"Auto-discovered ({vendor})" if vendor else "Auto-discovered",
        "mac": mac,
        "vendor": vendor
    })

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
    runs_dir = os.path.join(os.path.dirname(__file__), 'runs')
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
    normalized_devices = normalize_devices_for_save(devices, settings=load_settings())
    save_devices_file(normalized_devices)
    return jsonify({'success': True, 'devices': normalized_devices})


@app.route('/tools/api/scan', methods=['POST'])
def api_scan():
    subnet = request.json.get('subnet')
    if not subnet:
        return jsonify({'error': 'No subnet'}), 400

    try:
        result = subprocess.check_output(
            ['sudo', 'nmap', '-sn', '--open', subnet, '--oG', '-'],
            timeout=90
        ).decode()

        devices = []
        for line in result.splitlines():
            if 'Host:' in line:
                p = line.split()
                ip = p[1]
                hostname = p[2].strip('()') if len(p) > 2 else ''
                devices.append({'ip': ip, 'hostname': hostname, 'status': 'online'})

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
            ['ping', '-c', '4', host],
            timeout=15,
            stderr=subprocess.STDOUT
        ).decode()
        return jsonify({'output': out})
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output.decode(), 'error': 'Host unreachable'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/portscan', methods=['POST'])
def api_portscan():
    host = request.json.get('host')
    if not host:
        return jsonify({'error': 'No host'}), 400

    try:
        out = subprocess.check_output(['sudo', 'nmap', '-F', host], timeout=60).decode()
        return jsonify({'output': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/tools/api/traceroute', methods=['POST'])
def api_traceroute():
    host = request.json.get('host')
    if not host:
        return jsonify({'error': 'No host'}), 400

    try:
        out = subprocess.check_output(['traceroute', '-m', '15', host], timeout=30).decode()
        return jsonify({'output': out})
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
# NetPi V5 — System Graph Builder
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
                    summary_parts.append(f'{e["from"]} → {e["to"]} ({e["type"]})')
                summary_chain = " | ".join(summary_parts)
            else:
                summary_chain = " → ".join(names)

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
                f'{e["from"]} → {e["to"]} ({e["type"]})'
                for e in comp_edges
            )
        else:
            summary_chain = " → ".join(comp_list)

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

        with open(DEVICES_FILE, "w") as f:
            json.dump(devices, f, indent=2)

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
            devices = load_devices()

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
                "connectivity": [],
                "connectivity_summary": connectivity_summary,
                "connectivity_note": connectivity_note,
                "detected_systems": detected,
            })

        enriched_devices = [enrich_device_runtime(device) for device in devices]
        validations_by_ip = {}
        fingerprint_updates = []

        for device, item in zip(devices, enriched_devices):
            result = dict(item.get("_validation_result") or {})
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

        system_groups = build_runtime_system_groups(enriched_devices)
        results = run_system_validation(enriched_devices, validations_by_ip)
        system_group_results = build_system_group_results(system_groups, results)
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

        return jsonify({
            "ok": True,
            "count": len(results),
            "results": results,
            "system_groups": system_groups,
            "system_group_results": system_group_results,
            "connectivity": connectivity_results,
            "connectivity_summary": connectivity_summary,
            "connectivity_note": connectivity_note,
            "detected_systems": detected,
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
