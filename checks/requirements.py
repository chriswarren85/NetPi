import copy
import json
import os


REQUIREMENTS_CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "configs",
    "type_requirements.json",
)


def load_requirements_config():
    default_config = {"aliases": {}, "types": {}}
    try:
        with open(REQUIREMENTS_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return default_config
        aliases = data.get("aliases") if isinstance(data.get("aliases"), dict) else {}
        types = data.get("types") if isinstance(data.get("types"), dict) else {}
        return {"aliases": aliases, "types": types}
    except Exception:
        return default_config


def _normalize_token(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def _as_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def normalize_requirement_type(device_type, config):
    normalized = _normalize_token(device_type)
    aliases = config.get("aliases") if isinstance(config, dict) else {}
    aliases = aliases if isinstance(aliases, dict) else {}
    return _normalize_token(aliases.get(normalized, normalized))


def resolve_runtime_typing(device):
    item = device if isinstance(device, dict) else {}
    candidates = [
        ("effective_type", item.get("effective_type")),
        ("_resolved_type", item.get("_resolved_type")),
        ("suggested_type", item.get("suggested_type")),
        ("type", item.get("type")),
    ]
    for source, raw_value in candidates:
        value = _normalize_token(raw_value)
        if value:
            return value, source
    return "unknown", "none"


def resolve_vlan_zone(vlan_id, settings):
    """Map a VLAN ID string to a zone label using settings.json vlans list.

    Looks up the vlan entry where vlan_id matches and returns its name.
    Falls back to 'VLAN {vlan_id}' if not found.
    Returns empty string if vlan_id is blank.
    """
    vlan_id_str = str(vlan_id or "").strip()
    if not vlan_id_str:
        return ""
    vlans = (settings or {}).get("vlans") or []
    for vlan in vlans:
        if not isinstance(vlan, dict):
            continue
        entry_vlan_id = str(vlan.get("vlan_id") or "").strip()
        if entry_vlan_id and entry_vlan_id == vlan_id_str:
            name = str(vlan.get("name") or "").strip()
            if name:
                return name
    return f"VLAN {vlan_id_str}"


def _parse_required_ports(raw_ports):
    """Parse required_ports from type config, preserving both old and new field schemas."""
    parsed = []
    for entry in _as_list(raw_ports):
        if not isinstance(entry, dict):
            continue
        protocol = _normalize_token(entry.get("protocol")) or "tcp"
        raw_port = entry.get("port")
        if isinstance(raw_port, str) and raw_port.isdigit():
            raw_port = int(raw_port)
        if not isinstance(raw_port, int):
            continue

        # Old fields (backward compat)
        service = str(entry.get("service") or "").strip()
        required = bool(entry.get("required", True))

        # New fields
        direction = str(entry.get("direction") or "bidirectional").strip().lower()
        if direction not in ("inbound", "outbound", "bidirectional"):
            direction = "bidirectional"

        # Purpose: prefer explicit "purpose", fall back to "service"
        purpose = str(entry.get("purpose") or service or "").strip()

        req_level = str(entry.get("requirement_level") or "").strip().lower()
        if req_level not in ("min_required", "recommended"):
            # Derive from legacy "required" bool if new field absent
            req_level = "min_required" if required else "recommended"

        parsed.append({
            "protocol": protocol,
            "port": raw_port,
            "service": service,
            "required": required,
            "direction": direction,
            "purpose": purpose,
            "requirement_level": req_level,
        })
    return parsed


def generate_device_requirements(device, config, settings=None):
    """Generate structured network requirements for a single device.

    Parameters
    ----------
    device : dict   The device record (enriched or raw).
    config : dict   Loaded type_requirements.json content.
    settings : dict Optional settings.json content for zone resolution.

    Returns a dict with all original fields plus new structured fields.
    Does NOT remove any previously returned field.
    """
    item = copy.deepcopy(device if isinstance(device, dict) else {})
    source_type = _normalize_token(item.get("type"))
    resolved_type, derived_from = resolve_runtime_typing(item)
    normalized_type = normalize_requirement_type(resolved_type, config)

    type_map = config.get("types") if isinstance(config, dict) else {}
    type_map = type_map if isinstance(type_map, dict) else {}
    mapping = type_map.get(normalized_type) if normalized_type else None
    mapping = mapping if isinstance(mapping, dict) else {}

    required_ports = _parse_required_ports(mapping.get("required_ports"))
    required_services = [
        str(service).strip()
        for service in _as_list(mapping.get("required_services"))
        if str(service).strip()
    ]
    # Notes: support both list and string in config
    raw_notes = mapping.get("notes") or []
    if isinstance(raw_notes, str):
        raw_notes = [raw_notes]
    notes = [str(note).strip() for note in _as_list(raw_notes) if str(note).strip()]

    device_id = (
        str(item.get("mac") or "").strip()
        or str(item.get("ip") or "").strip()
        or str(item.get("name") or "").strip()
        or "unknown"
    )

    confidence_score = item.get("confidence_score")
    if isinstance(item.get("type_suggestion"), dict):
        confidence_score = item.get("type_suggestion", {}).get("confidence_score", confidence_score)
    if not isinstance(confidence_score, int):
        if isinstance(confidence_score, str) and confidence_score.isdigit():
            confidence_score = int(confidence_score)
        else:
            confidence_score = 0

    # New fields from expanded config
    multicast_required = bool(mapping.get("multicast_required", False))
    igmp_required = bool(mapping.get("igmp_required", False))
    vlan_recommendation = str(mapping.get("vlan_recommendation") or "").strip()
    av_justification = str(mapping.get("av_justification") or "").strip()
    display_name = str(mapping.get("display_name") or "").strip()

    # Zone resolution from VLAN field using settings
    vlan_id = str(item.get("vlan") or "").strip()
    zone = resolve_vlan_zone(vlan_id, settings) if settings else (
        f"VLAN {vlan_id}" if vlan_id else ""
    )

    port_count = len(required_ports)
    has_requirements = port_count > 0 or bool(required_services)

    return {
        # --- Original fields (preserved) ---
        "device_id": device_id,
        "name": str(item.get("name") or "").strip(),
        "ip": str(item.get("ip") or "").strip(),
        "effective_type": normalized_type or resolved_type or "unknown",
        "source_type": source_type,
        "confidence_score": confidence_score,
        "derived_from": derived_from,
        "required_ports": required_ports,
        "required_services": required_services,
        "notes": notes,
        # --- New fields (additive) ---
        "display_name": display_name,
        "vlan": vlan_id,
        "zone": zone,
        "multicast_required": multicast_required,
        "igmp_required": igmp_required,
        "vlan_recommendation": vlan_recommendation,
        "av_justification": av_justification,
        "port_count": port_count,
        "has_requirements": has_requirements,
    }
