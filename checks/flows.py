def build_flow_id(src_type, src_ip, dst_type, dst_ip, protocol, port):
    src_type_token = str(src_type or "unknown").strip().lower().replace(" ", "-")
    dst_type_token = str(dst_type or "unknown").strip().lower().replace(" ", "-")
    src_ip_token = str(src_ip or "na").strip().replace(".", "_")
    dst_ip_token = str(dst_ip or "na").strip().replace(".", "_")
    protocol_token = str(protocol or "tcp").strip().lower()
    port_token = str(port if port is not None else "na").strip()
    return f"{src_type_token}_{src_ip_token}__to__{dst_type_token}_{dst_ip_token}__{protocol_token}_{port_token}"


def normalize_flow_category(relationship_type="", fallback_category=""):
    rel = str(relationship_type or "").strip().lower()
    fallback = str(fallback_category or "").strip().lower()

    if rel in ("control", "ui"):
        return "control"
    if rel in ("media_flow", "media"):
        return "media"
    if rel in ("management", "mgmt"):
        return "management"
    if rel in ("service",):
        return "service"
    if rel == "peer":
        return "management"

    if fallback:
        if "control" in fallback:
            return "control"
        if "media" in fallback or "stream" in fallback:
            return "media"
        if "service" in fallback:
            return "service"
        if "manage" in fallback:
            return "management"
        return fallback

    return "unknown"


def status_to_confidence(status):
    value = str(status or "").strip().lower()
    if value == "pass":
        return 85
    if value == "info":
        return 75
    if value == "warn":
        return 65
    if value == "fail":
        return 45
    if value == "skipped":
        return 30
    return 40


def infer_protocol(protocol="", ports=None):
    value = str(protocol or "").strip().lower()
    if value:
        if value in ("udp", "tcp", "icmp"):
            return value
        if value == "dns":
            return "udp"
        if value == "ntp":
            return "udp"
        return "tcp"

    known_ports = set(int(p) for p in (ports or []) if isinstance(p, int))
    if 53 in known_ports or 123 in known_ports:
        return "udp"
    return "tcp"


def _system_id_for_flow(src_ip, dst_ip, ip_to_system_id):
    src_group = str((ip_to_system_id or {}).get(str(src_ip or "").strip(), "")).strip()
    dst_group = str((ip_to_system_id or {}).get(str(dst_ip or "").strip(), "")).strip()

    if src_group and dst_group:
        if src_group == dst_group:
            return src_group
        return f"{src_group}->{dst_group}"
    if src_group:
        return src_group
    if dst_group:
        return dst_group
    return ""


def _purpose_from_system_result(row, category):
    source_name = row.get("from_device") or "source"
    target_name = row.get("to_device") or "target"
    rel = str(row.get("relationship_type") or "").strip().lower()
    if rel in ("control", "ui"):
        return f"{source_name} to {target_name} control"
    if rel in ("media_flow", "media"):
        return f"{source_name} to {target_name} media flow"
    if category == "management":
        return f"{source_name} to {target_name} management"
    return f"{source_name} to {target_name} network flow"


def _collect_notes(row):
    notes = []
    inference = str(row.get("inference") or "").strip()
    if inference:
        notes.append(inference)
    reasons = row.get("reasons")
    if isinstance(reasons, list) and reasons:
        notes.extend(str(item).strip() for item in reasons if str(item).strip())
    return notes


def generate_flows_from_system_results(system_results, ip_to_system_id=None, ip_to_device=None):
    flows = []
    unmapped = []
    relationship_types = set()

    for row in (system_results or []):
        if not isinstance(row, dict):
            continue

        relationship_type = str(row.get("relationship_type") or "").strip().lower()
        if relationship_type:
            relationship_types.add(relationship_type)

        ports = row.get("required_target_ports")
        ports = [int(p) for p in (ports or []) if isinstance(p, int)]
        src_ip = str(row.get("from_ip") or "").strip()
        dst_ip = str(row.get("to_ip") or "").strip()
        src_name = str(row.get("from_device") or "").strip()
        dst_name = str(row.get("to_device") or "").strip()
        src_type = str(row.get("from_type") or "").strip()
        dst_type = str(row.get("to_type") or "").strip()
        status = str(row.get("status") or "").strip().lower()

        if (not src_name and src_ip and isinstance(ip_to_device, dict)):
            src_name = str(((ip_to_device.get(src_ip) or {}).get("name") or "")).strip()
        if (not dst_name and dst_ip and isinstance(ip_to_device, dict)):
            dst_name = str(((ip_to_device.get(dst_ip) or {}).get("name") or "")).strip()
        if (not src_type and src_ip and isinstance(ip_to_device, dict)):
            src_type = str(((ip_to_device.get(src_ip) or {}).get("type") or "")).strip()
        if (not dst_type and dst_ip and isinstance(ip_to_device, dict)):
            dst_type = str(((ip_to_device.get(dst_ip) or {}).get("type") or "")).strip()

        if status == "skipped" and not (src_ip and dst_ip):
            unmapped.append({
                "source": "system_results",
                "relationship_type": relationship_type or "unknown",
                "system_check": row.get("system_check") or "",
                "reason": "Skipped relationship has no concrete source/destination endpoints",
                "status": status,
                "from_device": src_name or "",
                "to_device": dst_name or "",
            })
            continue

        if not (src_ip or src_name) or not (dst_ip or dst_name):
            unmapped.append({
                "source": "system_results",
                "relationship_type": relationship_type or "unknown",
                "system_check": row.get("system_check") or "",
                "reason": "Relationship missing concrete source or destination",
                "status": status or "unknown",
                "from_device": src_name or "",
                "to_device": dst_name or "",
            })
            continue

        if not ports:
            unmapped.append({
                "source": "system_results",
                "relationship_type": relationship_type or "unknown",
                "system_check": row.get("system_check") or "",
                "reason": "No required_target_ports available for flow expansion",
                "status": status or "unknown",
                "from_device": src_name or "",
                "to_device": dst_name or "",
            })
            continue

        for port in ports:
            protocol = infer_protocol("", [port])
            category = normalize_flow_category(relationship_type, "")
            flow = {
                "flow_id": build_flow_id(src_type, src_ip, dst_type, dst_ip, protocol, port),
                "src_device": src_name or src_ip or "Unknown source",
                "src_ip": src_ip,
                "src_type": src_type or "unknown",
                "dst_device": dst_name or dst_ip or "Unknown destination",
                "dst_ip": dst_ip,
                "dst_type": dst_type or "unknown",
                "protocol": protocol,
                "port": port,
                "direction": "src_to_dst",
                "category": category,
                "purpose": _purpose_from_system_result(row, category),
                "confidence": status_to_confidence(status),
                "derived_from": {
                    "relationship_type": relationship_type or "unknown",
                    "source": "validate_systems.results",
                    "system_check": row.get("system_check") or "",
                    "status": status or "unknown",
                },
                "system_id": _system_id_for_flow(src_ip, dst_ip, ip_to_system_id),
                "notes": _collect_notes(row),
            }
            flows.append(flow)

    return {
        "flows": flows,
        "unmapped": unmapped,
        "relationship_types": relationship_types,
    }


def _purpose_from_connectivity_row(row, category):
    message = str(row.get("message") or "").strip()
    if message:
        cleaned = message.replace("PASS:", "").replace("WARN:", "").replace("FAIL:", "").replace("INFO:", "").strip()
        if cleaned:
            return cleaned
    source_name = row.get("source_device") or "source"
    target_name = row.get("dest_device") or "destination"
    if category == "service":
        return f"{source_name} to {target_name} service dependency"
    if category == "management":
        return f"{source_name} to {target_name} management flow"
    if category == "media":
        return f"{source_name} to {target_name} media flow"
    if category == "control":
        return f"{source_name} to {target_name} control flow"
    return f"{source_name} to {target_name} connectivity flow"


def generate_flows_from_connectivity_results(connectivity_results, ip_to_system_id=None, ip_to_device=None):
    flows = []
    unmapped = []
    relationship_types = set()

    for row in (connectivity_results or []):
        if not isinstance(row, dict):
            continue

        status = str(row.get("status") or "").strip().lower()
        if status == "skipped":
            unmapped.append({
                "source": "connectivity",
                "relationship_type": str(row.get("category") or "").strip().lower() or "unknown",
                "rule_id": row.get("rule_id") or "",
                "reason": row.get("message") or "Connectivity row skipped",
                "status": status,
                "from_device": row.get("source_device") or "",
                "to_device": row.get("dest_device") or "",
            })
            continue

        src_ip = str(row.get("source_ip") or "").strip()
        dst_ip = str(row.get("dest_ip") or "").strip()
        src_name = str(row.get("source_device") or "").strip()
        dst_name = str(row.get("dest_device") or "").strip()
        src_type = ""
        dst_type = ""

        if src_ip and isinstance(ip_to_device, dict):
            src_type = str(((ip_to_device.get(src_ip) or {}).get("type") or "")).strip()
            if not src_name:
                src_name = str(((ip_to_device.get(src_ip) or {}).get("name") or "")).strip()
        if dst_ip and isinstance(ip_to_device, dict):
            dst_type = str(((ip_to_device.get(dst_ip) or {}).get("type") or "")).strip()
            if not dst_name:
                dst_name = str(((ip_to_device.get(dst_ip) or {}).get("name") or "")).strip()

        ports = [int(p) for p in (row.get("ports") or []) if isinstance(p, int)]
        protocol = infer_protocol(row.get("protocol"), ports)
        category = normalize_flow_category("", row.get("category"))
        relationship_type = category or "unknown"
        relationship_types.add(relationship_type)

        if not ports:
            flow = {
                "flow_id": build_flow_id(src_type, src_ip, dst_type, dst_ip, protocol, None),
                "src_device": src_name or src_ip or "Unknown source",
                "src_ip": src_ip,
                "src_type": src_type or "unknown",
                "dst_device": dst_name or dst_ip or "Unknown destination",
                "dst_ip": dst_ip,
                "dst_type": dst_type or "unknown",
                "protocol": protocol,
                "port": None,
                "direction": "src_to_dst",
                "category": category,
                "purpose": _purpose_from_connectivity_row(row, category),
                "confidence": status_to_confidence(status),
                "derived_from": {
                    "relationship_type": relationship_type,
                    "source": "validate_systems.connectivity",
                    "rule_id": row.get("rule_id") or "",
                    "status": status or "unknown",
                },
                "system_id": _system_id_for_flow(src_ip, dst_ip, ip_to_system_id),
                "notes": [str(row.get("notes") or "").strip()] if str(row.get("notes") or "").strip() else [],
            }
            flows.append(flow)
            continue

        for port in ports:
            flow = {
                "flow_id": build_flow_id(src_type, src_ip, dst_type, dst_ip, protocol, port),
                "src_device": src_name or src_ip or "Unknown source",
                "src_ip": src_ip,
                "src_type": src_type or "unknown",
                "dst_device": dst_name or dst_ip or "Unknown destination",
                "dst_ip": dst_ip,
                "dst_type": dst_type or "unknown",
                "protocol": protocol,
                "port": port,
                "direction": "src_to_dst",
                "category": category,
                "purpose": _purpose_from_connectivity_row(row, category),
                "confidence": status_to_confidence(status),
                "derived_from": {
                    "relationship_type": relationship_type,
                    "source": "validate_systems.connectivity",
                    "rule_id": row.get("rule_id") or "",
                    "status": status or "unknown",
                },
                "system_id": _system_id_for_flow(src_ip, dst_ip, ip_to_system_id),
                "notes": [str(row.get("notes") or "").strip()] if str(row.get("notes") or "").strip() else [],
            }
            flows.append(flow)

    return {
        "flows": flows,
        "unmapped": unmapped,
        "relationship_types": relationship_types,
    }
