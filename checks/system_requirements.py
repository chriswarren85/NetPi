def _normalize_category(value):
    text = str(value or "").strip().lower()
    if text in {"control", "media", "service", "management", "unknown"}:
        return text
    if "control" in text:
        return "control"
    if "media" in text or "stream" in text:
        return "media"
    if "service" in text:
        return "service"
    if "manage" in text:
        return "management"
    return "unknown"


def _new_category_bucket():
    return {
        "control": [],
        "media": [],
        "service": [],
        "management": [],
        "unknown": [],
    }


def _new_totals_bucket():
    return {
        "control": 0,
        "media": 0,
        "service": 0,
        "management": 0,
        "unknown": 0,
    }


def _flow_group_key(flow):
    return (
        str(flow.get("src_ip") or "").strip(),
        str(flow.get("dst_ip") or "").strip(),
        str(flow.get("protocol") or "").strip().lower(),
        str(flow.get("direction") or "src_to_dst").strip().lower(),
        str(flow.get("purpose") or "").strip(),
    )


def _append_note_set(note_set, values):
    if isinstance(values, list):
        for value in values:
            text = str(value or "").strip()
            if text:
                note_set.add(text)
        return
    text = str(values or "").strip()
    if text:
        note_set.add(text)


def _build_system_label(system_id, system_record):
    if not isinstance(system_record, dict):
        return str(system_id or "")

    type_tokens = set()
    for category_name in ("control", "media", "service", "management", "unknown"):
        for row in (system_record.get("categories", {}).get(category_name) or []):
            for device in (row.get("devices") or []):
                token = str(device.get("type") or "").strip()
                if token:
                    type_tokens.add(token)

    if not type_tokens:
        return str(system_id or "")

    ordered = sorted(type_tokens)
    if len(ordered) == 1:
        return ordered[0]
    if len(ordered) == 2:
        return f"{ordered[0]} + {ordered[1]}"
    return f"{ordered[0]} + {ordered[1]} + {len(ordered) - 2} more"


def aggregate_flows_by_system(flows, ip_to_device=None):
    systems = {}
    ungrouped = []
    category_totals = _new_totals_bucket()
    flows_aggregated = 0

    for flow in (flows or []):
        if not isinstance(flow, dict):
            continue

        system_id = str(flow.get("system_id") or "").strip()
        category = _normalize_category(flow.get("category"))
        if not system_id:
            row = dict(flow)
            row["aggregation_reason"] = "Flow has no system_id"
            ungrouped.append(row)
            continue

        if system_id not in systems:
            systems[system_id] = {
                "system_id": system_id,
                "categories": _new_category_bucket(),
                "totals": _new_totals_bucket(),
                "_groups": {},
            }

        record = systems[system_id]
        group_key = (category,) + _flow_group_key(flow)
        grouped = record["_groups"].get(group_key)
        src_ip = str(flow.get("src_ip") or "").strip()
        dst_ip = str(flow.get("dst_ip") or "").strip()
        src_device = str(flow.get("src_device") or src_ip or "Unknown source").strip()
        dst_device = str(flow.get("dst_device") or dst_ip or "Unknown destination").strip()
        src_type = str(flow.get("src_type") or "").strip()
        dst_type = str(flow.get("dst_type") or "").strip()
        src_vlan = str(((ip_to_device or {}).get(src_ip, {}) or {}).get("vlan") or "").strip()
        dst_vlan = str(((ip_to_device or {}).get(dst_ip, {}) or {}).get("vlan") or "").strip()

        if grouped is None:
            grouped = {
                "src_zone_hint": src_vlan or "",
                "dst_zone_hint": dst_vlan or "",
                "src_vlan": src_vlan or "",
                "dst_vlan": dst_vlan or "",
                "protocol": str(flow.get("protocol") or "tcp").strip().lower(),
                "ports": set(),
                "direction": str(flow.get("direction") or "src_to_dst").strip().lower(),
                "purpose": str(flow.get("purpose") or "").strip() or "network flow",
                "devices": [
                    {"name": src_device, "ip": src_ip, "type": src_type or "unknown"},
                    {"name": dst_device, "ip": dst_ip, "type": dst_type or "unknown"},
                ],
                "derived_from": set(),
                "confidence_values": [],
                "notes": set(),
                "source_flow_ids": set(),
                "contributing_relationship_types": set(),
            }
            record["_groups"][group_key] = grouped
            record["categories"][category].append(grouped)
            record["totals"][category] += 1
            category_totals[category] += 1

        port_value = flow.get("port")
        if isinstance(port_value, int):
            grouped["ports"].add(port_value)
        elif isinstance(port_value, str) and port_value.isdigit():
            grouped["ports"].add(int(port_value))

        grouped["source_flow_ids"].add(str(flow.get("flow_id") or "").strip())
        confidence = flow.get("confidence")
        if isinstance(confidence, int):
            grouped["confidence_values"].append(confidence)
        elif isinstance(confidence, str) and confidence.isdigit():
            grouped["confidence_values"].append(int(confidence))

        derived_from = flow.get("derived_from")
        if isinstance(derived_from, dict):
            source = str(derived_from.get("source") or "").strip()
            rel = str(derived_from.get("relationship_type") or "").strip()
            if source:
                grouped["derived_from"].add(source)
            if rel:
                grouped["contributing_relationship_types"].add(rel)
        _append_note_set(grouped["notes"], flow.get("notes"))
        flows_aggregated += 1

    results = []
    for system_id in sorted(systems.keys()):
        record = systems[system_id]
        for category_name in ("control", "media", "service", "management", "unknown"):
            normalized_rows = []
            for row in record["categories"][category_name]:
                confidence_values = row.get("confidence_values") or []
                confidence = min(confidence_values) if confidence_values else 0
                normalized_rows.append({
                    "src_zone_hint": row.get("src_zone_hint") or "",
                    "dst_zone_hint": row.get("dst_zone_hint") or "",
                    "src_vlan": row.get("src_vlan") or "",
                    "dst_vlan": row.get("dst_vlan") or "",
                    "protocol": row.get("protocol") or "tcp",
                    "ports": sorted(set(row.get("ports") or set())),
                    "direction": row.get("direction") or "src_to_dst",
                    "purpose": row.get("purpose") or "network flow",
                    "devices": row.get("devices") or [],
                    "derived_from": sorted(set(row.get("derived_from") or set())),
                    "source_flow_ids": sorted(
                        item for item in set(row.get("source_flow_ids") or set()) if item
                    ),
                    "contributing_relationship_types": sorted(
                        set(row.get("contributing_relationship_types") or set())
                    ),
                    "confidence": confidence,
                    "notes": sorted(set(row.get("notes") or set())),
                })
            record["categories"][category_name] = normalized_rows

        record.pop("_groups", None)
        record["system_label"] = _build_system_label(system_id, record)
        results.append(record)

    summary = {
        "systems": len(results),
        "categories": category_totals,
        "flows_aggregated": flows_aggregated,
    }

    return {
        "summary": summary,
        "results": results,
        "ungrouped_flows": ungrouped,
    }
