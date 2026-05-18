"""
AI Recommendations Engine (W13.3)

Input:  project context dict (devices, validation results, multicast groups,
        topology, requirements output, firewall plan)
Output: list of {title, severity, category, evidence[], suggested_action,
                  affected_devices[], source:"ai-assisted"}

Pure function — no I/O, no side effects. All data is passed in by the caller.
"""

from datetime import datetime, timezone


_CATEGORY_ORDER = [
    "multicast", "qos_dscp", "vlan_segmentation",
    "switch_config", "firewall", "dante", "ndi",
    "control_system", "general_it",
]

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _sort_key(rec):
    return (
        _SEVERITY_RANK.get(rec.get("severity", "info"), 99),
        _CATEGORY_ORDER.index(rec["category"]) if rec.get("category") in _CATEGORY_ORDER else 99,
        rec.get("title", ""),
    )


def generate_recommendations(context):
    """
    Generate AI-assisted recommendations from the project context.

    Args:
        context: dict from _build_recommendation_context()

    Returns:
        {
          ok: True,
          source: "ai-assisted",
          generated_at: str,
          recommendations: [{
            title, severity, category, finding, suggested_action,
            evidence, affected_devices, source
          }]
        }
    """
    recs = []

    devices = list(context.get("devices") or [])
    validate_all = context.get("validate_all") or {}
    validation_results = list(validate_all.get("results") or [])
    validate_systems = context.get("validate_systems") or {}
    system_results = list(validate_systems.get("results") or [])
    multicast_snapshot = context.get("multicast_groups") or {}
    multicast_groups = list(multicast_snapshot.get("groups") or [])
    firewall_plan = context.get("firewall_plan") or {}
    firewall_rules = list(firewall_plan.get("rules") or [])
    requirements = context.get("system_requirements") or {}
    req_results = list(requirements.get("results") or [])
    topology = context.get("topology") or {}

    # Build quick lookups
    devices_by_ip = {str(d.get("ip") or "").strip(): d for d in devices if d.get("ip")}
    validation_by_ip = {}
    for vr in validation_results:
        ip = str(vr.get("ip") or "").strip()
        if ip:
            validation_by_ip[ip] = vr

    def _add(category, severity, title, finding, suggested_action, evidence=None, affected=None):
        recs.append({
            "title": title,
            "severity": severity,
            "category": category,
            "finding": finding,
            "suggested_action": suggested_action,
            "evidence": list(evidence or []),
            "affected_devices": list(affected or []),
            "source": "ai-assisted",
        })

    def _device_label(d):
        return d.get("name") or d.get("hostname") or d.get("ip") or "?"

    # ── Multicast / IGMP ─────────────────────────────────────────────────────

    if multicast_groups:
        total_flows = len(multicast_groups)
        dante_groups = [g for g in multicast_groups if _is_dante_multicast(g.get("group") or "")]
        ndi_groups = [g for g in multicast_groups if _is_ndi_multicast(g.get("group") or "")]

        vlans_with_multicast = set()
        for d in devices:
            for g in multicast_groups:
                members = g.get("members") or []
                ip = str(d.get("ip") or "").strip()
                if ip in members:
                    vlan = str(d.get("vlan") or "").strip()
                    if vlan:
                        vlans_with_multicast.add(vlan)

        if total_flows > 0 and vlans_with_multicast:
            for vlan in vlans_with_multicast:
                _add(
                    "multicast", "high",
                    f"Enable IGMP snooping on VLAN {vlan}",
                    f"{total_flows} active multicast flow{'s' if total_flows != 1 else ''} detected on VLAN {vlan}. "
                    f"Without IGMP snooping, all multicast traffic floods every port on this VLAN, "
                    f"consuming bandwidth on devices that are not multicast receivers.",
                    f"Enable IGMP snooping on VLAN {vlan} on all switches carrying multicast traffic. "
                    f"Verify with 'show ip igmp snooping' and confirm querier is elected.",
                    evidence=[f"{total_flows} multicast groups observed on VLAN {vlan}"],
                    affected=list(vlans_with_multicast),
                )

        if dante_groups:
            dante_devices = _devices_of_type(devices, ["dante-endpoint", "dante"])
            if not dante_devices:
                dante_devices = _devices_of_role(devices, ["dante"])
            affected = [_device_label(d) for d in dante_devices]
            _add(
                "dante", "medium",
                "Verify IGMP querier for Dante multicast flows",
                f"{len(dante_groups)} Dante multicast group{'s' if len(dante_groups) != 1 else ''} detected. "
                f"Dante relies on multicast for audio flows — an IGMP querier must be active on each VLAN "
                f"carrying Dante traffic to prevent group timeouts and audio dropout.",
                "Confirm an IGMP querier is configured on every VLAN carrying Dante flows. "
                "For multi-VLAN Dante deployments, configure a querier on each VLAN explicitly.",
                evidence=[f"{len(dante_groups)} Dante multicast groups: " + ", ".join(g.get("group","") for g in dante_groups[:5])],
                affected=affected,
            )

        if ndi_groups:
            _add(
                "ndi", "medium",
                "NDI multicast discovery — verify mDNS/multicast routing",
                f"{len(ndi_groups)} NDI-associated multicast groups detected. "
                f"NDI uses mDNS for discovery and multicast for video transport. "
                f"Cross-VLAN NDI requires mDNS proxy/repeater and routed multicast or NDI Bridge.",
                "Verify mDNS proxy is configured for cross-VLAN NDI discovery. "
                "For routed multicast, configure PIM on inter-VLAN interfaces. "
                "Consider NDI Bridge or dedicated NDI VLAN to simplify multicast scope.",
                evidence=[f"{len(ndi_groups)} NDI multicast groups observed"],
            )

    # ── QoS / DSCP ────────────────────────────────────────────────────────────

    dante_devices = _devices_of_type(devices, ["dante-endpoint", "dante", "biamp-tesira", "biamp"])
    ndi_devices = _devices_of_type(devices, ["ndi-encoder", "ndi"])
    av_devices = _devices_of_type(devices, [
        "dante-endpoint", "dante", "biamp-tesira", "biamp",
        "qsys", "ndi-encoder", "shure-mxa",
    ])

    if dante_devices:
        affected = [_device_label(d) for d in dante_devices]
        _add(
            "qos_dscp", "high",
            "Configure QoS DSCP marking for Dante audio traffic",
            f"{len(dante_devices)} Dante device{'s' if len(dante_devices) != 1 else ''} detected. "
            f"Dante audio flows must be marked DSCP EF (46) / 0x2E for strict priority queuing. "
            f"Without QoS, audio packets compete with bulk traffic during congestion, causing dropout.",
            "Mark Dante audio flows DSCP EF (46) at ingress on each access port. "
            "Configure switch queues: strict priority queue for EF, separate queue for bulk. "
            "Verify end-to-end DSCP transparency — do not remap on transit links.",
            evidence=[f"{len(dante_devices)} Dante devices: " + ", ".join(affected[:5])],
            affected=affected,
        )

    if av_devices:
        no_vlan_av = [d for d in av_devices if not str(d.get("vlan") or "").strip()]
        if no_vlan_av:
            affected = [_device_label(d) for d in no_vlan_av]
            _add(
                "vlan_segmentation", "high",
                "AV devices missing VLAN assignment",
                f"{len(no_vlan_av)} AV device{'s' if len(no_vlan_av) != 1 else ''} "
                f"({'Dante, Q-SYS, Biamp'}) have no VLAN assigned. "
                f"AV devices must be on a dedicated AV VLAN, isolated from corporate IT traffic "
                f"to prevent jitter, broadcast storms, and security boundary violations.",
                "Assign all AV devices to a dedicated AV VLAN (e.g. VLAN 40 for audio, VLAN 41 for video). "
                "Configure switch access ports in the correct VLAN before commissioning.",
                evidence=["Devices with missing VLAN: " + ", ".join(affected[:5])],
                affected=affected,
            )

    # ── VLAN Segmentation ─────────────────────────────────────────────────────

    vlan_device_map = {}
    for d in devices:
        vlan = str(d.get("vlan") or "").strip()
        dtype = str(d.get("type") or d.get("effective_type") or "").strip().lower()
        if vlan:
            if vlan not in vlan_device_map:
                vlan_device_map[vlan] = {"it": [], "av": []}
            if _is_av_type(dtype):
                vlan_device_map[vlan]["av"].append(d)
            else:
                vlan_device_map[vlan]["it"].append(d)

    for vlan, groups in vlan_device_map.items():
        if groups["av"] and groups["it"]:
            av_names = [_device_label(d) for d in groups["av"][:3]]
            it_names = [_device_label(d) for d in groups["it"][:3]]
            _add(
                "vlan_segmentation", "medium",
                f"Mixed AV and IT devices on VLAN {vlan}",
                f"VLAN {vlan} contains {len(groups['av'])} AV device(s) and {len(groups['it'])} IT device(s). "
                f"Mixing AV and general IT traffic on the same VLAN introduces jitter risk, "
                f"broadcast domain pollution, and potential QoS policy conflicts.",
                f"Separate AV devices onto a dedicated AV VLAN. "
                f"Move IT devices ({', '.join(it_names)}) to a separate VLAN. "
                f"Review firewall/ACL rules to allow necessary cross-VLAN control traffic.",
                evidence=[
                    f"AV devices on VLAN {vlan}: " + ", ".join(av_names),
                    f"IT devices on VLAN {vlan}: " + ", ".join(it_names),
                ],
                affected=[_device_label(d) for d in groups["av"] + groups["it"]],
            )

    # ── Switch Configuration ───────────────────────────────────────────────────

    switch_devices = _devices_of_type(devices, ["cisco-switch", "switch", "network-switch", "managed-switch"])
    if dante_devices and not switch_devices:
        _add(
            "switch_config", "medium",
            "No managed switches identified — verify switch capabilities",
            f"{len(dante_devices)} Dante device(s) detected but no managed switches were identified in the inventory. "
            f"Dante and other AV protocols require managed switch features: IGMP snooping, QoS/DSCP, "
            f"jumbo frames, and 100Mbps+ full-duplex ports.",
            "Verify all switches in the Dante audio path are managed switches with IGMP snooping, "
            "QoS queuing, and gigabit ports. Add switches to the NetPi device inventory with correct type.",
            evidence=["No switch-type devices found in inventory"],
        )

    # ── Control System ─────────────────────────────────────────────────────────

    control_devices = _devices_of_type(devices, [
        "crestron-processor", "crestron", "amx", "extron",
        "qsys", "crestron_control",
    ])
    if control_devices:
        no_zone = [d for d in control_devices if not str(d.get("zone") or "").strip()
                   and not str(d.get("room") or "").strip()]
        if no_zone:
            affected = [_device_label(d) for d in no_zone]
            _add(
                "control_system", "low",
                "Control processors missing room/zone assignment",
                f"{len(no_zone)} control processor(s) have no room or zone assigned. "
                f"Without room assignment, control topology cannot be verified and "
                f"commissioning documentation will be incomplete.",
                "Assign each control processor to a room or zone in the device inventory. "
                "This enables system topology validation and commissioning report generation.",
                evidence=["Devices without zone/room: " + ", ".join(affected[:5])],
                affected=affected,
            )

    # ── Firewall Rules ─────────────────────────────────────────────────────────

    if firewall_rules:
        permit_all = [r for r in firewall_rules if str(r.get("action") or "").lower() == "permit"
                      and (r.get("destination_port") == "any" or r.get("source_port") == "any")]
        if permit_all:
            _add(
                "firewall", "medium",
                "Broad 'permit any' firewall rules detected",
                f"{len(permit_all)} firewall rule(s) use 'any' for source or destination port. "
                f"Overly broad rules increase attack surface and may allow unintended cross-VLAN access.",
                "Review and tighten permit-any rules. Specify exact ports required for each AV protocol: "
                "Dante UDP 319/320 (PTP), TCP/UDP 14336 (audio), Crestron TCP 41794, "
                "Q-SYS TCP 1710/1711. Replace any-port rules with protocol-specific rules.",
                evidence=[f"{len(permit_all)} broad rules in firewall plan"],
            )

    # ── Dante-Specific ─────────────────────────────────────────────────────────

    if dante_devices:
        cross_vlan = _detect_cross_vlan_dante(dante_devices)
        if cross_vlan:
            vlans = sorted(cross_vlan)
            _add(
                "dante", "high",
                "Dante devices span multiple VLANs — routing required",
                f"Dante devices are assigned to {len(vlans)} different VLAN(s): {', '.join(vlans)}. "
                f"Dante audio flows do not route across VLANs by default — devices on different VLANs "
                f"cannot communicate without Dante Domain Manager (DDM) or VLAN-aware Dante routing.",
                "Either consolidate all Dante devices onto a single VLAN, or configure Dante Domain Manager "
                "for cross-VLAN operation. Ensure IGMP snooping and QoS are applied on all VLANs carrying "
                "Dante traffic. Test audio routing after VLAN changes.",
                evidence=[f"Dante devices on VLANs: {', '.join(vlans)}"],
                affected=[_device_label(d) for d in dante_devices],
            )

    # ── Validation Failures ────────────────────────────────────────────────────

    failed_systems = [r for r in system_results if str(r.get("status") or "").lower() in {"fail", "error"}]
    if failed_systems:
        by_category = {}
        for r in failed_systems:
            cat = str(r.get("category") or r.get("check") or "general").strip()
            by_category.setdefault(cat, []).append(r)

        for cat, failures in list(by_category.items())[:5]:
            device_names = []
            for f in failures[:3]:
                name = f.get("device") or f.get("ip") or ""
                if name:
                    device_names.append(str(name))
            _add(
                "general_it", "high",
                f"System validation failures: {cat}",
                f"{len(failures)} {cat} check(s) failed. "
                + (f"Affected: {', '.join(device_names[:3])}." if device_names else ""),
                f"Review {cat} configuration for affected devices. "
                "Re-run validation after applying fixes to confirm resolution.",
                evidence=[f"{len(failures)} {cat} failures"],
                affected=device_names,
            )

    recs.sort(key=_sort_key)

    return {
        "ok": True,
        "source": "ai-assisted",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "recommendations": recs,
        "summary": {
            "total": len(recs),
            "high": sum(1 for r in recs if r["severity"] == "high"),
            "medium": sum(1 for r in recs if r["severity"] == "medium"),
            "low": sum(1 for r in recs if r["severity"] == "low"),
            "info": sum(1 for r in recs if r["severity"] == "info"),
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_av_type(dtype):
    av_keywords = [
        "dante", "biamp", "tesira", "qsys", "q-sys", "shure", "mxa",
        "crestron", "amx", "extron", "ndi", "barco", "av-",
    ]
    dtype_lower = dtype.lower()
    return any(k in dtype_lower for k in av_keywords)


def _is_dante_multicast(group_addr):
    if not group_addr:
        return False
    try:
        parts = [int(p) for p in group_addr.split(".")]
        if len(parts) != 4:
            return False
        # Dante uses 239.255.x.x and 239.254.x.x for audio flows
        return parts[0] == 239 and parts[1] in (254, 255)
    except Exception:
        return False


def _is_ndi_multicast(group_addr):
    if not group_addr:
        return False
    try:
        parts = [int(p) for p in group_addr.split(".")]
        if len(parts) != 4:
            return False
        # NDI uses 239.255.0.0/16 for discovery
        return parts[0] == 239 and parts[1] == 255
    except Exception:
        return False


def _devices_of_type(devices, types):
    types_lower = [t.lower() for t in types]
    result = []
    for d in devices:
        dtype = str(d.get("type") or d.get("effective_type") or "").lower()
        if any(t in dtype for t in types_lower):
            result.append(d)
    return result


def _devices_of_role(devices, roles):
    roles_lower = [r.lower() for r in roles]
    result = []
    for d in devices:
        role = str(d.get("role") or d.get("av_role") or "").lower()
        if any(r in role for r in roles_lower):
            result.append(d)
    return result


def _detect_cross_vlan_dante(dante_devices):
    vlans = set()
    for d in dante_devices:
        vlan = str(d.get("vlan") or "").strip()
        if vlan:
            vlans.add(vlan)
    return vlans if len(vlans) > 1 else set()
