"""
AI Topology Pattern Recognition (W13.5)

Library of named AV deployment topology patterns. After device discovery,
scores the current project against known patterns and suggests baseline
VLAN, QoS, and multicast configuration if a match is found.

Input:  devices list, optional topology/multicast context
Output: {matched_pattern, confidence_score, pre_populate_suggestions}
"""

from datetime import datetime, timezone


TOPOLOGY_PATTERNS = [
    {
        "id": "corporate-boardroom",
        "name": "Corporate Boardroom",
        "description": "Single-room AV with presentation switching, control processor, and conferencing DSP.",
        "device_requirements": {
            "crestron-processor": {"min": 1, "max": 2, "weight": 4},
            "crestron-touchpanel": {"min": 1, "max": 4, "weight": 3},
            "biamp-tesira": {"min": 0, "max": 2, "weight": 3},
            "biamp": {"min": 0, "max": 2, "weight": 3},
            "qsys": {"min": 0, "max": 1, "weight": 3},
            "extron": {"min": 0, "max": 3, "weight": 2},
        },
        "total_device_range": (3, 20),
        "expected_vlans": ["av", "control", "mgmt"],
        "expected_multicast": False,
        "weight_total": 12,
        "suggestions": {
            "vlans": [
                {"id": "40", "name": "AV-CONTROL", "purpose": "AV control traffic — Crestron, AMX, IP control"},
                {"id": "10", "name": "MGMT", "purpose": "Management VLAN for AV devices"},
            ],
            "qos": [
                "Mark control traffic DSCP CS3 (24) — reliable delivery priority",
                "Ensure management VLAN has dedicated bandwidth allocation",
            ],
            "multicast": [],
            "firewall_hints": [
                "Allow TCP 41794/41795 for Crestron control processor communication",
                "Allow TCP 443 for remote management of AV devices",
            ],
        },
    },
    {
        "id": "dante-audio-system",
        "name": "Dante Audio Network",
        "description": "IP audio distribution using Dante protocol — DSP, amplifiers, microphones.",
        "device_requirements": {
            "dante-endpoint": {"min": 3, "weight": 5},
            "biamp-tesira": {"min": 0, "max": 6, "weight": 3},
            "biamp": {"min": 0, "max": 6, "weight": 3},
            "shure-mxa": {"min": 0, "max": 10, "weight": 3},
            "crestron-processor": {"min": 0, "max": 2, "weight": 1},
            "cisco-switch": {"min": 0, "max": 4, "weight": 2},
        },
        "total_device_range": (4, 50),
        "expected_vlans": ["av", "dante", "audio"],
        "expected_multicast": True,
        "weight_total": 14,
        "suggestions": {
            "vlans": [
                {"id": "40", "name": "AV-DANTE", "purpose": "Dedicated VLAN for Dante audio flows"},
                {"id": "41", "name": "AV-CONTROL", "purpose": "AV control and management"},
            ],
            "qos": [
                "Mark Dante audio flows DSCP EF (46) — strict priority",
                "Mark Dante PTP DSCP CS7 (56) for clock synchronisation",
                "Enable jumbo frames (MTU 9000) on Dante VLAN",
                "Disable EEE (Energy Efficient Ethernet) on all Dante ports",
            ],
            "multicast": [
                "Enable IGMP snooping on Dante VLAN",
                "Configure IGMP querier on Dante VLAN",
                "Set IGMP leave delay to 1 second for fast failover",
            ],
            "firewall_hints": [
                "Allow UDP 14336 — Dante audio",
                "Allow UDP 319/320 — PTP clock sync",
                "Allow UDP 5353 — mDNS for Dante discovery",
                "Allow UDP 8700-8730 — Dante device control",
            ],
        },
    },
    {
        "id": "ndi-video-network",
        "name": "NDI Video Production Network",
        "description": "IP video distribution using NDI with encoders, receivers, and production switcher.",
        "device_requirements": {
            "ndi-encoder": {"min": 2, "weight": 5},
            "cisco-switch": {"min": 0, "max": 6, "weight": 2},
            "crestron-processor": {"min": 0, "max": 2, "weight": 1},
        },
        "total_device_range": (3, 40),
        "expected_vlans": ["ndi", "video", "av"],
        "expected_multicast": True,
        "weight_total": 8,
        "suggestions": {
            "vlans": [
                {"id": "50", "name": "AV-NDI", "purpose": "Dedicated VLAN for NDI video flows"},
                {"id": "51", "name": "AV-NDI-MGMT", "purpose": "NDI device management"},
            ],
            "qos": [
                "Mark NDI video flows DSCP AF41 (34) — assured forwarding",
                "Reserve minimum 200Mbps per NDI stream for uncompressed 1080p60",
                "Use 10GbE uplinks for NDI aggregation switches",
            ],
            "multicast": [
                "Enable IGMP snooping on NDI VLAN",
                "Configure mDNS proxy for cross-VLAN NDI discovery",
                "Consider PIM-SM for routed NDI multicast deployments",
            ],
            "firewall_hints": [
                "Allow UDP 5960-5961 — NDI video streams",
                "Allow TCP 5960 — NDI TCP fallback",
                "Allow UDP 5353 — mDNS for NDI discovery",
            ],
        },
    },
    {
        "id": "courtroom-av",
        "name": "Courtroom AV System",
        "description": "Legal AV deployment — recording, evidence display, microphone system, room control.",
        "device_requirements": {
            "crestron-processor": {"min": 1, "weight": 3},
            "crestron-touchpanel": {"min": 1, "weight": 2},
            "biamp-tesira": {"min": 1, "weight": 3},
            "biamp": {"min": 1, "weight": 3},
            "shure-mxa": {"min": 2, "weight": 2},
        },
        "total_device_range": (6, 30),
        "expected_vlans": ["av", "control", "record"],
        "expected_multicast": False,
        "weight_total": 13,
        "suggestions": {
            "vlans": [
                {"id": "40", "name": "AV-COURT", "purpose": "Courtroom AV control and audio"},
                {"id": "41", "name": "AV-RECORD", "purpose": "Recording systems — isolated for evidence integrity"},
                {"id": "10", "name": "MGMT", "purpose": "AV device management"},
            ],
            "qos": [
                "Mark audio conference flows DSCP EF (46)",
                "Mark recording traffic DSCP AF31 — assured delivery",
                "Isolate recording VLAN from public network access",
            ],
            "multicast": [],
            "firewall_hints": [
                "Strict ACL on recording VLAN — no outbound internet access",
                "Allow legal case management system on separate VLAN with ACL",
                "Log all cross-VLAN traffic for audit compliance",
            ],
        },
    },
    {
        "id": "university-lecture-hall",
        "name": "University Lecture Hall / Classroom AV",
        "description": "Multi-room/campus AV — lecture capture, wireless presentation, room scheduling.",
        "device_requirements": {
            "crestron-processor": {"min": 1, "weight": 3},
            "crestron-touchpanel": {"min": 1, "weight": 2},
            "biamp-tesira": {"min": 0, "max": 2, "weight": 2},
            "biamp": {"min": 0, "max": 2, "weight": 2},
            "barco-device": {"min": 0, "max": 4, "weight": 2},
        },
        "total_device_range": (4, 25),
        "expected_vlans": ["av", "edu", "classroom"],
        "expected_multicast": False,
        "weight_total": 11,
        "suggestions": {
            "vlans": [
                {"id": "40", "name": "AV-CLASS", "purpose": "Classroom AV devices"},
                {"id": "42", "name": "AV-WIRELESS", "purpose": "Wireless presentation (Barco, Mersive, etc.)"},
                {"id": "10", "name": "MGMT", "purpose": "AV management — accessible from IT"},
            ],
            "qos": [
                "Mark lecture capture DSCP AF31",
                "Limit wireless presentation VLAN bandwidth to prevent saturation",
                "Prioritise room control traffic CS3",
            ],
            "multicast": [
                "Enable IGMP snooping if lecture streaming is used",
            ],
            "firewall_hints": [
                "Allow AV VLAN to reach campus LDAP/AD for room booking",
                "Allow lecture capture to reach campus storage/streaming server",
                "Block AV VLAN from student network VLAN",
            ],
        },
    },
]


def _match_type(device_type, pattern_type_key):
    """Check if a device type matches a pattern key (partial match OK)."""
    dt = str(device_type or "").lower()
    pk = str(pattern_type_key or "").lower()
    return pk in dt or dt == pk


def score_pattern(devices, pattern):
    """
    Score a single topology pattern against the device list.

    Returns (score, max_score, reasoning[]).
    """
    total_score = 0
    max_score = pattern.get("weight_total", 1)
    reasoning = []

    req = pattern.get("device_requirements") or {}

    for pattern_type, spec in req.items():
        matched = [d for d in devices if _match_type(d.get("type") or d.get("effective_type"), pattern_type)]
        count = len(matched)
        min_req = spec.get("min", 0)
        max_req = spec.get("max")
        weight = spec.get("weight", 1)

        if count >= min_req:
            if max_req is None or count <= max_req:
                total_score += weight
                reasoning.append(f"{count}x {pattern_type} (expected >={min_req})")

    # Total device count sanity check
    total_devices = len(devices)
    min_dev, max_dev = pattern.get("total_device_range", (0, 9999))
    if min_dev <= total_devices <= max_dev:
        reasoning.append(f"Device count {total_devices} within expected range {min_dev}-{max_dev}")
    else:
        total_score = max(0, total_score - 2)

    normalized = min(1.0, total_score / max_score)
    return total_score, max_score, round(normalized, 3), reasoning


def match_topology(devices, min_confidence=0.40):
    """
    Score all patterns and return the best match if above min_confidence.

    Returns:
    {
      matched: bool,
      pattern_id: str | None,
      pattern_name: str | None,
      confidence_score: float,
      confidence_label: str,
      suggestions: dict | None,
      all_scores: list,
      generated_at: str,
    }
    """
    all_scores = []
    for pattern in TOPOLOGY_PATTERNS:
        score, max_score, normalized, reasoning = score_pattern(devices, pattern)
        all_scores.append({
            "pattern_id": pattern["id"],
            "pattern_name": pattern["name"],
            "score": score,
            "max_score": max_score,
            "normalized": normalized,
            "reasoning": reasoning,
        })

    all_scores.sort(key=lambda x: x["normalized"], reverse=True)
    best = all_scores[0] if all_scores else None

    if best and best["normalized"] >= min_confidence:
        matched_pattern = next((p for p in TOPOLOGY_PATTERNS if p["id"] == best["pattern_id"]), None)
        conf = best["normalized"]
        label = "high" if conf >= 0.75 else ("medium" if conf >= 0.55 else "low")
        return {
            "matched": True,
            "pattern_id": best["pattern_id"],
            "pattern_name": best["pattern_name"],
            "pattern_description": (matched_pattern or {}).get("description", ""),
            "confidence_score": conf,
            "confidence_label": label,
            "reasoning": best["reasoning"],
            "suggestions": (matched_pattern or {}).get("suggestions"),
            "all_scores": all_scores,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "matched": False,
        "pattern_id": None,
        "pattern_name": None,
        "pattern_description": "",
        "confidence_score": (best["normalized"] if best else 0.0),
        "confidence_label": "none",
        "reasoning": [],
        "suggestions": None,
        "all_scores": all_scores,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
