"""
AI Device Fingerprint Classifier (W13.1)

Input:  a device's observed attributes (MAC OUI, open ports, mDNS service types,
        SNMP sysDescr, HTTP title/server, hostname, multicast behaviour)
Output: {predicted_type, confidence_score, confidence_label, reasoning[], evidence_used[]}

Pure function — no I/O, no side effects. Callers load pattern data and pass it in.
"""

import re
import json
import os
from datetime import datetime, timezone

_PATTERNS_FILE = os.path.join(os.path.dirname(__file__), "fingerprint_patterns.json")

_CONF_THRESHOLDS = [
    (0.85, "high"),
    (0.60, "medium"),
    (0.35, "low"),
    (0.0,  "very_low"),
]


def load_patterns():
    """Load the bundled pattern library. Returns the parsed dict."""
    with open(_PATTERNS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _normalize(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def _field_value(device_attrs, field):
    """Extract the value for a rule field from a flat attribute dict."""
    mapping = {
        "hostname":              device_attrs.get("hostname") or device_attrs.get("name") or "",
        "http_title":            device_attrs.get("http_title") or "",
        "http_server":           device_attrs.get("http_server") or "",
        "http_headers_location": device_attrs.get("http_headers_location") or "",
        "http_headers_xframe":   device_attrs.get("http_headers_xframe") or "",
        "snmp_sysdescr":         device_attrs.get("snmp_sysdescr") or "",
        "open_ports":            device_attrs.get("open_ports") or [],
        "mdns_services":         device_attrs.get("mdns_services") or [],
        "mac_oui":               (device_attrs.get("mac") or "")[:8].upper(),
    }
    return mapping.get(field)


def _rule_matches(value, rule):
    """Return (matched: bool, hit_description: str)."""
    op = None
    target = None

    if "contains" in rule:
        op, target = "contains", rule["contains"]
    elif "icontains" in rule:
        op, target = "icontains", rule["icontains"]
    elif "iregex" in rule:
        op, target = "iregex", rule["iregex"]
    elif "in" in rule:
        op, target = "in", rule["in"]
    else:
        return False, ""

    field = rule.get("field", "")

    if isinstance(value, list):
        if op == "contains":
            hit = target in value
            return hit, f"{field} contains {target}" if hit else ""
        if op == "icontains":
            t = _normalize(target)
            hit = any(t in _normalize(v) for v in value)
            return hit, f"{field} icontains '{target}'" if hit else ""
        if op == "iregex":
            pattern = re.compile(target, re.IGNORECASE)
            hit = any(pattern.search(str(v)) for v in value)
            return hit, f"{field} matches /{target}/" if hit else ""
        if op == "in":
            hit = any(v in target for v in value)
            return hit, f"{field} value in list" if hit else ""
    else:
        str_value = _normalize(value) if value is not None else ""
        if op == "contains":
            hit = str(target) in str(value) if value is not None else False
            return hit, f"{field} contains {target}" if hit else ""
        if op == "icontains":
            hit = _normalize(target) in str_value
            return hit, f"{field} icontains '{target}'" if hit else ""
        if op == "iregex":
            hit = bool(re.search(target, str_value, re.IGNORECASE))
            return hit, f"{field} matches /{target}/" if hit else ""
        if op == "in":
            oui = str_value.upper()
            hit = any(oui.startswith(prefix.upper().replace(":", "").replace("-", ""))
                      or oui.replace(":", "").replace("-", "").startswith(
                          prefix.upper().replace(":", "").replace("-", ""))
                      for prefix in target)
            return hit, f"{field} OUI in known list" if hit else ""

    return False, ""


def _score_pattern(device_attrs, pattern):
    """Score one pattern against device_attrs. Returns (score, max_possible, reasoning)."""
    score = 0
    max_possible = sum(r.get("weight", 1) for r in pattern.get("rules", []))
    reasoning = []

    for rule in pattern.get("rules", []):
        field = rule.get("field", "")
        value = _field_value(device_attrs, field)
        matched, description = _rule_matches(value, rule)
        if matched:
            weight = rule.get("weight", 1)
            score += weight
            reasoning.append(description)

    return score, max_possible, reasoning


def _confidence_label(normalized_score):
    for threshold, label in _CONF_THRESHOLDS:
        if normalized_score >= threshold:
            return label
    return "very_low"


def classify_device(device_attrs, patterns_data=None):
    """
    Classify a device from its observed attributes.

    Args:
        device_attrs: dict with keys: hostname, http_title, http_server,
                      http_headers_location, http_headers_xframe, snmp_sysdescr,
                      open_ports (list), mdns_services (list), mac (str).
        patterns_data: optional pre-loaded patterns dict. Loaded from disk if None.

    Returns:
        {
          predicted_type: str | None,
          confidence_score: float,      # 0.0 – 1.0
          confidence_label: str,        # "high" | "medium" | "low" | "very_low"
          label: str,
          reasoning: [str],
          all_scores: [{pattern_id, score, max, normalized}],
          generated_at: str,
        }
    """
    if patterns_data is None:
        patterns_data = load_patterns()

    patterns = patterns_data.get("patterns", [])
    confirmed = patterns_data.get("confirmed", [])
    all_patterns = list(patterns) + list(confirmed)

    candidates = []

    for pattern in all_patterns:
        min_score = pattern.get("min_score", 3)
        score, max_possible, reasoning = _score_pattern(device_attrs, pattern)
        if max_possible == 0:
            continue
        normalized = score / max_possible
        candidates.append({
            "pattern_id": pattern.get("id"),
            "predicted_type": pattern.get("predicted_type"),
            "label": pattern.get("label", pattern.get("predicted_type", "")),
            "score": score,
            "max": max_possible,
            "normalized": round(normalized, 3),
            "min_score": min_score,
            "reasoning": reasoning,
        })

    # Filter to patterns that met their minimum absolute score
    qualified = [c for c in candidates if c["score"] >= c["min_score"]]
    qualified.sort(key=lambda c: (c["normalized"], c["score"]), reverse=True)

    all_scores = [
        {"pattern_id": c["pattern_id"], "score": c["score"],
         "max": c["max"], "normalized": c["normalized"]}
        for c in candidates
    ]

    if not qualified:
        return {
            "predicted_type": None,
            "confidence_score": 0.0,
            "confidence_label": "very_low",
            "label": "Unknown",
            "reasoning": [],
            "all_scores": all_scores,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    best = qualified[0]
    return {
        "predicted_type": best["predicted_type"],
        "confidence_score": best["normalized"],
        "confidence_label": _confidence_label(best["normalized"]),
        "label": best["label"],
        "reasoning": best["reasoning"],
        "all_scores": all_scores,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_device_attrs_from_evidence(device, evidence=None):
    """
    Build a flat device_attrs dict suitable for classify_device() from
    a device record (devices.json entry) and optional evidence store entry.
    """
    evidence = evidence or {}
    http_info = evidence.get("http") or device.get("http") or {}
    headers = http_info.get("headers") or {}

    open_ports = (
        evidence.get("open_ports")
        or device.get("open_ports")
        or []
    )
    if isinstance(open_ports, list):
        open_ports = [int(p) for p in open_ports if str(p).isdigit()]

    services = evidence.get("services") or device.get("services") or []
    mdns_services = [s.get("name") for s in services if s.get("name")]

    return {
        "hostname":              device.get("hostname") or device.get("name") or "",
        "http_title":            http_info.get("title") or "",
        "http_server":           http_info.get("server") or headers.get("server") or "",
        "http_headers_location": headers.get("location") or "",
        "http_headers_xframe":   headers.get("x-frame-options") or "",
        "snmp_sysdescr":         device.get("snmp_sysdescr") or evidence.get("snmp_sysdescr") or "",
        "open_ports":            open_ports,
        "mdns_services":         mdns_services,
        "mac":                   device.get("mac") or device.get("mac_address") or "",
    }
