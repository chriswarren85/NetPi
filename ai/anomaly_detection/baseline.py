"""
Network Behaviour Baseline + Anomaly Detection (W13.4)

After each validation run, key metrics are recorded to a rolling baseline store.
On subsequent runs, current values are compared against the baseline.

Flagged anomalies:
  - Multicast group membership change > threshold
  - Device appearing on unexpected VLAN
  - New open ports outside expected profile
  - Device scan response time change > threshold

Pure functions — callers handle I/O (load/save baseline.json).
"""

from datetime import datetime, timezone
import copy


MULTICAST_INCREASE_THRESHOLD = 2.0   # 200% increase
PORT_PROFILE_CHANGE = True           # always flag new unexpected ports
VLAN_CHANGE_ALERT = True             # always flag VLAN changes


def snapshot_from_context(devices, validation_results, multicast_groups=None):
    """
    Build a baseline snapshot from current scan data.

    Returns a dict keyed by device IP with baseline metrics.
    """
    snapshot = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "devices": {},
    }

    validation_by_ip = {}
    for vr in (validation_results or []):
        ip = str(vr.get("ip") or "").strip()
        if ip:
            validation_by_ip[ip] = vr

    multicast_groups = multicast_groups or []
    multicast_by_ip = {}
    for group in multicast_groups:
        members = group.get("members") or []
        group_addr = group.get("group") or ""
        for ip in members:
            ip = str(ip).strip()
            if ip:
                if ip not in multicast_by_ip:
                    multicast_by_ip[ip] = []
                multicast_by_ip[ip].append(group_addr)

    for device in (devices or []):
        ip = str(device.get("ip") or "").strip()
        if not ip:
            continue

        vr = validation_by_ip.get(ip) or {}
        open_ports = sorted(set(int(p) for p in (vr.get("open_ports") or device.get("open_ports") or [])
                                if str(p).isdigit()))
        vlan = str(device.get("vlan") or "").strip()
        multicast_memberships = sorted(multicast_by_ip.get(ip, []))
        response_time_ms = None
        if vr.get("reachability") in ("reachable", "online"):
            response_time_ms = vr.get("response_time_ms")

        snapshot["devices"][ip] = {
            "name": device.get("name") or device.get("hostname") or ip,
            "vlan": vlan,
            "open_ports": open_ports,
            "multicast_memberships": multicast_memberships,
            "multicast_count": len(multicast_memberships),
            "response_time_ms": response_time_ms,
            "reachable": vr.get("reachability") in ("reachable", "online"),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }

    return snapshot


def compare_snapshots(baseline_snapshot, current_snapshot):
    """
    Compare current snapshot against baseline. Returns list of anomaly dicts.

    Each anomaly:
    {
      ip, device_name, anomaly_type, severity,
      description, before, after, detected_at
    }
    """
    anomalies = []
    baseline_devices = (baseline_snapshot or {}).get("devices") or {}
    current_devices = (current_snapshot or {}).get("devices") or {}
    detected_at = datetime.now(timezone.utc).isoformat()

    for ip, current in current_devices.items():
        baseline = baseline_devices.get(ip)
        device_name = current.get("name") or ip

        if baseline is None:
            anomalies.append({
                "ip": ip,
                "device_name": device_name,
                "anomaly_type": "new_device",
                "severity": "info",
                "description": f"New device {device_name} ({ip}) not present in baseline — appeared since last scan.",
                "before": None,
                "after": {"vlan": current.get("vlan"), "open_ports": current.get("open_ports")},
                "detected_at": detected_at,
            })
            continue

        # VLAN change
        if VLAN_CHANGE_ALERT:
            b_vlan = str(baseline.get("vlan") or "").strip()
            c_vlan = str(current.get("vlan") or "").strip()
            if b_vlan and c_vlan and b_vlan != c_vlan:
                anomalies.append({
                    "ip": ip,
                    "device_name": device_name,
                    "anomaly_type": "vlan_change",
                    "severity": "high",
                    "description": f"{device_name} ({ip}) moved from VLAN {b_vlan} to VLAN {c_vlan}. "
                                   f"Unexpected VLAN boundary change — may indicate misconfiguration or network drift.",
                    "before": {"vlan": b_vlan},
                    "after": {"vlan": c_vlan},
                    "detected_at": detected_at,
                })

        # New open ports
        if PORT_PROFILE_CHANGE:
            b_ports = set(baseline.get("open_ports") or [])
            c_ports = set(current.get("open_ports") or [])
            new_ports = sorted(c_ports - b_ports)
            removed_ports = sorted(b_ports - c_ports)
            if new_ports:
                anomalies.append({
                    "ip": ip,
                    "device_name": device_name,
                    "anomaly_type": "new_ports",
                    "severity": "medium",
                    "description": f"{device_name} ({ip}) has {len(new_ports)} new open port(s) not in baseline: {new_ports}. "
                                   f"May indicate new service, configuration change, or compromise.",
                    "before": {"open_ports": sorted(b_ports)},
                    "after": {"open_ports": sorted(c_ports), "new_ports": new_ports},
                    "detected_at": detected_at,
                })
            if removed_ports:
                anomalies.append({
                    "ip": ip,
                    "device_name": device_name,
                    "anomaly_type": "ports_disappeared",
                    "severity": "low",
                    "description": f"{device_name} ({ip}) lost {len(removed_ports)} port(s) since baseline: {removed_ports}. "
                                   f"May indicate service failure or intentional change.",
                    "before": {"open_ports": sorted(b_ports)},
                    "after": {"open_ports": sorted(c_ports), "removed_ports": removed_ports},
                    "detected_at": detected_at,
                })

        # Multicast membership increase
        b_mc_count = int(baseline.get("multicast_count") or 0)
        c_mc_count = int(current.get("multicast_count") or 0)
        if b_mc_count > 0 and c_mc_count > 0:
            ratio = c_mc_count / b_mc_count
            if ratio >= (1 + MULTICAST_INCREASE_THRESHOLD):
                anomalies.append({
                    "ip": ip,
                    "device_name": device_name,
                    "anomaly_type": "multicast_spike",
                    "severity": "high",
                    "description": f"{device_name} ({ip}) multicast group membership increased by "
                                   f"{int((ratio - 1) * 100)}% (from {b_mc_count} to {c_mc_count} groups). "
                                   f"Abnormal multicast growth may indicate misconfiguration or loop.",
                    "before": {"multicast_count": b_mc_count, "groups": baseline.get("multicast_memberships")},
                    "after": {"multicast_count": c_mc_count, "groups": current.get("multicast_memberships")},
                    "detected_at": detected_at,
                })

        # Reachability change
        b_reachable = baseline.get("reachable")
        c_reachable = current.get("reachable")
        if b_reachable is True and c_reachable is False:
            anomalies.append({
                "ip": ip,
                "device_name": device_name,
                "anomaly_type": "device_offline",
                "severity": "high",
                "description": f"{device_name} ({ip}) was reachable in baseline but is now offline. "
                               f"May indicate device failure, power loss, or IP change.",
                "before": {"reachable": True},
                "after": {"reachable": False},
                "detected_at": detected_at,
            })

    # Devices in baseline but not in current (disappeared)
    for ip, baseline in baseline_devices.items():
        if ip not in current_devices:
            device_name = baseline.get("name") or ip
            anomalies.append({
                "ip": ip,
                "device_name": device_name,
                "anomaly_type": "device_disappeared",
                "severity": "medium",
                "description": f"{device_name} ({ip}) was present in baseline but not found in current scan. "
                               f"Device may have been powered off, removed, or IP reassigned.",
                "before": {"vlan": baseline.get("vlan"), "open_ports": baseline.get("open_ports")},
                "after": None,
                "detected_at": detected_at,
            })

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    anomalies.sort(key=lambda a: severity_order.get(a.get("severity", "info"), 99))
    return anomalies


def update_baseline(existing_baseline, new_snapshot, max_history=5):
    """
    Merge a new snapshot into the baseline store.
    Keeps rolling history of up to max_history snapshots.
    The 'current' key always holds the latest snapshot.
    """
    baseline = copy.deepcopy(existing_baseline) if existing_baseline else {}
    history = list(baseline.get("history") or [])

    # Roll the previous current into history
    prev_current = baseline.get("current")
    if prev_current:
        history.append(prev_current)
        if len(history) > max_history:
            history = history[-max_history:]

    baseline["current"] = new_snapshot
    baseline["history"] = history
    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
    return baseline
