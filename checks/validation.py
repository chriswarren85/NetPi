import subprocess
import socket
import time
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from checks.connectivity_matrix import get_connectivity_rules, format_ports_for_display

# Lightweight defaults for fast UI-safe validation
DEFAULT_PING_COUNT = 1
DEFAULT_PING_TIMEOUT = 2
DEFAULT_TCP_TIMEOUT = 2
DEFAULT_HTTP_TIMEOUT = 3
DEFAULT_MAX_WORKERS = 8

# Device-type validation profiles
# Keep this simple and easy to extend later.
VALIDATION_RULES = {
    "network-device": ["ping", "http", "ssh"],
    "crestron": ["ping", "http", "https"],
    "crestron_uc": ["ping", "http", "https"],
    "crestron_control": ["ping", "http", "https"],
    "biamp": ["ping", "http", "https"],
    "nvx": ["ping", "http", "https"],
    "av_general": ["ping"],
    "qsys": ["ping", "http", "port:1710"],
    "dante": ["ping", "port:8700", "port:8800"],
    "novastar": ["ping", "port:5200"],
    "lighting": ["ping", "artnet", "sacn"],
    "barco_ctrl": ["ping", "http", "https"],
    "sacn": ["ping", "port:5568"],
    "artnet": ["ping", "port:6454"],
    "grandma": ["ping", "port:80", "port:443"],
    "generic": ["ping"],
}

# Aliases so existing NetPi device types can map cleanly
TYPE_ALIASES = {
    "crestron": "crestron",
    "crestron_uc": "crestron_uc",
    "crestron uc": "crestron_uc",
    "crestron_control": "crestron_control",
    "crestron control": "crestron_control",
    "biamp": "biamp",
    "tesira": "biamp",
    "nvx": "nvx",
    "av_general": "av_general",
    "av general": "av_general",
    "qsys": "qsys",
    "dante": "dante",
    "novastar": "novastar",
    "barco_ctrl": "barco_ctrl",
    "barco ctrl": "barco_ctrl",
    "sacn": "sacn",
    "artnet": "artnet",
    "grandma": "grandma",
    "lighting": "lighting",
    "network-device": "network-device",
    "network device": "network-device",
    "generic": "generic",
}

# Named checks can expand to one or more primitive checks
CHECK_EXPANDERS = {
    "http": ["port:80"],
    "https": ["port:443", "ssl"],
    "ssh": ["port:22"],
    "web": ["port:80", "port:443"],
    "ssl": ["ssl"],
    "artnet": ["port:6454"],
    "sacn": ["port:5568"],
}


def normalize_device_type(device_type):
    value = (device_type or "").strip().lower()
    return TYPE_ALIASES.get(value, value or "generic")


def get_validation_profile(device_type):
    normalized = normalize_device_type(device_type)
    checks = VALIDATION_RULES.get(normalized)

    if not checks:
        checks = VALIDATION_RULES["generic"]

    expanded = []
    for check in checks:
        expanded.extend(expand_check(check))

    # Deduplicate while preserving order
    seen = set()
    ordered = []
    for item in expanded:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    return normalized, ordered


def expand_check(check):
    check = (check or "").strip().lower()
    return CHECK_EXPANDERS.get(check, [check])


def summarize_results(results):
    statuses = [r.get("status") for r in results]

    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    if "error" in statuses:
        return "error"
    return "pass"


def format_latency_ms(start_time):
    return round((time.time() - start_time) * 1000, 1)


def make_result(check, status, detail="", latency_ms=None, extra=None):
    payload = {
        "check": check,
        "status": status,
        "detail": detail,
    }
    if latency_ms is not None:
        payload["latency_ms"] = latency_ms
    if extra:
        payload.update(extra)
    return payload


def run_ping_check(ip):
    start = time.time()
    try:
        result = subprocess.run(
            ["ping", "-c", str(DEFAULT_PING_COUNT), "-W", str(DEFAULT_PING_TIMEOUT), ip],
            capture_output=True,
            text=True,
            timeout=DEFAULT_PING_TIMEOUT + 2,
        )

        latency_ms = format_latency_ms(start)

        if result.returncode == 0:
            parsed_avg = None
            for line in result.stdout.splitlines():
                if "rtt" in line or "round-trip" in line:
                    parts = line.split("=")
                    if len(parts) > 1:
                        stats = parts[1].strip().split("/")
                        if len(stats) >= 2:
                            parsed_avg = stats[1].strip()
                    break

            extra = {}
            if parsed_avg is not None:
                extra["reported_latency_ms"] = parsed_avg

            return make_result(
                "ping",
                "pass",
                detail=f"{ip} responded to ping",
                latency_ms=latency_ms,
                extra=extra,
            )

        return make_result(
            "ping",
            "fail",
            detail=f"{ip} did not respond to ping",
            latency_ms=latency_ms,
        )

    except subprocess.TimeoutExpired:
        return make_result("ping", "fail", detail=f"Ping timed out for {ip}")
    except Exception as e:
        return make_result("ping", "error", detail=str(e))


def run_tcp_port_check(ip, port):
    check_name = f"port:{port}"
    start = time.time()
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TCP_TIMEOUT)
        result = sock.connect_ex((ip, int(port)))
        latency_ms = format_latency_ms(start)

        if result == 0:
            return make_result(
                check_name,
                "pass",
                detail=f"TCP {port} open on {ip}",
                latency_ms=latency_ms,
                extra={"port": int(port)},
            )

        return make_result(
            check_name,
            "fail",
            detail=f"TCP {port} closed or filtered on {ip}",
            latency_ms=latency_ms,
            extra={"port": int(port)},
        )

    except Exception as e:
        return make_result(
            check_name,
            "error",
            detail=str(e),
            extra={"port": int(port)},
        )
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def run_ssl_check(ip, port=443):
    start = time.time()
    sock = None
    wrapped = None

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((ip, int(port)), timeout=DEFAULT_HTTP_TIMEOUT)
        wrapped = context.wrap_socket(sock, server_hostname=ip)

        cipher = wrapped.cipher()
        version = wrapped.version()
        latency_ms = format_latency_ms(start)

        return make_result(
            "ssl",
            "pass",
            detail=f"TLS handshake successful on {ip}:{port}",
            latency_ms=latency_ms,
            extra={
                "port": int(port),
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
            },
        )

    except Exception as e:
        return make_result(
            "ssl",
            "fail",
            detail=f"TLS handshake failed on {ip}:{port} - {e}",
            extra={"port": int(port)},
        )
    finally:
        for handle in (wrapped, sock):
            if handle:
                try:
                    handle.close()
                except Exception:
                    pass


def run_check(device, check):
    ip = device.get("ip", "").strip()
    if not ip:
        return make_result(check, "error", detail="Device has no IP address")

    check = (check or "").strip().lower()

    if check == "ping":
        return run_ping_check(ip)

    if check.startswith("port:"):
        try:
            port = int(check.split(":", 1)[1])
            return run_tcp_port_check(ip, port)
        except ValueError:
            return make_result(check, "error", detail=f"Invalid port definition: {check}")

    if check == "ssl":
        return run_ssl_check(ip, 443)

    return make_result(check, "warn", detail=f"Check type not implemented yet: {check}")



COMMON_PORTS = [80, 443, 22, 23, 8080, 8443, 445, 3389, 139]
AV_FINGERPRINT_PORTS = [1710, 8700, 8800]



AV_PORT_PROFILES = {
    "crestron_uc": {
        "ports": [80, 443, 41795, 22],
        "descriptions": {
            443: "Teams / web interface",
            41795: "Crestron UC control link",
            22: "SSH management"
        }
    },

    "crestron_control": {
        "ports": [41795, 80, 443],
        "descriptions": {
            41795: "Crestron control protocol",
            80: "Web UI",
            443: "Secure web UI"
        }
    },

    "qsys": {
        "ports": [1710, 80, 443],
        "descriptions": {
            1710: "Q-SYS control",
            80: "Core manager",
            443: "Secure Core manager"
        }
    },

    "biamp": {
        "ports": [80, 443, 23],
        "descriptions": {
            80: "Tesira web UI",
            23: "Telnet control (legacy)"
        }
    },

    "nvx": {
        "ports": [80, 443, 554],
        "descriptions": {
            80: "NVX web UI",
            554: "RTSP stream"
        }
    },

    "av_general": {
        "ports": [80, 443, 22, 445],
        "descriptions": {
            80: "Web UI",
            443: "Secure web UI",
            22: "SSH access",
            445: "File sharing / domain"
        }
    }
}

SERVICE_MAP_LOOKUP = {
    80: "http",
    443: "https",
    22: "ssh",
    23: "telnet",
    139: "netbios-ssn",
    445: "smb",
    554: "rtsp",
    1710: "qsys-control",
    3389: "rdp",
    41795: "crestron-control",
    8080: "http-alt",
    8443: "https-alt",
}


def quick_tcp_probe(ip, port, timeout=1):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def _extract_validation_open_ports(validation):
    ports = set()

    for port in validation.get("open_ports", []) or []:
        try:
            ports.add(int(port))
        except Exception:
            pass

    for result in validation.get("results", []) or []:
        if result.get("status") != "pass":
            continue

        port = result.get("port")
        if port is None:
            check = (result.get("check") or "").strip().lower()
            if check.startswith("port:"):
                try:
                    port = int(check.split(":", 1)[1])
                except Exception:
                    port = None

        if port is not None:
            try:
                ports.add(int(port))
            except Exception:
                pass

    return sorted(ports)


def _has_validation_evidence(validation):
    if not validation:
        return False

    if validation.get("overall") == "pass":
        return True

    if _extract_validation_open_ports(validation):
        return True

    for result in validation.get("results", []) or []:
        if result.get("check") == "ping" and result.get("status") == "pass":
            return True

    return False


def http_probe(ip, port):
    try:
        import http.client

        is_https = port in (443, 8443)
        conn_class = http.client.HTTPSConnection if is_https else http.client.HTTPConnection

        if is_https:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = conn_class(ip, port=port, timeout=1.5, context=context)
        else:
            conn = conn_class(ip, port=port, timeout=1.5)

        conn.request("GET", "/", headers={"Host": ip, "User-Agent": "NetPi/3.0"})
        resp = conn.getresponse()
        status = resp.status
        body = resp.read(4096).decode(errors="ignore")
        conn.close()

        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            title = " ".join(m.group(1).split())[:120]

        payload = {"status_code": status}
        server = resp.getheader("Server", "")
        if server:
            payload["server"] = " ".join(str(server).split())[:160]
        headers = {}
        for key, value in resp.getheaders():
            if not key:
                continue
            lowered = str(key).strip().lower()
            if not lowered or lowered in headers:
                continue
            headers[lowered] = str(value)
        if headers:
            payload["headers"] = headers
        if title:
            payload["title"] = title
        keyword_blob = " ".join([
            title,
            payload.get("server", ""),
            body.lower(),
        ]).lower()
        keyword_matches = []
        for keyword in ("biamp", "tesira", "barco", "clickshare", "barco ctrl", "crestron", "q-sys", "qsys", "qsc"):
            if keyword in keyword_blob and keyword not in keyword_matches:
                keyword_matches.append(keyword)
        if keyword_matches:
            payload["keywords"] = keyword_matches
        return payload
    except Exception:
        return None


def ssh_probe_banner(ip, port=22):
    sock = None
    try:
        sock = socket.create_connection((ip, int(port)), timeout=0.75)
        sock.settimeout(0.75)
        banner = sock.recv(256).decode(errors="ignore").strip()
        if banner:
            return " ".join(banner.split())[:160]
    except Exception:
        return ""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return ""


def build_validation_evidence(device, normalized_type, open_ports, service_map, http_details, fingerprint, ssh_banner=""):
    vendor = (device.get("vendor") or "").strip()
    mac = (device.get("mac") or "").strip()
    observed_ports = sorted(int(port) for port in (open_ports or []))

    http_summary = {
        "title": "",
        "server": "",
        "headers": {},
        "keywords": [],
    }

    preferred_http = None
    for port_key in ("443", "80", "8443", "8080"):
        if port_key in http_details:
            preferred_http = http_details.get(port_key) or {}
            break

    if not preferred_http and http_details:
        first_key = sorted(http_details.keys())[0]
        preferred_http = http_details.get(first_key) or {}

    if preferred_http:
        http_summary["title"] = preferred_http.get("title", "") or ""
        http_summary["server"] = preferred_http.get("server", "") or ""
        http_summary["headers"] = preferred_http.get("headers", {}) or {}
        http_summary["keywords"] = list(preferred_http.get("keywords", []) or [])

    services = []
    for port in observed_ports:
        services.append({
            "port": int(port),
            "name": service_map.get(str(port), "unknown"),
        })

    return {
        "ip": (device.get("ip") or "").strip(),
        "open_ports": observed_ports,
        "http": http_summary,
        "vendor": vendor,
        "mac": mac,
        "services": services,
        "ssh": {
            "banner": ssh_banner or "",
        },
        "fingerprint": {
            "platform": fingerprint.get("platform", ""),
            "confidence": fingerprint.get("confidence", ""),
            "reasons": list(fingerprint.get("reasons", []) or []),
        },
        "type": normalized_type,
    }


def _http_signal_blob(http_details):
    http_details = http_details or {}
    title_text = " ".join(str(v.get("title", "")) for v in http_details.values()).lower()
    server_text = " ".join(str(v.get("server", "")) for v in http_details.values()).lower()
    keyword_text = " ".join(
        " ".join(str(keyword) for keyword in (value.get("keywords") or []))
        for value in http_details.values()
    ).lower()
    combined_text = " ".join((title_text, server_text, keyword_text)).strip()
    return title_text, server_text, keyword_text, combined_text


def _contains_any_token(text, tokens):
    return any(token in text for token in (tokens or []))


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


def _detect_av_http_platform(open_ports, http_details):
    ports = set(open_ports or [])
    title_text, server_text, keyword_text, combined_text = _http_signal_blob(http_details)

    qsys_tokens = ("q-sys", "qsys", "qsc")
    qsys_touch_tokens = ("tsc-", "touchscreen controller", "qsys touch", "q-sys touch")
    qsys_nv21_tokens = ("nv-21", "nv21")
    qsys_nv32_tokens = ("nv-32", "nv32", "nv-32-h", "nv32-h")
    crestron_control_tokens = ("cp4", "mc4", "rmc4", "pro4")
    crestron_touch_tokens = ("tsw", "tss", "touchpanel", "touch panel")
    crestron_uc_tokens = ("uc-", "flex", "teams")
    biamp_tokens = ("biamp", "tesira")
    barco_tokens = ("barco", "clickshare", "barco ctrl")

    qsys_context = 1710 in ports or _contains_any_token(combined_text, qsys_tokens)
    if qsys_context:
        reasons = []
        if 1710 in ports:
            reasons.append("port 1710 open")
        if _contains_any_token(combined_text, qsys_tokens):
            reasons.append("http evidence suggests q-sys")
        if _contains_any_token(combined_text, qsys_nv32_tokens):
            reasons.append("model token suggests qsys nv32")
            return {"platform": "qsys-nv32", "confidence": "high" if 1710 in ports else "medium", "reasons": reasons}
        if _contains_any_token(combined_text, qsys_nv21_tokens):
            reasons.append("model token suggests qsys nv21")
            return {"platform": "qsys-nv21", "confidence": "high" if 1710 in ports else "medium", "reasons": reasons}
        if _contains_any_token(combined_text, qsys_touch_tokens):
            reasons.append("model token suggests qsys touchpanel")
            return {"platform": "qsys-touchpanel", "confidence": "medium", "reasons": reasons}
        if "core" in combined_text:
            reasons.append("http evidence suggests qsys core")
            return {"platform": "qsys-core", "confidence": "high" if 1710 in ports else "medium", "reasons": reasons}
        return {"platform": "qsys", "confidence": "high" if 1710 in ports else "medium", "reasons": reasons}

    crestron_context = any(port in ports for port in (41794, 41795, 41796)) or "crestron" in combined_text
    if crestron_context:
        reasons = []
        if any(port in ports for port in (41794, 41795, 41796)):
            reasons.append("crestron control ports open")
        if "crestron" in combined_text:
            reasons.append("http evidence suggests crestron")
        if _contains_any_token(combined_text, crestron_control_tokens):
            reasons.append("model token suggests crestron control processor")
            return {"platform": "crestron_control", "confidence": "medium", "reasons": reasons}
        if _contains_any_token(combined_text, crestron_touch_tokens):
            reasons.append("model token suggests crestron touchpanel")
            return {"platform": "crestron_touchpanel", "confidence": "medium", "reasons": reasons}
        if _contains_any_token(combined_text, crestron_uc_tokens):
            reasons.append("model token suggests crestron uc")
            return {"platform": "crestron_uc", "confidence": "medium", "reasons": reasons}
        return {"platform": "crestron", "confidence": "medium", "reasons": reasons}

    if _contains_any_token(combined_text, biamp_tokens):
        return {
            "platform": "biamp",
            "confidence": "medium",
            "reasons": ["http evidence suggests biamp/tesira"],
        }

    if _contains_any_token(combined_text, barco_tokens):
        return {
            "platform": "barco",
            "confidence": "medium",
            "reasons": ["http evidence suggests barco/clickshare"],
        }

    if _is_video_processing_match(title_text) and (8080 in ports or 22 in ports or 80 in ports or 443 in ports):
        reasons = ["http title suggests video processing device"]
        if 8080 in ports:
            reasons.append("port 8080 open")
        if 22 in ports:
            reasons.append("ssh open")
        return {
            "platform": "video-wall-processor",
            "confidence": "high" if 8080 in ports else "medium",
            "reasons": reasons,
        }

    return None




def infer_observed_platform(open_ports, http_details):
    ports = set(open_ports or [])
    title_text, server_text, keyword_text, _ = _http_signal_blob(http_details)
    reasons = []

    if 22 in ports:
        reasons.append("ssh open")

    av_platform = _detect_av_http_platform(open_ports, http_details)
    if av_platform:
        merged_reasons = list(dict.fromkeys(reasons + list(av_platform.get("reasons") or [])))
        return {
            "platform": av_platform.get("platform", "unknown"),
            "confidence": av_platform.get("confidence", "low"),
            "reasons": merged_reasons,
        }

    if "pi-hole" in title_text or "pi-hole" in keyword_text:
        reasons.append("pi-hole title observed")
        return {
            "platform": "pi-hole",
            "confidence": "high",
            "reasons": reasons
        }

    if "nginx" in server_text and 80 in ports:
        reasons.append("nginx server header")
        return {
            "platform": "linux-web-device",
            "confidence": "medium",
            "reasons": reasons
        }

    if "apache" in server_text:
        reasons.append("apache server header")
        return {
            "platform": "apache-web-device",
            "confidence": "medium",
            "reasons": reasons
        }

    if 22 in ports and (80 in ports or 443 in ports or 8080 in ports or 8443 in ports):
        return {
            "platform": "linux-web-device",
            "confidence": "low",
            "reasons": reasons
        }

    return {
        "platform": "unknown",
        "confidence": "low",
        "reasons": reasons
    }


def infer_fingerprint(normalized_type, open_ports, http_details):
    ports = set(open_ports or [])
    title_text, server_text, _, _ = _http_signal_blob(http_details)
    av_platform = _detect_av_http_platform(open_ports, http_details)
    if av_platform:
        return av_platform

    # Dante
    if 8700 in ports or 8800 in ports or "dante" in title_text:
        reasons = []
        if 8700 in ports:
            reasons.append("port 8700 open")
        if 8800 in ports:
            reasons.append("port 8800 open")
        if "dante" in title_text:
            reasons.append("http title suggests dante")
        return {
            "platform": "dante",
            "confidence": "high" if (8700 in ports and 8800 in ports) else "medium",
            "reasons": reasons
        }

    # NVX
    if "dm nvx" in title_text or " nvx" in f" {title_text}" or title_text.startswith("nvx"):
        reasons = ["http title suggests dm nvx"]
        return {
            "platform": "nvx",
            "confidence": "medium",
            "reasons": reasons
        }

    # Extron
    if "extron" in title_text or "extron" in server_text:
        reasons = []
        if "extron" in title_text:
            reasons.append("http title suggests extron")
        if "extron" in server_text:
            reasons.append("server header suggests extron")
        return {
            "platform": "extron",
            "confidence": "medium",
            "reasons": reasons
        }

    # BrightSign
    if "brightsign" in title_text or "brightsign" in server_text:
        reasons = []
        if "brightsign" in title_text:
            reasons.append("http title suggests brightsign")
        if "brightsign" in server_text:
            reasons.append("server header suggests brightsign")
        return {
            "platform": "brightsign",
            "confidence": "medium",
            "reasons": reasons
        }

    if normalized_type in ("qsys", "dante", "crestron"):
        if normalized_type == "qsys":
            return {
                "platform": "unknown",
                "confidence": "low",
                "reasons": []
            }
        return {
            "platform": normalized_type,
            "confidence": "low",
            "reasons": ["inferred from device type"]
        }

    return {
        "platform": "unknown",
        "confidence": "low",
        "reasons": []
    }

def run_validation(device):
    start_time = time.time()

    device_type = device.get("type", "generic")
    normalized_type, checks = get_validation_profile(device_type)

    results = []
    open_ports = set()
    ip = device.get("ip", "").strip()

    for check in checks:
        result = run_check(device, check)
        result["source"] = "profile"
        results.append(result)

        if result.get("status") == "pass" and result.get("check", "").startswith("port:"):
            try:
                port = int(result["check"].split(":", 1)[1])
                open_ports.add(port)
            except Exception:
                pass

    profile = AV_PORT_PROFILES.get(normalized_type, AV_PORT_PROFILES.get("av_general"))
    ports_to_scan = sorted(set((profile or {}).get("ports", COMMON_PORTS) + AV_FINGERPRINT_PORTS + [8080]))

    if ip:
        for port in ports_to_scan:
            if port in open_ports:
                continue

            if quick_tcp_probe(ip, port, timeout=0.25):
                open_ports.add(port)
                results.append(make_result(
                    f"port:{port}",
                    "pass",
                    detail="Discovered via quick probe",
                    extra={
                        "port": port,
                        "source": "quick_probe",
                        "reason": (profile or {}).get("descriptions", {}).get(port, "General service port")
                    }
                ))

    service_map = {}
    http_details = {}
    ssh_banner = ""

    for port in sorted(open_ports):
        service_map[str(port)] = SERVICE_MAP_LOOKUP.get(port, "unknown")

        if port in (80, 443, 8080, 8443):
            http_data = http_probe(ip, port)
            if http_data:
                http_details[str(port)] = http_data
        elif port == 22 and ip:
            ssh_banner = ssh_probe_banner(ip, port)

    fingerprint = infer_fingerprint(normalized_type, open_ports, http_details)
    observed_platform = infer_observed_platform(open_ports, http_details)
    observed_open_ports = _extract_validation_open_ports({
        "open_ports": sorted(open_ports),
        "results": results,
    })

    return {
        "device": device.get("name") or device.get("ip") or "Unnamed device",
        "name": device.get("name") or device.get("ip") or "Unnamed device",
        "ip": device.get("ip", ""),
        "type": normalized_type,
        "original_type": device_type,
        "latency_ms": format_latency_ms(start_time),
        "open_ports": observed_open_ports,
        "service_map": service_map,
        "http": http_details,
        "fingerprint": fingerprint,
        "observed_platform": observed_platform,
        "evidence": build_validation_evidence(
            device,
            normalized_type,
            observed_open_ports,
            service_map,
            http_details,
            fingerprint,
            ssh_banner=ssh_banner,
        ),
        "results": results,
        "overall": summarize_results(results),
    }


def run_validation_for_all(devices, max_workers=DEFAULT_MAX_WORKERS):
    devices = devices or []
    if not devices:
        return []

    results = [None] * len(devices)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(run_validation, device): index
            for index, device in enumerate(devices)
        }

        for future in as_completed(future_map):
            index = future_map[future]
            device = devices[index]
            try:
                results[index] = future.result()
            except Exception as e:
                results[index] = {
                    "device": device.get("name") or device.get("ip") or "Unnamed device",
                    "name": device.get("name") or device.get("ip") or "Unnamed device",
                    "ip": device.get("ip", ""),
                    "type": normalize_device_type(device.get("type", "generic")),
                    "original_type": device.get("type", "generic"),
                    "results": [
                        make_result("validation", "error", detail=str(e))
                    ],
                    "overall": "error",
                }

    return [item for item in results if item is not None]


SYSTEM_VALIDATION_RULES = [
    {
        "name": "crestron_control_to_qsys",
        "relationship_type": "control",
        "source_types": ["crestron_control", "crestron"],
        "target_types": ["qsys"],
        "required_target_ports": [1710],
        "port_mode": "all",
        "description": "Crestron processor should see Q-SYS control service",
        "inference_note": "Readiness inferred from NetPi validation, not source-initiated control session"
    },
    {
        "name": "crestron_control_to_biamp",
        "relationship_type": "control",
        "source_types": ["crestron_control", "crestron"],
        "target_types": ["biamp", "tesira"],
        "required_target_ports": [80, 443, 23],
        "port_mode": "any",
        "description": "Crestron processor should see Biamp/Tesira management or control service",
        "inference_note": "Readiness inferred from target service exposure"
    },
    {
        "name": "crestron_uc_to_touchpanel",
        "relationship_type": "control",
        "source_types": ["crestron_uc"],
        "target_types": ["tp1070", "touchpanel", "crestron_touchpanel"],
        "required_target_ports": [41795, 443],
        "port_mode": "all",
        "description": "UC engine and touch panel should expose expected control + secure UI services",
        "inference_note": "Readiness inferred from port presence only"
    },
    {
        "name": "qsys_core_to_nv",
        "relationship_type": "media_flow",
        "source_types": ["qsys-core"],
        "target_types": ["qsys-nv-endpoint", "qsys-nv-decoder"],
        "required_target_ports": [443, 554],
        "port_mode": "all",
        "description": "Q-SYS Core should see NV control and media services on the endpoint",
        "inference_note": "Readiness inferred from target port evidence, not source-initiated media flow",
        "source_label": "Q-SYS core",
        "target_label": "Q-SYS NV endpoint"
    },
    {
        "name": "qsys_core_to_touchpanel",
        "relationship_type": "control",
        "source_types": ["qsys-core"],
        "target_types": ["qsys-touchpanel"],
        "required_target_ports": [443],
        "port_mode": "any",
        "description": "Q-SYS Core should relate to Q-SYS touch panels in the same AV system",
        "inference_note": "Relationship inferred from role-aware device classification and reachable UI service",
        "source_label": "Q-SYS core",
        "target_label": "Q-SYS touchpanel"
    }
]


def _humanize_system_role(rule, key):
    explicit = (rule.get(key) or "").strip()
    if explicit:
        return explicit

    allowed = set(rule.get("source_types" if key == "source_label" else "target_types", []))

    if "qsys-core" in allowed:
        return "Q-SYS core"
    if "qsys-touchpanel" in allowed:
        return "Q-SYS touchpanel"
    if "qsys-nv-endpoint" in allowed or "qsys-nv-decoder" in allowed:
        return "Q-SYS NV endpoint"
    if "crestron_control" in allowed or "crestron" in allowed:
        return "Crestron control processor"
    if "biamp" in allowed or "tesira" in allowed:
        return "Biamp/Tesira device"
    if "crestron_uc" in allowed:
        return "Crestron UC engine"
    if "tp1070" in allowed or "touchpanel" in allowed or "crestron_touchpanel" in allowed:
        return "touchpanel"

    return "required device"


def _missing_system_reasons(rule, sources, targets):
    source_label = _humanize_system_role(rule, "source_label")
    target_label = _humanize_system_role(rule, "target_label")
    reasons = []

    if not sources and targets:
        reasons.append(f"{target_label} detected but no {source_label} found")
    elif not sources:
        reasons.append(f"No {source_label} present in device list")

    if not targets and sources:
        reasons.append(f"{source_label} detected but no {target_label} found")
    elif not targets:
        reasons.append(f"No {target_label} present in device list")

    return reasons


def _system_devices_by_types(devices, allowed_types):
    allowed = set((allowed_types or []))
    matched = []

    for d in devices or []:
        raw_type = (d.get("type", "") or "").strip().lower()
        normalized = normalize_device_type(raw_type)
        role = (d.get("av_role") or "").strip().lower()

        def role_matches():
            if not role:
                return False
            for a in allowed:
                if role == a:
                    return True
                if role.startswith(a + "-"):
                    return True
            return False

        if (
            role_matches()
            or normalized in allowed
            or raw_type in allowed
        ):
            item = dict(d)
            item["_normalized_type"] = role or normalized
            matched.append(item)

    return matched


def _evaluate_system_rule(rule, source_device, target_device, validations_by_ip):
    source_ip = source_device.get("ip", "")
    target_ip = target_device.get("ip", "")

    source_validation = validations_by_ip.get(source_ip, {})
    target_validation = validations_by_ip.get(target_ip, {})

    required_ports = list(rule.get("required_target_ports", []))
    target_open_ports = _extract_validation_open_ports(target_validation)

    if target_ip and required_ports:
        for port in required_ports:
            if port in target_open_ports:
                continue
            if quick_tcp_probe(target_ip, int(port), timeout=0.5):
                target_open_ports.append(int(port))

    target_open_ports = sorted(set(target_open_ports))
    observed_ports = [p for p in required_ports if p in target_open_ports]

    port_mode = rule.get("port_mode", "all")
    if not required_ports:
        ports_ok = True
    elif port_mode == "any":
        ports_ok = len(observed_ports) > 0
    else:
        ports_ok = len(observed_ports) == len(required_ports)

    source_ok = _has_validation_evidence(source_validation)
    target_ok = _has_validation_evidence(target_validation) or bool(observed_ports)

    status = "pass" if (source_ok and target_ok and ports_ok) else "fail"

    reasons = []
    if source_ok:
        reasons.append(f'source {source_device.get("name") or source_ip} validated')
    else:
        reasons.append(f'source {source_device.get("name") or source_ip} failed validation or is unavailable')

    if target_ok:
        reasons.append(f'target {target_device.get("name") or target_ip} validated')
    else:
        reasons.append(f'target {target_device.get("name") or target_ip} failed validation or is unavailable')

    if ports_ok:
        reasons.append(f'required target ports observed: {", ".join(str(p) for p in observed_ports)}')
    else:
        if required_ports:
            reasons.append(
                f'required target ports missing: expected {", ".join(str(p) for p in required_ports)}, '
                f'observed {", ".join(str(p) for p in observed_ports) if observed_ports else "none"}'
            )

    return {
        "system_check": rule.get("name"),
        "relationship_type": rule.get("relationship_type", "link"),
        "description": rule.get("description", ""),
        "status": status,
        "from_device": source_device.get("name") or source_ip or "Unknown source",
        "from_ip": source_ip,
        "from_type": source_device.get("_normalized_type") or normalize_device_type(source_device.get("type", "generic")),
        "to_device": target_device.get("name") or target_ip or "Unknown target",
        "to_ip": target_ip,
        "to_type": target_device.get("_normalized_type") or normalize_device_type(target_device.get("type", "generic")),
        "required_target_ports": required_ports,
        "observed_target_ports": observed_ports,
        "target_open_ports": target_open_ports,
        "inference": rule.get("inference_note", ""),
        "reasons": reasons,
    }


def run_system_validation(devices, validations_by_ip=None):
    devices = devices or []

    if validations_by_ip is None:
        validation_results = run_validation_for_all(devices)
        validations_by_ip = {item.get("ip", ""): item for item in validation_results}

    results = []

    for rule in SYSTEM_VALIDATION_RULES:
        sources = _system_devices_by_types(devices, rule.get("source_types", []))
        targets = _system_devices_by_types(devices, rule.get("target_types", []))

        if not sources or not targets:
            results.append({
                "system_check": rule.get("name"),
                "relationship_type": rule.get("relationship_type", "link"),
                "description": rule.get("description", ""),
                "status": "skipped",
                "from_device": None,
                "from_ip": None,
                "from_type": None,
                "to_device": None,
                "to_ip": None,
                "to_type": None,
                "required_target_ports": list(rule.get("required_target_ports", [])),
                "observed_target_ports": [],
                "target_open_ports": [],
                "inference": rule.get("inference_note", ""),
                "reasons": _missing_system_reasons(rule, sources, targets),
            })
            continue

        for source_device in sources:
            for target_device in targets:
                if source_device.get("ip") == target_device.get("ip"):
                    continue
                results.append(_evaluate_system_rule(rule, source_device, target_device, validations_by_ip))

    return results


CONNECTIVITY_ROLE_ALIASES = {
    "crestron-processor": {"crestron-processor", "crestron_control", "crestron-control", "crestron"},
    "crestron-touchpanel": {"crestron-touchpanel", "crestron_touchpanel", "touchpanel", "tp1070"},
    "uc-engine": {"uc-engine", "crestron_uc", "crestron-uc"},
    "crestron-device": {
        "crestron-device", "crestron", "crestron-processor", "crestron-touchpanel",
        "crestron_control", "crestron_touchpanel", "crestron_uc"
    },
    "dante-device": {"dante-device", "dante"},
    "biamp-device": {"biamp-device", "biamp", "tesira"},
    "qsys": {"qsys", "qsys-core"},
    "qsys-touchpanel": {"qsys-touchpanel"},
    "novastar": {"novastar"},
    "samsung-display": {"samsung-display"},
    "barco-encoder": {"barco-encoder"},
    "barco-decoder": {"barco-decoder"},
    "barco-ctrl-server": {"barco-ctrl-server"},
    "barco-ha-server": {"barco-ha-server"},
    "tesira-control-host": {"tesira-control-host"},
    "xio-managed-device": {"xio-managed-device"},
}

VIRTUAL_DESTINATION_ROLES = {"internet", "dns", "ntp"}


def _connectivity_device_roles(device):
    roles = set()

    for value in (device.get("av_role"), device.get("type"), device.get("_normalized_type")):
        text = (value or "").strip().lower()
        if text:
            roles.add(text)

    vendor = (device.get("vendor") or "").strip().lower()
    name = (device.get("name") or "").strip().lower()
    notes = (device.get("notes") or "").strip().lower()
    combined = f"{vendor} {name} {notes}"

    if "samsung" in combined:
        roles.add("samsung-display")

    return roles


def _device_matches_connectivity_roles(device, allowed_roles):
    device_roles = _connectivity_device_roles(device)

    for role in allowed_roles or []:
        normalized_role = (role or "").strip().lower()
        aliases = CONNECTIVITY_ROLE_ALIASES.get(normalized_role, {normalized_role})
        if device_roles.intersection(aliases):
            return True

    return False


def _connectivity_devices_by_roles(devices, allowed_roles):
    return [dict(device) for device in (devices or []) if _device_matches_connectivity_roles(device, allowed_roles)]


def _normalize_scope_value(value):
    return (value or "").strip().lower()


def _scope_pair_allowed(rule, source_device, dest_device):
    scope = _normalize_scope_value(rule.get("scope"))
    if scope not in ("same_vlan", "cross_vlan"):
        return True

    source_vlan = (source_device.get("vlan") or "").strip()
    dest_vlan = (dest_device.get("vlan") or "").strip()

    if not source_vlan or not dest_vlan:
        return True

    if scope == "same_vlan":
        return source_vlan == dest_vlan

    return source_vlan != dest_vlan


def _scope_confidence_note(rule, source_device, dest_device):
    scope = _normalize_scope_value(rule.get("scope"))
    if scope not in ("same_vlan", "cross_vlan"):
        return ""

    source_vlan = (source_device.get("vlan") or "").strip()
    dest_vlan = (dest_device.get("vlan") or "").strip()

    if not source_vlan or not dest_vlan:
        return "VLAN scope could not be fully confirmed from the saved device data."

    return ""


def _dedupe_connectivity_pairs(rule, pairs):
    if not rule.get("bidirectional"):
        return pairs

    seen = set()
    deduped = []

    for source_device, dest_device in pairs:
        source_key = source_device.get("ip") or source_device.get("name") or ""
        dest_key = dest_device.get("ip") or dest_device.get("name") or ""
        pair_key = tuple(sorted([source_key, dest_key]))
        if pair_key in seen:
            continue
        seen.add(pair_key)
        deduped.append((source_device, dest_device))

    return deduped


def _make_connectivity_result(rule, source_device, dest_device, status, message, notes="", observed_ports=None):
    return {
        "rule_id": rule.get("id"),
        "category": rule.get("category", ""),
        "source_device": source_device.get("name") or source_device.get("ip") or "Unknown source",
        "source_ip": source_device.get("ip"),
        "dest_device": dest_device.get("name") or dest_device.get("ip") or "Unknown destination",
        "dest_ip": dest_device.get("ip"),
        "protocol": rule.get("protocol", ""),
        "ports": list(rule.get("ports", [])),
        "status": status,
        "severity": rule.get("required_level", "required"),
        "scope": rule.get("scope", ""),
        "message": message,
        "notes": notes or rule.get("notes", ""),
        "observed_ports": observed_ports or [],
    }


def _make_virtual_connectivity_result(rule, source_device, destination_name, status, message, notes=""):
    return {
        "rule_id": rule.get("id"),
        "category": rule.get("category", ""),
        "source_device": source_device.get("name") or source_device.get("ip") or "Unknown source",
        "source_ip": source_device.get("ip"),
        "dest_device": destination_name,
        "dest_ip": None,
        "protocol": rule.get("protocol", ""),
        "ports": list(rule.get("ports", [])),
        "status": status,
        "severity": rule.get("required_level", "required"),
        "scope": rule.get("scope", ""),
        "message": message,
        "notes": notes or rule.get("notes", ""),
        "observed_ports": [],
    }


def _connectivity_failure_status(rule):
    return "fail" if rule.get("required_level") == "required" else "warn"


def _is_tcp_observable(rule):
    protocol = (rule.get("protocol") or "").strip().lower()
    return protocol == "tcp" and all(isinstance(port, int) for port in (rule.get("ports") or []))


def _evaluate_virtual_connectivity_rule(rule, source_device, validations_by_ip):
    source_ip = source_device.get("ip", "")
    source_validation = validations_by_ip.get(source_ip, {})
    destination_name = ((rule.get("dest_roles") or ["dependency"])[0] or "dependency").upper()

    if not _has_validation_evidence(source_validation):
        return _make_virtual_connectivity_result(
            rule,
            source_device,
            destination_name,
            _connectivity_failure_status(rule),
            f"FAIL: {(source_device.get('name') or source_ip)} source validation is unavailable; outbound {rule.get('protocol')}/{format_ports_for_display(rule.get('ports'))} not assessed",
            notes="Source device did not present enough validation evidence for outbound dependency assessment.",
        )

    return _make_virtual_connectivity_result(
        rule,
        source_device,
        destination_name,
        "warn",
        f"WARN: {(source_device.get('name') or source_ip)} outbound {rule.get('protocol')}/{format_ports_for_display(rule.get('ports'))} dependency is listed but not directly provable from the current probe method",
        notes=rule.get("notes", ""),
    )


def _evaluate_probe_limited_connectivity_rule(rule, source_device, dest_device, validations_by_ip):
    source_ip = source_device.get("ip", "")
    dest_ip = dest_device.get("ip", "")
    source_validation = validations_by_ip.get(source_ip, {})
    target_validation = validations_by_ip.get(dest_ip, {})
    source_name = source_device.get("name") or source_ip
    dest_name = dest_device.get("name") or dest_ip

    if not _has_validation_evidence(source_validation) or not _has_validation_evidence(target_validation):
        return _make_connectivity_result(
            rule,
            source_device,
            dest_device,
            _connectivity_failure_status(rule),
            f"FAIL: {source_name} -> {dest_name} {rule.get('protocol')}/{format_ports_for_display(rule.get('ports'))} could not be assessed because one or both endpoints lack validation evidence",
            notes=rule.get("notes", ""),
        )

    return _make_connectivity_result(
        rule,
        source_device,
        dest_device,
        "warn",
        f"WARN: {source_name} -> {dest_name} {rule.get('protocol')}/{format_ports_for_display(rule.get('ports'))} is scope-sensitive; full end-to-end proof is not available from the current probe method",
        notes=rule.get("notes", ""),
    )


def _evaluate_tcp_connectivity_rule(rule, source_device, dest_device, validations_by_ip):
    source_ip = source_device.get("ip", "")
    dest_ip = dest_device.get("ip", "")
    source_validation = validations_by_ip.get(source_ip, {})
    target_validation = validations_by_ip.get(dest_ip, {})
    source_name = source_device.get("name") or source_ip
    dest_name = dest_device.get("name") or dest_ip

    required_ports = list(rule.get("ports", []))
    observed_ports = set(_extract_validation_open_ports(target_validation))

    if dest_ip:
        for port in required_ports:
            if port in observed_ports:
                continue
            if quick_tcp_probe(dest_ip, int(port), timeout=0.35):
                observed_ports.add(int(port))

    observed_required_ports = sorted(port for port in required_ports if port in observed_ports)
    source_ok = _has_validation_evidence(source_validation)
    target_ok = _has_validation_evidence(target_validation) or bool(observed_required_ports)
    ports_ok = len(observed_required_ports) == len(required_ports)
    status = "pass" if (source_ok and target_ok and ports_ok) else _connectivity_failure_status(rule)

    if status == "pass":
        notes = _scope_confidence_note(rule, source_device, dest_device)
        message = f"PASS: {source_name} -> {dest_name} tcp/{format_ports_for_display(required_ports)} reachable"
        if notes:
            status = "info"
            message = f"INFO: {source_name} -> {dest_name} tcp/{format_ports_for_display(required_ports)} observed but VLAN scope could not be fully confirmed"
        return _make_connectivity_result(
            rule,
            source_device,
            dest_device,
            status,
            message,
            notes=notes,
            observed_ports=observed_required_ports,
        )

    if not source_ok:
        notes = "Source device did not present enough validation evidence."
    elif not target_ok:
        notes = "Destination device did not present enough validation evidence."
    else:
        missing_ports = [port for port in required_ports if port not in observed_required_ports]
        notes = f"Expected ports not observed from NetPi probe path: {format_ports_for_display(missing_ports)}"

    return _make_connectivity_result(
        rule,
        source_device,
        dest_device,
        status,
        f"FAIL: {source_name} -> {dest_name} tcp/{format_ports_for_display(required_ports)} blocked or not observed",
        notes=notes,
        observed_ports=observed_required_ports,
    )


def _connectivity_rule_pairs(rule, devices):
    source_roles = [role for role in (rule.get("source_roles") or []) if role not in VIRTUAL_DESTINATION_ROLES]
    dest_roles = [role for role in (rule.get("dest_roles") or []) if role not in VIRTUAL_DESTINATION_ROLES]
    sources = _connectivity_devices_by_roles(devices, source_roles)

    if any(role in VIRTUAL_DESTINATION_ROLES for role in (rule.get("dest_roles") or [])):
        return sources, []

    targets = _connectivity_devices_by_roles(devices, dest_roles)
    pairs = []

    for source_device in sources:
        for dest_device in targets:
            if source_device.get("ip") == dest_device.get("ip"):
                continue
            if not _scope_pair_allowed(rule, source_device, dest_device):
                continue
            pairs.append((source_device, dest_device))

    return sources, _dedupe_connectivity_pairs(rule, pairs)


def _skipped_connectivity_result(rule, message):
    return {
        "rule_id": rule.get("id"),
        "category": rule.get("category", ""),
        "source_device": None,
        "source_ip": None,
        "dest_device": None,
        "dest_ip": None,
        "protocol": rule.get("protocol", ""),
        "ports": list(rule.get("ports", [])),
        "status": "skipped",
        "severity": rule.get("required_level", "required"),
        "scope": rule.get("scope", ""),
        "message": f"SKIPPED: {message}",
        "notes": rule.get("notes", ""),
        "observed_ports": [],
    }


def run_connectivity_validation(devices, validations_by_ip=None):
    devices = devices or []

    if validations_by_ip is None:
        validation_results = run_validation_for_all(devices)
        validations_by_ip = {item.get("ip", ""): item for item in validation_results}

    results = []

    for rule in get_connectivity_rules():
        source_roles = set(rule.get("source_roles", []))
        dest_roles = set(rule.get("dest_roles", []))
        sources, pairs = _connectivity_rule_pairs(rule, devices)

        if not sources:
            results.append(_skipped_connectivity_result(
                rule,
                f"Rule not evaluated because no matching source role exists for {', '.join(sorted(source_roles)) or 'source'}",
            ))
            continue

        if dest_roles.intersection(VIRTUAL_DESTINATION_ROLES):
            for source_device in sources:
                results.append(_evaluate_virtual_connectivity_rule(rule, source_device, validations_by_ip))
            continue

        targets = _connectivity_devices_by_roles(devices, rule.get("dest_roles", []))
        if not targets:
            results.append(_skipped_connectivity_result(
                rule,
                f"Rule not evaluated because no matching destination role exists for {', '.join(sorted(dest_roles)) or 'destination'}",
            ))
            continue

        if not pairs:
            results.append(_skipped_connectivity_result(
                rule,
                "Rule not evaluated because no source/destination pairs matched the requested VLAN scope",
            ))
            continue

        for source_device, dest_device in pairs:
            if _is_tcp_observable(rule):
                results.append(_evaluate_tcp_connectivity_rule(rule, source_device, dest_device, validations_by_ip))
            else:
                results.append(_evaluate_probe_limited_connectivity_rule(rule, source_device, dest_device, validations_by_ip))

    return results


def summarize_connectivity_results(results):
    summary = {
        "pass": 0,
        "fail": 0,
        "warn": 0,
        "info": 0,
        "skipped": 0,
    }

    for item in results or []:
        status = (item.get("status") or "").strip().lower()
        if status in summary:
            summary[status] += 1

    return summary
