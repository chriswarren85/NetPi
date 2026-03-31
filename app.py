from flask import Flask, render_template, request, jsonify, redirect, send_file
import json, os, subprocess, csv
from datetime import datetime
from checks.network import run_base_checks
from checks.devices import run_device_checks
import io
import ipaddress
import re
from checks.validation import run_validation, run_validation_for_all

app = Flask(__name__)
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
DEVICES_FILE  = os.path.join(os.path.dirname(__file__), 'devices.json')

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
    }
    return aliases.get(s, s)


def weak_device_type(device_type):
    s = (device_type or "").strip().lower()
    return s in ("", "generic", "unknown", "device", "other")


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
    current_type = (device.get("type") or "").lower()
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

        role = infer_av_role(device, result)
        if role:
            result["av_role"] = role


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
        devices = load_devices()
        results = run_validation_for_all(devices)

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
    selected_vlan = data.get("vlan")

    subnet = None
    if selected_vlan:
        for vlan in s.get("vlans", []):
            if vlan.get("name") == selected_vlan:
                subnet = vlan.get("subnet")
                break

    if not subnet:
        subnet = resolve_subnet(s)

    if not subnet:
        return jsonify({"error": "No subnet available"}), 400

    try:
        result = subprocess.check_output(
            ['sudo', 'nmap', '-sn', '--open', subnet, '-oG', '-'],
            timeout=90
        ).decode()

        devices = []
        for line in result.splitlines():
            if 'Host:' in line:
                parts = line.split()
                ip = parts[1]
                hostname = ''
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
                    except Exception:
                        hostname = ''

                if not hostname:
                    try:
                        mdns = subprocess.check_output(
                            ['avahi-resolve-address', ip],
                            stderr=subprocess.DEVNULL,
                            timeout=3
                        ).decode().strip()
                        if '	' in mdns:
                            hostname = mdns.split('	', 1)[1].strip()
                    except Exception:
                        hostname = ''

                guessed_type = guess_type_from_vendor(vendor)

                devices.append({
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "guessed_type": guessed_type,
                    "status": "online"
                })

        return jsonify({
            "subnet": subnet,
            "count": len(devices),
            "devices": devices
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/tools/api/fingerprint_host", methods=["POST"])
def fingerprint_host():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    vendor = (data.get("vendor") or "").lower()
    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    try:
        scan_ports = ",".join([
            "21","22","23","25","53","80","81","88","123","135","139","161","162",
            "389","443","445","515","554","631","902","989","990","1701","1723",
            "1883","1935","2049","2222","2869","2967","3074","3389","3689","3702",
            "5000","5001","5060","5061","5200","5353","5568","5683","5985","5986",
            "6454","7001","7002","7142","8000","8001","8080","8081","8088","8090",
            "8443","8554","8610","8899","9000","9001","9090","9100","9999","10001",
            "10008","10443","15002","20000","41794","41795","41796","47808"
        ])

        result = subprocess.check_output(
            ['sudo', 'nmap', '-Pn', '-p', scan_ports, ip, '-oG', '-'],
            timeout=60
        ).decode()

        open_ports = []
        for line in result.splitlines():
            if '/open/' in line and 'Ports:' in line:
                ports_part = line.split('Ports:', 1)[1]
                for part in ports_part.split(','):
                    part = part.strip()
                    if '/open/' in part:
                        port = part.split('/')[0].strip()
                        if port.isdigit():
                            open_ports.append(int(port))

        open_ports = sorted(set(open_ports))
        open_set = set(open_ports)

        guessed = 'generic'

        def has_any(*ports):
            return any(p in open_set for p in ports)

        # Strong AV / control fingerprints first
        if has_any(41794, 41795, 41796):
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

        # Network / OS style fingerprints
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

        # Vendor-assisted refinement
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
            (['sony'], 'camera-or-display'),
            (['panasonic'], 'camera-or-display'),
            (['lg'], 'display'),
            (['samsung'], 'display'),
            (['philips'], 'display'),
            (['epson'], 'projector'),
            (['benq'], 'projector'),
            (['nec'], 'display'),
            (['netgear', 'cisco', 'aruba', 'juniper', 'hp', 'hewlett packard enterprise', 'hpe', 'ruckus'], 'network-device'),
            (['ubiquiti'], 'network-device'),
            (['fortinet', 'palo alto', 'sophos'], 'firewall'),
            (['axis'], 'camera'),
            (['hikvision', 'dahua'], 'camera'),
            (['yealink', 'poly', 'polycom'], 'voip-device'),
            (['brother', 'xerox', 'canon', 'ricoh', 'kyocera', 'lexmark'], 'printer'),
        ]

        if guessed in (
            'generic', 'web-device', 'network-device', 'ssh-device',
            'snmp-device', 'rtsp-device'
        ):
            for vendor_keys, vendor_guess in vendor_map:
                if any(k in vendor for k in vendor_keys):
                    guessed = vendor_guess
                    break

        # Port + vendor combo refinement
        if 'qsc' in vendor and has_any(80, 443, 8080, 8443, 1702):
            guessed = 'qsys'
        elif 'biamp' in vendor and has_any(80, 443, 5000, 5001):
            guessed = 'biamp'
        elif 'shure' in vendor and has_any(80, 443, 2202):
            guessed = 'shure'
        elif ('cisco' in vendor or 'aruba' in vendor or 'netgear' in vendor or 'juniper' in vendor) and has_any(22, 23, 80, 443, 161, 162):
            guessed = 'network-device'
        elif ('samsung' in vendor or 'lg' in vendor or 'nec' in vendor or 'philips' in vendor) and has_any(80, 443, 8080):
            guessed = 'display'
        elif ('epson' in vendor or 'benq' in vendor) and has_any(80, 443, 23):
            guessed = 'projector'
        elif ('axis' in vendor or 'hikvision' in vendor or 'dahua' in vendor) and has_any(80, 443, 554, 8554):
            guessed = 'camera'

        return jsonify({
            "ip": ip,
            "open_ports": open_ports,
            "guessed_type": guessed
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
    added = 0
    skipped_existing = 0

    for d in devices_in:
        ip = (d.get("ip") or "").strip()
        if not ip:
            continue

        if any(existing.get("ip") == ip for existing in devices):
            skipped_existing += 1
            continue

        device_type = (d.get("type") or "generic").strip() or "generic"
        preferred_name = (d.get("name") or d.get("hostname") or "").strip()
        vendor = (d.get("vendor") or "").strip()
        notes = (d.get("notes") or "").strip()
        generated_name = generate_device_name(devices, device_type, preferred_name)

        devices.append({
            "name": generated_name,
            "ip": ip,
            "type": device_type,
            "vlan": (d.get("vlan") or "").strip(),
            "notes": notes or (f"Auto-discovered ({vendor})" if vendor else "Auto-discovered"),
            "mac": (d.get("mac") or "").strip(),
            "vendor": vendor
        })
        added += 1

    return devices, {
        "added": added,
        "skipped_existing": skipped_existing,
        "total_seen": len(devices_in)
    }


@app.route("/tools/api/devices/add_discovered", methods=["POST"])
def add_discovered_device():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    hostname = data.get("hostname", "").strip()
    vlan = data.get("vlan", "").strip()
    device_type = data.get("type", "generic").strip()
    mac = data.get("mac", "").strip()
    vendor = data.get("vendor", "").strip()

    if not ip:
        return jsonify({"error": "Missing IP"}), 400

    devices = load_devices()

    if any(d.get("ip") == ip for d in devices):
        return jsonify({"success": True, "message": "Device already exists"})

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
    save_devices_file(devices)
    return jsonify({'success': True})


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
    existing_ips = { (d.get("ip") or "").strip() for d in existing_devices if d.get("ip") }

    preview_devices = []
    simulated_devices = list(existing_devices)

    for row in result["devices"]:
        row_copy = dict(row)
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
    added = 0
    skipped = []

    for d in devices_in:
        ip = (d.get("ip") or "").strip()
        if not ip or not _valid_ip(ip):
            skipped.append({"ip": ip, "reason": "invalid_ip"})
            continue

        if any(existing.get("ip") == ip for existing in devices):
            skipped.append({"ip": ip, "reason": "duplicate_ip"})
            continue

        device_type = (d.get("type") or "").strip() or guess_type_from_vendor(d.get("vendor", ""))
        preferred_name = (d.get("name") or "").strip()
        generated_name = generate_device_name(devices, device_type, preferred_name)

        devices.append({
            "name": generated_name,
            "ip": ip,
            "type": device_type,
            "vlan": (d.get("vlan") or "").strip(),
            "notes": (d.get("notes") or "").strip() or f"Pasted import ({d.get('vendor', '')})".strip(),
            "mac": (d.get("mac") or "").strip(),
            "vendor": (d.get("vendor") or "").strip()
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
        t = role or stored_type

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
        import json
        from pathlib import Path
        from checks.validation import run_system_validation
        payload = request.get_json(silent=True) or {}

        devices = payload.get("devices")

        if not isinstance(devices, list) or not devices:
            devices = load_devices()

        validation_results = run_validation_for_all(devices)

        enriched_devices = []
        validations_by_ip = {}

        for device, result in zip(devices, validation_results):
            item = dict(device)
            role = infer_av_role(device, result)
            if role:
                item["av_role"] = role
                result["av_role"] = role
            enriched_devices.append(item)
            validations_by_ip[result.get("ip", "")] = result

        results = run_system_validation(enriched_devices, validations_by_ip)

        detected = build_detected_systems(enriched_devices, results)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
