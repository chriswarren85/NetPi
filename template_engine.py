"""
Config Script Template Engine (W20.0)

Pure substitution engine: takes a device record + project settings, selects the
matching template file, substitutes {{placeholders}}, and returns the rendered
script with a list of any fields that could not be resolved.

No Flask dependency — importable and unit-testable in isolation.
"""

import ipaddress
import os
import re

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "configs", "config_templates")
MISSING_MARKER = "[MISSING — enter manually]"

# Maps normalised device type strings → template filename (without .txt)
TYPE_TEMPLATE_MAP = {
    # Q-SYS
    "qsys-core": "qsys_core",
    "qsys": "qsys_core",
    "qsys-io-bridge": "qsys_core",
    # Biamp
    "biamp-tesira": "biamp_tesira",
    "biamp": "biamp_tesira",
    "tesira": "biamp_tesira",
    # Crestron control processors / touch panels
    "crestron-processor": "crestron_control_processor",
    "crestron-control-processor": "crestron_control_processor",
    "crestron-control": "crestron_control_processor",
    "crestron-touchpanel": "crestron_control_processor",
    "crestron-uc-engine": "crestron_control_processor",
    "crestron-uc": "crestron_control_processor",
    "crestron": "crestron_control_processor",
    "control-processor": "crestron_control_processor",
    # Crestron DMPS
    "crestron-dmps": "crestron_dmps",
    "dmps": "crestron_dmps",
    # Dante audio endpoints
    "dante-device": "dante_device",
    "dante": "dante_device",
    "dante-amplifier": "dante_device",
    "dante-gateway": "dante_device",
    # Shure
    "shure-mxa": "shure_mxa",
    "shure-qlxd": "shure_mxa",
    "shure": "shure_mxa",
    # Extron
    "extron-controller": "extron_switcher",
    "extron-matrix": "extron_switcher",
    "extron-presentation-switcher": "extron_switcher",
    "extron-touchpanel": "extron_switcher",
    "extron": "extron_switcher",
    # AMX
    "amx-processor": "amx_controller",
    "amx-touchpanel": "amx_controller",
    "amx": "amx_controller",
    "amx-controller": "amx_controller",
}

# Human-readable names for display in the modal
TEMPLATE_DISPLAY_NAMES = {
    "qsys_core": "Q-SYS Core — Designer CLI Reference",
    "biamp_tesira": "Biamp Tesira — SSH CLI",
    "crestron_control_processor": "Crestron Control Processor — SSH CLI",
    "crestron_dmps": "Crestron DMPS — SSH CLI",
    "dante_device": "Dante Audio Endpoint — Dante Controller Reference",
    "shure_mxa": "Shure MXA / Wireless — Web/Designer Reference",
    "extron_switcher": "Extron Device — Telnet / RS-232 CLI",
    "amx_controller": "AMX Control Processor — Netlinx Studio CLI",
}


def _cidr_to_mask(subnet_cidr):
    """Convert a CIDR subnet string like '192.168.10.0/24' to '255.255.255.0'."""
    try:
        net = ipaddress.ip_network(str(subnet_cidr or ""), strict=False)
        return str(net.netmask)
    except Exception:
        return ""


def _resolve_vlan_info(device, settings):
    """Return the vlan settings dict matching the device's vlan field."""
    device_vlan = str(device.get("vlan") or "").strip().lower()
    for vlan in (settings or {}).get("vlans") or []:
        if not isinstance(vlan, dict):
            continue
        name = str(vlan.get("name") or "").strip().lower()
        if name == device_vlan:
            return vlan
    return {}


def _build_context(device, settings):
    """
    Build a flat dict of all placeholder values.
    Values that cannot be resolved are set to MISSING_MARKER.
    """
    device = device or {}
    settings = settings or {}
    vlan_info = _resolve_vlan_info(device, settings)

    hostname = (
        str(device.get("hostname") or "").strip()
        or str(device.get("name") or "").strip()
    )

    ip = str(device.get("ip") or "").strip()

    subnet_cidr = str(vlan_info.get("subnet") or "").strip()
    subnet_mask = _cidr_to_mask(subnet_cidr) if subnet_cidr else ""

    gateway = (
        str(vlan_info.get("gateway") or "").strip()
        or str(settings.get("gateway") or "").strip()
    )

    dns_primary = (
        str(settings.get("dns_server") or "").strip()
        or str(settings.get("dns_primary") or "").strip()
        or str(settings.get("dns") or "").strip()
    )

    ntp_server = str(settings.get("ntp_server") or "").strip()

    vlan_id = str(vlan_info.get("vlan_id") or vlan_info.get("id") or "").strip()

    device_name = str(device.get("name") or "").strip()
    vendor = str(device.get("vendor") or "").strip()
    model = str(device.get("model") or "").strip()
    firmware = str(device.get("firmware_version") or "").strip()
    serial = str(device.get("serial") or "").strip()

    def val(v):
        return v if v else MISSING_MARKER

    return {
        "hostname": val(hostname),
        "ip": val(ip),
        "subnet": val(subnet_mask),
        "gateway": val(gateway),
        "dns_primary": val(dns_primary),
        "ntp_server": val(ntp_server),
        "vlan_id": val(vlan_id),
        "device_name": val(device_name),
        "vendor": val(vendor),
        "model": val(model),
        "firmware": val(firmware),
        "serial": val(serial),
    }


def _substitute(template_text, context):
    """Replace all {{key}} placeholders using context dict."""
    def replacer(match):
        key = match.group(1).strip()
        return context.get(key, MISSING_MARKER)
    return re.sub(r"\{\{(\w+)\}\}", replacer, template_text)


def _list_missing(context):
    """Return list of placeholder keys that resolved to MISSING_MARKER."""
    return [k for k, v in context.items() if v == MISSING_MARKER]


def get_template_name(device_type):
    """
    Return the template filename stem for the given device type string, or None.
    Normalises the type to lowercase before lookup.
    """
    normalised = str(device_type or "").strip().lower().replace("_", "-")
    return TYPE_TEMPLATE_MAP.get(normalised)


def get_template_display_name(template_name):
    """Return a human-readable display label for a template filename stem."""
    return TEMPLATE_DISPLAY_NAMES.get(template_name or "", template_name or "Unknown Template")


def load_template(template_name):
    """Load the raw template text for the given filename stem. Returns None if not found."""
    path = os.path.join(TEMPLATES_DIR, f"{template_name}.txt")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def render_config_script(device, settings):
    """
    Render a config script for the device.

    Returns a dict:
      {
        "ok": bool,
        "script": str | None,
        "template_name": str | None,
        "display_name": str | None,
        "missing_fields": list[str],
        "ai_generated": False,
        "error": str | None,
      }
    """
    device = device or {}
    device_type = (
        str(device.get("effective_type") or "").strip()
        or str(device.get("_resolved_type") or "").strip()
        or str(device.get("type") or "").strip()
    )
    template_name = get_template_name(device_type)

    if not template_name:
        return {
            "ok": False,
            "script": None,
            "template_name": None,
            "display_name": None,
            "missing_fields": [],
            "ai_generated": False,
            "error": f"No template available for device type: {device_type or '(unknown)'}",
        }

    template_text = load_template(template_name)
    if template_text is None:
        return {
            "ok": False,
            "script": None,
            "template_name": template_name,
            "display_name": get_template_display_name(template_name),
            "missing_fields": [],
            "ai_generated": False,
            "error": f"Template file not found: {template_name}.txt",
        }

    context = _build_context(device, settings)
    rendered = _substitute(template_text, context)
    missing = _list_missing(context)

    return {
        "ok": True,
        "script": rendered,
        "template_name": template_name,
        "display_name": get_template_display_name(template_name),
        "missing_fields": missing,
        "ai_generated": False,
        "error": None,
    }
