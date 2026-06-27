import platform


def is_windows():
    return platform.system().lower() == "windows"


def build_ping_command(host, count=4):
    if is_windows():
        return ["ping", "-n", str(count), host]
    return ["ping", "-c", str(count), host]


def build_ping_check_command(host, count=3, wait_timeout=1):
    if is_windows():
        return ["ping", "-n", str(count), "-w", str(int(wait_timeout) * 1000), host]
    return ["ping", "-c", str(count), "-W", str(wait_timeout), host]


def build_traceroute_command(host, max_hops=15):
    if is_windows():
        return {
            "command": ["tracert", "-h", str(max_hops), "-d", host],
            "timeout": 60,
        }
    return {
        "command": ["traceroute", "-m", str(max_hops), host],
        "timeout": 30,
    }


def build_nmap_command(host, fast_scan=True):
    args = ["-F", host] if fast_scan else [host]
    if is_windows():
        return ["nmap"] + args
    return ["sudo", "nmap"] + args


def build_nmap_host_discovery_command(subnet, output_flag="-oG", scan_mode=None):
    mode = (scan_mode or "standard").lower()
    # Accept a list of IPs or a space-separated string of IPs as separate nmap targets.
    # A single CIDR/hostname (no spaces) becomes a one-element list, which is identical
    # to the old behaviour. This prevents Windows from receiving "ip1 ip2" as one
    # quoted argument, which nmap cannot parse.
    if isinstance(subnet, list):
        targets = subnet
    elif " " in str(subnet or ""):
        targets = str(subnet).split()
    else:
        targets = [subnet]

    if mode in ("av_port_probe", "targeted"):
        # -Pn: skip host discovery, probe AV ports directly
        command = ["nmap", "-Pn", "-p",
                   "80,443,22,23,1710,41794,41795,50002,2202",
                   *targets, output_flag, "-"]
    elif mode == "arp_only":
        # ARP-only: fastest on same L2 segment, cannot cross routed boundary
        command = ["nmap", "-sn", "-PR", *targets, output_flag, "-"]
    elif mode == "deep_fingerprint":
        # -sV: service version detection + AV ports
        command = ["nmap", "-Pn", "-sV", "-p",
                   "80,443,22,23,1710,41794,41795,50002,2202",
                   *targets, output_flag, "-"]
    else:
        # standard (default): ping sweep
        command = ["nmap", "-sn", *targets, output_flag, "-"]

    if is_windows():
        return command
    return ["sudo"] + command


def build_arp_lookup_commands(ip):
    target = str(ip or "").strip()
    if not target:
        return []
    if is_windows():
        return [
            ["arp", "-a", target],
        ]
    return [
        ["ip", "neigh", "show", target],
        ["arp", "-n", target],
    ]
