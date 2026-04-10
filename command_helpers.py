import platform


def is_windows():
    return platform.system().lower() == "windows"


def build_ping_command(host, count=4):
    if is_windows():
        return ["ping", "-n", str(count), host]
    return ["ping", "-c", str(count), host]


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
