import subprocess
import socket
import struct
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False
import os

def ping_test(ip, name, count=3):
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', '1', ip],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            # Parse latency from ping output
            for line in result.stdout.splitlines():
                if 'rtt' in line or 'round-trip' in line:
                    avg = line.split('/')[4] if '/' in line else '?'
                    return {'name': name, 'ip': ip, 'status': 'ok', 'latency_ms': avg, 'detail': result.stdout}
            return {'name': name, 'ip': ip, 'status': 'ok', 'latency_ms': '?', 'detail': result.stdout}
        else:
            return {'name': name, 'ip': ip, 'status': 'fail', 'latency_ms': None, 'detail': result.stdout}
    except Exception as e:
        return {'name': name, 'ip': ip, 'status': 'error', 'latency_ms': None, 'detail': str(e)}

def dns_test(hostname='google.com'):
    try:
        ip = socket.gethostbyname(hostname)
        return {'name': 'DNS resolution', 'status': 'ok', 'detail': f'{hostname} resolved to {ip}'}
    except Exception as e:
        return {'name': 'DNS resolution', 'status': 'fail', 'detail': str(e)}

def get_arp_table():
    try:
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=10)
        entries = {}
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != '<incomplete>':
                ip = parts[0]
                mac = parts[2]
                if mac in entries:
                    entries[mac].append(ip)
                else:
                    entries[mac] = [ip]
        return entries
    except Exception as e:
        return {}

def duplicate_ip_test(subnet):
    try:
        # Run a quick nmap ping scan to find all hosts
        result = subprocess.run(
            ['sudo', 'nmap', '-sn', subnet, '--oG', '-'],
            capture_output=True, text=True, timeout=60
        )
        ips = []
        for line in result.stdout.splitlines():
            if 'Host:' in line:
                parts = line.split()
                ips.append(parts[1])

        # Check ARP table for duplicate MACs
        arp = get_arp_table()
        duplicates = {mac: ips for mac, ips in arp.items() if len(ips) > 1}

        if duplicates:
            detail = 'Duplicate IPs detected:\n'
            for mac, ips in duplicates.items():
                detail += f'  MAC {mac} → {", ".join(ips)}\n'
            return {'name': 'Duplicate IP check', 'status': 'warn', 'detail': detail}
        else:
            return {'name': 'Duplicate IP check', 'status': 'ok', 'detail': f'No duplicates found. {len(ips)} hosts scanned.'}
    except Exception as e:
        return {'name': 'Duplicate IP check', 'status': 'error', 'detail': str(e)}

def dhcp_conflict_test():
    try:
        lease_paths = [
            "/etc/pihole/dhcp.leases",
            "/var/lib/misc/dnsmasq.leases",
            "/run/pihole/dhcp.leases"
        ]

        lease_file = None
        for path in lease_paths:
            if os.path.exists(path):
                lease_file = path
                break

        if not lease_file:
            return {"name": "DHCP conflict check", "status": "warn", "detail": "No DHCP lease file found"}

        raw = subprocess.check_output(['sudo', 'cat', lease_file], timeout=5).decode()
        lines = raw.splitlines()

        ips = [l.split()[2] for l in lines if len(l.split()) >= 3]
        macs = [l.split()[1] for l in lines if len(l.split()) >= 3]

        dup_ips = [ip for ip in ips if ips.count(ip) > 1]
        dup_macs = [mac for mac in macs if macs.count(mac) > 1]

        if dup_ips or dup_macs:
            return {"name": "DHCP conflict check", "status": "warn",
                    "detail": f"Conflicts — IPs: {set(dup_ips)}, MACs: {set(dup_macs)}"}

        return {"name": "DHCP conflict check", "status": "ok",
                "detail": f"{len(ips)} leases checked (source: {lease_file})"}

    except Exception as e:
        return {"name": "DHCP conflict check", "status": "error", "detail": str(e)}

def run_base_checks(gateway, subnet):
    results = []
    results.append(ping_test(gateway, 'Gateway reachability'))
    results.append(ping_test('8.8.8.8', 'Internet access'))
    results.append(dns_test())
    results.append(duplicate_ip_test(subnet))
    results.append(dhcp_conflict_test())
    return results
