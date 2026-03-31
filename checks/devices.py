import subprocess
import socket
import time
import requests

def ping_device(ip, name):
    try:
        start = time.time()
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '1', ip],
            capture_output=True, text=True, timeout=10
        )
        elapsed = round((time.time() - start) * 1000)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'rtt' in line or 'round-trip' in line:
                    avg = line.split('/')[4] if '/' in line else '?'
                    return {'check': 'ping', 'status': 'ok', 'latency_ms': avg, 'detail': result.stdout}
            return {'check': 'ping', 'status': 'ok', 'latency_ms': '?', 'detail': result.stdout}
        else:
            return {'check': 'ping', 'status': 'fail', 'latency_ms': None, 'detail': f'{name} ({ip}) not responding'}
    except Exception as e:
        return {'check': 'ping', 'status': 'error', 'latency_ms': None, 'detail': str(e)}

def port_check(ip, port, name):
    try:
        start = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, int(port)))
        elapsed = round((time.time() - start) * 1000)
        sock.close()
        if result == 0:
            return {'check': f'port {port}', 'status': 'ok', 'latency_ms': elapsed, 'detail': f'Port {port} open on {ip}'}
        else:
            return {'check': f'port {port}', 'status': 'fail', 'latency_ms': None, 'detail': f'Port {port} closed or filtered on {ip}'}
    except Exception as e:
        return {'check': f'port {port}', 'status': 'error', 'latency_ms': None, 'detail': str(e)}

def barco_ctrl_check(ip, username='admin', password='admin'):
    try:
        start = time.time()
        r = requests.get(f'http://{ip}/api/v1/system', auth=(username, password), timeout=5)
        elapsed = round((time.time() - start) * 1000)
        if r.status_code in [200, 401]:
            return {'check': 'Barco CTRL API', 'status': 'ok', 'latency_ms': elapsed,
                    'detail': f'API responding (HTTP {r.status_code})'}
        else:
            return {'check': 'Barco CTRL API', 'status': 'warn', 'latency_ms': elapsed,
                    'detail': f'Unexpected response: HTTP {r.status_code}'}
    except Exception as e:
        return {'check': 'Barco CTRL API', 'status': 'fail', 'latency_ms': None, 'detail': str(e)}

# AV protocol port mappings
AV_PORTS = {
    'crestron':   [41794, 41795],
    'barco_ctrl': [80, 443],
    'novastar':   [5200],
    'dante':      [4440, 319, 320],
    'sacn':       [5568],
    'artnet':     [6454],
    'grandma':    [8000, 8001]
}

def check_device(device):
    ip       = device.get('ip')
    name     = device.get('name', ip)
    dtype    = device.get('type', '').lower()
    results  = []

    # Always ping
    results.append(ping_device(ip, name))

    # Type-specific port checks
    ports = AV_PORTS.get(dtype, [])
    for port in ports:
        results.append(port_check(ip, port, name))

    # Barco CTRL API check
    if dtype == 'barco_ctrl':
        results.append(barco_ctrl_check(ip))

    # Overall status — worst of all checks
    statuses = [r['status'] for r in results]
    if 'fail' in statuses:   overall = 'fail'
    elif 'warn' in statuses: overall = 'warn'
    elif 'error' in statuses: overall = 'error'
    else:                     overall = 'ok'

    return {
        'name':    name,
        'ip':      ip,
        'type':    dtype,
        'overall': overall,
        'checks':  results
    }

def run_device_checks(devices):
    return [check_device(d) for d in devices]
