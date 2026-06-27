import socket
import ssl
import json
import urllib.request
import urllib.error
from datetime import datetime
from .utils import Colors, c, print_table, save_json, timestamp


def run(target, output=None, **kwargs):
    """Gather network intelligence on a target host or IP."""
    results = {
        'target': target,
        'timestamp': timestamp(),
        'whois': {},
        'dns': {},
        'geo': {},
        'http_headers': {},
        'security_headers': {}
    }

    print(c(f"\n[*] Network info: {target}", Colors.CYAN))

    # Reverse DNS
    try:
        hostname, _, ip_list = socket.gethostbyaddr(target)
        results['dns']['reverse'] = hostname
        results['dns']['ips'] = list(ip_list)
        print(c(f"[+] Reverse DNS: {hostname}", Colors.GREEN))
    except Exception as e:
        results['dns']['reverse'] = None
        print(c(f"[-] Reverse DNS failed: {e}", Colors.RED))

    # Forward DNS
    try:
        ip = socket.gethostbyname(target)
        results['dns']['forward'] = ip
        print(c(f"[+] Resolved: {ip}", Colors.GREEN))
    except Exception as e:
        results['dns']['forward'] = None
        print(c(f"[-] DNS resolution failed: {e}", Colors.RED))

    # Geolocation via ip-api.com (free, no key)
    try:
        query_ip = results['dns'].get('forward', target)
        url = f"http://ip-api.com/json/{query_ip}?fields=status,country,regionName,city,isp,org,as,query"
        with urllib.request.urlopen(url, timeout=5) as resp:
            geo = json.loads(resp.read().decode())
            if geo.get('status') == 'success':
                results['geo'] = geo
                print(c(f"[+] Location: {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}", Colors.GREEN))
                print(c(f"[+] ISP: {geo.get('isp')}", Colors.GREEN))
                print(c(f"[+] ASN: {geo.get('as')}", Colors.GREEN))
    except Exception as e:
        print(c(f"[-] Geolocation failed: {e}", Colors.RED))

    # HTTP headers + security audit
    try:
        url = f"https://{target}" if not target.startswith('http') else target
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5, context=ssl.create_default_context()) as resp:
            headers = dict(resp.headers)
            results['http_headers'] = headers

            security_checks = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy',
            }

            print(c("\n[*] Security headers:", Colors.CYAN))
            for header, label in security_checks.items():
                if header in headers:
                    print(c(f"  [+] {label}: {headers[header][:60]}", Colors.GREEN))
                    results['security_headers'][header] = headers[header]
                else:
                    print(c(f"  [-] Missing: {label}", Colors.YELLOW))
                    results['security_headers'][header] = None

            server = headers.get('Server', 'Not disclosed')
            powered = headers.get('X-Powered-By', 'Not disclosed')
            print(c(f"\n[+] Server: {server}", Colors.GREEN))
            print(c(f"[+] X-Powered-By: {powered}", Colors.GREEN))

    except Exception as e:
        print(c(f"[-] HTTP headers failed: {e}", Colors.RED))

    if output:
        save_json(results, output)
        print(c(f"\n[+] Saved to {output}", Colors.GREEN))

    return results
