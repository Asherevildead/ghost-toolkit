"""
Ghost Toolkit - Banner Grabber
Connects to open ports and reads service banners to identify software/versions.
"""

import socket
import ssl
import concurrent.futures
import time
from typing import Optional
from .utils import info, success, warn, error, result, print_table, Colors, c

# Protocol-specific probes
PROBES = {
    21:  b"",           # FTP sends banner on connect
    22:  b"",           # SSH sends banner on connect
    25:  b"EHLO ghost\r\n",
    80:  b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    110: b"",           # POP3 sends banner on connect
    143: b"",           # IMAP sends banner on connect
    443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    3306: b"",          # MySQL sends banner on connect
    5432: b"",          # PostgreSQL
    6379: b"INFO\r\n",  # Redis
    27017: b"",         # MongoDB
}

SERVICE_SIGNATURES = {
    "Apache":     ["Apache"],
    "Nginx":      ["nginx"],
    "IIS":        ["Microsoft-IIS", "IIS"],
    "OpenSSH":    ["OpenSSH"],
    "ProFTPD":    ["ProFTPD"],
    "vsftpd":     ["vsftpd"],
    "Postfix":    ["Postfix"],
    "Exim":       ["Exim"],
    "MySQL":      ["mysql", "MariaDB"],
    "Redis":      ["redis_version"],
    "MongoDB":    ["mongod"],
}


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Grab banner from a port. Returns banner string or None."""
    probe = PROBES.get(port, b"")
    if b"{host}" in probe:
        probe = probe.replace(b"{host}", host.encode())

    try:
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = socket.create_connection((host, port), timeout=timeout)
            sock = ctx.wrap_socket(conn, server_hostname=host)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)

        sock.settimeout(timeout)

        if probe:
            sock.sendall(probe)

        banner = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 2048:
                    break
        except socket.timeout:
            pass

        sock.close()
        return banner.decode("utf-8", errors="ignore").strip()[:200] if banner else None

    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
        return None


def _identify_service(banner: str) -> str:
    """Try to identify the service from the banner text."""
    if not banner:
        return "unknown"
    for service, sigs in SERVICE_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in banner.lower():
                return service
    return "unknown"


def grab(
    host: str,
    ports: list[int],
    timeout: float = 3.0,
    workers: int = 20,
    output_json: str = None,
) -> list[dict]:
    """
    Grab service banners from open ports.

    Args:
        host:        Target hostname or IP
        ports:       List of ports to probe
        timeout:     Socket timeout per port
        workers:     Concurrent threads
        output_json: Optional path to save JSON results
    """
    from .utils import save_json

    info(f"Grabbing banners from {c(host, Colors.CYAN)} on {c(str(len(ports)), Colors.YELLOW)} port(s)")
    print()

    results = []
    start = time.time()

    def probe_port(port):
        banner = _grab_banner(host, port, timeout)
        service = _identify_service(banner) if banner else "no response"
        return {"port": port, "service": service, "banner": banner or ""}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(probe_port, p): p for p in ports}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            done_count += 1
            r = future.result()
            results.append(r)
            pct = int(done_count / len(ports) * 40)
            bar = f"[{'â' * pct}{'â' * (40 - pct)}]"
            print(f"\r  {c(bar, Colors.MAGENTA)} {done_count}/{len(ports)}", end="", flush=True)

    elapsed = time.time() - start
    print()
    print()

    results = sorted(results, key=lambda x: x["port"])
    found = [r for r in results if r["banner"]]

    if not found:
        warn("No banners captured")
        return results

    success(f"Captured {len(found)} banner(s) in {elapsed:.2f}s")
    print()

    rows = [
        [str(r["port"]), r["service"], (r["banner"][:50] + "â§") if len(r["banner"]) > 50 else r["banner"]]
        for r in results if r["banner"]
    ]
    print_table(["PORT", "IDENTIFIED AS", "BANNER SNIPPET"], rows)

    if output_json:
        save_json({"host": host, "banners": results}, output_json)

    return results
