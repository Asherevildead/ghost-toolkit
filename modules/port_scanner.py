"""
Ghost Toolkit - Async Port Scanner
Scans TCP ports using asyncio for maximum speed.
"""

import asyncio
import socket
import time
from typing import Optional
from .utils import info, success, warn, error, result, print_table, Colors, c

# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


async def _check_port(host: str, port: int, timeout: float) -> Optional[tuple[int, str, str]]:
    """Returns (port, service, banner) if open, else None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=1.0)
            banner = data.decode("utf-8", errors="ignore").strip().split("\n")[0][:60]
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        service = COMMON_PORTS.get(port, "unknown")
        return (port, service, banner)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _scan_range(host: str, ports: list[int], timeout: float, concurrency: int) -> list:
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def bounded_check(port):
        async with sem:
            return await _check_port(host, port, timeout)

    tasks = [bounded_check(p) for p in ports]
    total = len(tasks)
    done = 0

    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        pct = int(done / total * 40)
        bar = f"[{'â' * pct}{'â' * (40 - pct)}]"
        print(f"\r  {c(bar, Colors.GREEN)} {done}/{total}", end="", flush=True)
        if r:
            open_ports.append(r)

    print()
    return sorted(open_ports)


def resolve_host(host: str) -> str:
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            info(f"Resolved {c(host, Colors.CYAN)} â {c(ip, Colors.GREEN)}")
        return ip
    except socket.gaierror:
        error(f"Cannot resolve host: {host}")
        raise


def scan(
    host: str,
    port_range: str = "1-1024",
    timeout: float = 1.0,
    concurrency: int = 500,
    output_json: str = None,
) -> list[dict]:
    """
    Scan a host for open TCP ports.

    Args:
        host:        Target hostname or IP
        port_range:  Port range string like '1-1024' or '80,443,8080'
        timeout:     Connection timeout per port (seconds)
        concurrency: Max simultaneous connections
        output_json: Optional path to save JSON results
    """
    from .utils import save_json, timestamp

    ip = resolve_host(host)

    # Parse port range
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))

    info(f"Scanning {c(ip, Colors.CYAN)} | {c(str(len(ports)), Colors.YELLOW)} ports | "
         f"timeout={timeout}s | concurrency={concurrency}")
    print()

    start = time.time()
    open_ports = asyncio.run(_scan_range(ip, ports, timeout, concurrency))
    elapsed = time.time() - start

    print()
    if not open_ports:
        warn(f"No open ports found on {ip}")
        return []

    success(f"Found {len(open_ports)} open port(s) in {elapsed:.2f}s")
    print()

    rows = [[str(p), svc, ban or "â"] for p, svc, ban in open_ports]
    print_table(["PORT", "SERVICE", "BANNER"], rows)

    results = [
        {"port": p, "service": svc, "banner": ban}
        for p, svc, ban in open_ports
    ]

    if output_json:
        save_json({"host": host, "ip": ip, "open_ports": results}, output_json)

    return results
