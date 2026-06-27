"""
Ghost Toolkit - Subdomain Enumerator
DNS-based subdomain discovery with concurrent threading.
"""

import socket
import threading
import queue
import time
from typing import Optional
from .utils import info, success, warn, error, result, print_table, Colors, c

# Default subdomain wordlist
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "m", "smtp", "imap", "gateway", "gw", "ssh", "mx", "mx1", "mx2",
    "dev", "staging", "test", "qa", "uat", "prod", "beta", "alpha", "internal",
    "admin", "portal", "api", "cdn", "static", "media", "images", "img",
    "assets", "download", "upload", "files", "backup", "db", "database", "sql",
    "auth", "login", "sso", "oauth", "identity", "app", "apps", "mobile",
    "shop", "store", "blog", "news", "forum", "support", "help", "docs",
    "dashboard", "panel", "control", "manage", "management", "cpanel",
    "webdisk", "autoconfig", "autodiscover", "remote", "vpn2", "citrix",
    "cloud", "aws", "azure", "git", "gitlab", "github", "jenkins", "jida",
    "confluence", "kibana", "grafana", "prometheus", "monitor", "metrics",
    "status", "health", "ping", "ns3", "ns4", "smtp2", "mail2", "mx3",
]


def _resolve(subdomain: str, domain: str) -> Optional[tuple[str, str]]:
    """Try to resolve a subdomain. Returns (full_domain, ip) or None."""
    full = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(full)
        return (full, ip)
    except (socket.gaierror, UnicodeError):
        return None


def _worker(domain: str, q: queue.Queue, results: list, lock: threading.Lock, counter: list):
    while True:
        try:
            sub = q.get_nowait()
        except queue.Empty:
            break
        found = _resolve(sub, domain)
        with lock:
            counter[0] += 1
            if found:
                results.append(found)
                print(f"\r  {c('[+]', Colors.GREEN)}  {c(found[0], Colors.GREEN)} â {found[1]}{'':30}")
        q.task_done()


def enumerate_subdomains(
    domain: str,
    wordlist: list[str] = None,
    threads: int = 50,
    output_json: str = None,
) -> list[dict]:
    """
    Enumerate subdomains of a domain via DNS resolution.

    Args:
        domain:      Target domain (e.g. 'example.com')
        wordlist:    List of subdomain prefixes to try (uses built-in if None)
        threads:     Number of concurrent threads
        output_json: Optional path to save JSON results
    """
    from .utils import save_json, timestamp

    wordlist = wordlist or DEFAULT_WORDLIST
    info(f"Enumerating subdomains for {c(domain, Colors.CYAN)} | "
         f"{c(str(len(wordlist)), Colors.YELLOW)} words | "
         f"{threads} threads")
    print()

    q = queue.Queue()
    for sub in wordlist:
        q.put(sub)

    results = []
    lock = threading.Lock()
    counter = [0]
    total = len(wordlist)

    start = time.time()
    workers = []
    for _ in range(min(threads, total)):
        t = threading.Thread(target=_worker, args=(domain, q, results, lock, counter), daemon=True)
        t.start()
        workers.append(t)

    # Progress display
    while any(t.is_alive() for t in workers):
        with lock:
            done = counter[0]
        pct = int(done / total * 40)
        bar = f"[{'â' * pct}{'â' * (40 - pct)}]"
        print(f"\r  {c(bar, Colors.BLUE)} {done}/{total}", end="", flush=True)
        time.sleep(0.1)

    for t in workers:
        t.join()

    elapsed = time.time() - start
    print(f"\r  {' ' * 60}", end="\r")

    print()
    if not results:
        warn(f"No subdomains found for {domain}")
        return []

    success(f"Discovered {len(results)} subdomain(s) in {elapsed:.2f}s")
    print()

    print_table(["SUBDOMAIN", "IP ADDRESS"], [[d, ip] for d, ip in sorted(results)])

    output = [{"subdomain": d, "ip": ip} for d, ip in results]

    if output_json:
        save_json({"domain": domain, "subdomains": output}, output_json)

    return output
