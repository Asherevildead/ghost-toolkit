"""
Ghost Toolkit - Directory Fuzzer
Fast HTTP directory and file enumeration using threading.
"""

import urllib.request
import urllib.error
import threading
import queue
import time
from typing import Optional
from .utils import info, success, warn, error, result, print_table, Colors, c

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2",
    "backup", "uploads", "upload", "files", "file", "download",
    "images", "img", "static", "assets", "css", "js", "fonts",
    "config", "configuration", ".env", ".git", ".git/config",
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "phpinfo.php", "info.php", "test.php", "index.php", "index.bak",
    "wp-admin", "wp-login.php", "wp-config.php", "wordpress",
    "panel", "cpanel", "phpmyadmin", "pma", "mysql", "db",
    "console", "manager", "management", "portal", "user", "users",
    "register", "signup", "signin", "auth", "oauth", "token",
    "reset", "forgot", "password", "logout", "profile", "account",
    "docs", "documentation", "help", "support", "changelog",
    "error", "404", "500", "status", "health", "ping", "metrics",
    "swagger", "swagger-ui", "openapi", "redoc", "graphql",
    "xmlrpc.php", "server-status", "server-info", ".DS_Store",
    "old", "new", "bak", "backup.zip", "backup.sql", "dump.sql",
    "shell", "cmd", "command", "exec", "execute", "run",
    "v1", "v2", "v3", "beta", "alpha", "dev", "development",
    "staging", "test", "qa", "prod", "production",
]

STATUS_COLORS = {
    2: Colors.GREEN,    # 2xx â found
    3: Colors.YELLOW,   # 3xx â redirect
    4: Colors.GRAY,     # 4xx â not found / forbidden
    5: Colors.RED,      # 5xx â server error
}

INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}


def _check_path(base_url: str, path: str, timeout: float) -> Optional[dict]:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (ghost-toolkit/1.0; security research)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            length = resp.headers.get("Content-Length", "?")
            ctype  = resp.headers.get("Content-Type", "").split(";")[0].strip()
            return {"url": url, "status": status, "length": length, "type": ctype}
    except urllib.error.HTTPError as e:
        if e.code in INTERESTING:
            return {"url": url, "status": e.code, "length": "?", "type": ""}
        return None
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def _worker(base_url: str, q: queue.Queue, results: list, lock: threading.Lock,
            counter: list, timeout: float):
    while True:
        try:
            path = q.get_nowait()
        except queue.Empty:
            break
        found = _check_path(base_url, path, timeout)
        with lock:
            counter[0] += 1
            if found:
                results.append(found)
                color = STATUS_COLORS.get(found["status"] // 100, Colors.WHITE)
                status_str = c(str(found["status"]), color)
                print(f"\r  {c('[â]', Colors.CYAN)}  [{status_str}] {found['url']:<60} ({found['length']} bytes)")
        q.task_done()


def fuzz(
    url: str,
    wordlist: list[str] = None,
    threads: int = 30,
    timeout: float = 5.0,
    extensions: list[str] = None,
    filter_status: list[int] = None,
    output_json: str = None,
) -> list[dict]:
    """
    Fuzz directories and files on a web target.

    Args:
        url:           Target base URL (e.g. 'http://example.com')
        wordlist:      List of paths to try (uses built-in if None)
        threads:       Concurrent request threads
        timeout:       Request timeout in seconds
        extensions:    Extra file extensions to try (e.g. ['.php', '.bak'])
        filter_status: Only show these status codes (None = show all interesting)
        output_json:   Optional path to save JSON results
    """
    from .utils import save_json

    wordlist = wordlist or DEFAULT_WORDLIST

    # Add extension variants
    if extensions:
        extra = []
        for path in wordlist:
            if "." not in path.split("/")[-1]:
                for ext in extensions:
                    extra.append(path + ext)
        wordlist = wordlist + extra

    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    info(f"Fuzzing {c(url, Colors.CYAN)} | "
         f"{c(str(len(wordlist)), Colors.YELLOW)} paths | "
         f"{threads} threads")
    print()

    q = queue.Queue()
    for path in wordlist:
        q.put(path)

    results = []
    lock = threading.Lock()
    counter = [0]
    total = len(wordlist)
    start = time.time()

    workers = []
    for _ in range(min(threads, total)):
        t = threading.Thread(
            target=_worker,
            args=(url, q, results, lock, counter, timeout),
            daemon=True,
        )
        t.start()
        workers.append(t)

    while any(t.is_alive() for t in workers):
        with lock:
            done = counter[0]
        pct = int(done / total * 40)
        bar = f"[{'â' * pct}{'â' * (40 - pct)}]"
        print(f"\r  {c(bar, Colors.CYAN)} {done}/{total}  ", end="", flush=True)
        time.sleep(0.2)

    for t in workers:
        t.join()

    elapsed = time.time() - start
    print(f"\r  {' ' * 60}", end="\r")
    print()

    if filter_status:
        results = [r for r in results if r["status"] in filter_status]

    results = sorted(results, key=lambda x: x["status"])

    if not results:
        warn("Nothing found â try a larger wordlist or different extensions")
        return []

    success(f"Found {len(results)} path(s) in {elapsed:.2f}s")
    print()
    print_table(
        ["STATUS", "URL", "TYPE", "SIZE"],
        [[str(r["status"]), r["url"], r["type"] or "â", str(r["length"])]
         for r in results],
    )

    if output_json:
        save_json({"target": url, "results": results}, output_json)

    return results
