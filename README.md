```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
        toolkit — recon & enumeration
```

![Python](https://img.shields.io/badge/python-3.11+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Zero Deps](https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square)

Python security toolkit for recon, enumeration, and network analysis. No third-party dependencies — runs on stdlib only.

---

## Modules

| Command | What it does |
|---------|-------------|
| `scan`  | TCP port scanner with async concurrency |
| `enum`  | Subdomain enumeration via DNS brute-force |
| `grab`  | Banner grabbing with SSL and service fingerprinting |
| `fuzz`  | HTTP directory/file fuzzer with extension support |
| `hash`  | Hash identification and dictionary cracking |
| `info`  | WHOIS, reverse DNS, geolocation, HTTP header audit |

---

## Setup

```bash
git clone https://github.com/Asherevildead/ghost-toolkit
cd ghost-toolkit
python ghost.py --help
```

Python 3.11+ required. No pip install needed.

---

## Usage

```bash
# Port scan
python ghost.py scan -t 192.168.1.1 -p 1-1000 --threads 200

# Subdomain enumeration
python ghost.py enum -t example.com --wordlist wordlists/subs.txt

# Banner grab
python ghost.py grab -t example.com -p 22,80,443,8080

# Directory fuzzing
python ghost.py fuzz -t http://example.com -w wordlists/dirs.txt -x php,html

# Hash cracking
python ghost.py hash -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlists/rockyou.txt

# Network info
python ghost.py info -t example.com
```

All commands support `-o output.json` to save results.

---

## Module breakdown

**port_scanner.py** — async TCP scanner using `asyncio`. Semaphore-controlled concurrency, configurable timeout and thread count.

**subdomain_enum.py** — DNS-based subdomain discovery. Threaded workers, 80+ built-in subdomains, custom wordlist support, wildcard detection.

**banner_grabber.py** — socket-level banner grabbing with SSL fallback. Fingerprints common services (SSH, HTTP, FTP, SMTP, MySQL, Redis, etc).

**dir_fuzzer.py** — HTTP directory and file fuzzer. Threading, extension support, color-coded status codes, configurable delay.

**hash_tools.py** — identifies hash type from 20+ patterns, then cracks with a wordlist using hashlib.

**network_info.py** — reverse DNS, forward resolution, geolocation (ip-api.com), HTTP header dump, and security header audit (HSTS, CSP, X-Frame-Options, etc).

---

## Notes

- Use on systems you own or have permission to test.
- Some modules (subdomain enum, port scan) generate significant traffic — avoid running against production targets without authorization.
- Optional packages in `requirements.txt` can extend functionality but are not required.

---

MIT License
