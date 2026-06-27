<div align="center">

```
   _____ _               _     _______          _ _   _ _
  / ____| |             | |   |__   __|        | | | (_) |
 | |  __| |__   ___  ___| |_     | | ___   ___ | | |  _| |_
 | | |_ | '_ \ / _ \/ __| __|    | |/ _ \ / _ \| | | | | __|
 | |__| | | | | (_) \__ \ |_     | | (_) | (_) | | |_| | |_
  \_____|_| |_|\___/|___/\__|    |_|\___/ \___/|_|_(_)_|\__|
```

**Modular Python security toolkit for recon, enumeration & network analysis**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00FF41?style=for-the-badge)]()
[![Zero Deps](https://img.shields.io/badge/Dependencies-Zero%20Required-blueviolet?style=for-the-badge)]()

</div>

---

## What is Ghost Toolkit?

Ghost Toolkit is a **zero-dependency** collection of offensive security tools written in pure Python. Built for learning, CTFs, and authorized penetration testing â everything runs on Python's standard library out of the box.

```
âââ(asherã¿ghost)-[~/ghost-toolkit]
ââ$ python ghost.py scan example.com --ports 1-1024

   _____ _               _     _______          _ _   _ _
  ...

  [*]  Resolved example.com â 93.184.216.34
  [*]  Scanning 93.184.216.34 | 1024 ports | timeout=1.0s | concurrency=500

  [ââââââââââââââââââââââââââââââââââââââââ] 1024/1024

  [+]  Found 3 open port(s) in 2.14s

  âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
  â PORT â SERVICE â BANNER                               â
  âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
  â 22   â SSH     â SSH-2.0-OpenSSH_8.9p1               â
  â 80   â HTTP    â HTTP/1.1 200 OK                      â
  â 443  â HTTPS   â HTTP/1.1 200 OK                      â
  âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
```

---

## Modules

| Module | Command | What it does |
|--------|---------|-------------|
| **Port Scanner** | `scan` | Async TCP scanner â 1000 ports in ~2 seconds |
| **Subdomain Enumerator** | `enum` | DNS-based subdomain discovery with threading |
| **Banner Grabber** | `grab` | Identifies service versions from banners |
| **Directory Fuzzer** | `fuzz` | HTTP path enumeration with extension support |
| **Hash Tools** | `hash` | Identifies hash types + dictionary cracking |
| **Network Info** | `info` | WHOIS + geolocation + HTTP security audit |

---

## Quick Start

```bash
# Clone
git clone https://github.com/Asherevildead/ghost-toolkit.git
cd ghost-toolkit

# No install needed â pure Python stdlib
python ghost.py --help
```

---

## Usage

### Port Scanner
```bash
# Scan top 1024 ports
python ghost.py scan target.com

# Full scan with custom timeout
python ghost.py scan 192.168.1.1 --ports 1-65535 --timeout 0.5 --concurrency 1000

# Save results
python ghost.py scan target.com --ports 80,443,8080,8443 --output results.json
```

### Subdomain Enumerator
```bash
# Built-in wordlist (130+ common subdomains)
python ghost.py enum target.com

# Custom wordlist + more threads
python ghost.py enum target.com --wordlist /usr/share/wordlists/subdomains.txt --threads 100

# Save results
python ghost.py enum target.com --output subs.json
```

### Banner Grabber
```bash
# Grab banners from common ports
python ghost.py grab target.com

# Custom port list
python ghost.py grab target.com --ports 22,80,443,3306,6379

# After a port scan â grab banners from discovered ports
python ghost.py grab target.com --ports 21,22,80,443,8080 --output banners.json
```

### Directory Fuzzer
```bash
# Fuzz with built-in wordlist
python ghost.py fuzz http://target.com

# Add file extensions
python ghost.py fuzz http://target.com --extensions .php,.bak,.txt,.sql

# Custom wordlist
python ghost.py fuzz http://target.com --wordlist /usr/share/wordlists/dirb/common.txt

# Save results
python ghost.py fuzz http://target.com -e .php,.html --output dirs.json
```

### Hash Tools
```bash
# Identify hash type
python ghost.py hash 5f4dcc3b5aa765d61d8327deb882cf99

# Identify + attempt crack
python ghost.py hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist /usr/share/wordlists/rockyou.txt

# Identify only, skip cracking
python ghost.py hash "$2y$10$somehashedvalue..." --no-crack
```

### Network Info
```bash
# Full intel gather (WHOIS + geo + headers)
python ghost.py info target.com

# Skip WHOIS (faster)
python ghost.py info target.com --no-whois

# Save everything
python ghost.py info target.com --output intel.json
```

---

## Output

Every module supports `--output <file.json>` for structured JSON output â useful for piping into other tools or building automated pipelines.

```bash
# Scan â grab banners from found ports â save all
python ghost.py scan target.com -p 1-1024 -o scan.json
python ghost.py grab target.com -p 22,80,443 -o banners.json
python ghost.py info target.com -o intel.json
```

---

## Project Structure

```
ghost-toolkit/
âââ ghost.py              # Main CLI entry point
âââ modules/
â   âââ __init__.py
â   âââ utils.py          # Colors, logging, tables, output helpers
â   âââ port_scanner.py   # Async TCP port scanner
â   âââ subdomain_enum.py # Threaded subdomain enumeration
â   âââ banner_grabber.py # Service banner identification
â   âââ dir_fuzzer.py     # HTTP directory & file fuzzer
â   âââ hash_tools.py     # Hash identifier & dictionary cracker
â   âââ network_info.py   # WHOIS, geo, HTTP security headers
âââ requirements.txt      # All optional (stdlib only by default)
âââ .gitignore
```

---

## Requirements

- **Python 3.11+**
- **Zero required dependencies** â runs on stdlib only
- Optional: `rich`, `dnspython`, `requests`, `scapy` (see `requirements.txt`)

---

## Roadmap

- [ ] Async HTTP fuzzer (faster than threaded)
- [ ] CVE lookup by service + version
- [ ] SSH/FTP brute-forcer module
- [ ] Packet sniffer (raw sockets)
- [ ] WAF detection module
- [ ] Web crawler / link extractor
- [ ] Report generator (HTML/PDF output)

---

## Legal

> **For educational use and authorized testing only.**
> Always ensure you have explicit written permission before testing any target.
> Unauthorized scanning is illegal. The author takes no responsibility for misuse.

---

<div align="center">

Built by [Asherevildead](https://github.com/Asherevildead) &nbsp;|&nbsp; Learning in public &nbsp;|&nbsp; PRs welcome

</div>
# ghost-toolkit
Modular Python security toolkit for recon, enumeraton &amp; network analysis
