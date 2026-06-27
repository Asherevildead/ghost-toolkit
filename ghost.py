#!/usr/bin/env python3
"""
Ghost Toolkit â Modular Python Security Toolkit
Usage: python ghost.py <command> [options]

Commands:
  scan      TCP port scanner
  enum      Subdomain enumerator
  grab      Banner grabber
  fuzz      Directory fuzzer
  hash      Hash identifier & cracker
  info      Network information gatherer
"""

import argparse
import sys
import os

# Add parent dir to path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import banner, error, warn, Colors, c


# ââ Subcommand handlers âââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def cmd_scan(args):
    from modules.port_scanner import scan
    scan(
        host=args.target,
        port_range=args.ports,
        timeout=args.timeout,
        concurrency=args.concurrency,
        output_json=args.output,
    )


def cmd_enum(args):
    from modules.subdomain_enum import enumerate_subdomains
    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]
    enumerate_subdomains(
        domain=args.target,
        wordlist=wordlist,
        threads=args.threads,
        output_json=args.output,
    )


def cmd_grab(args):
    from modules.banner_grabber import grab
    if args.ports:
        ports = []
        for part in args.ports.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
    else:
        ports = [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 27017]
    grab(
        host=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.threads,
        output_json=args.output,
    )


def cmd_fuzz(args):
    from modules.dir_fuzzer import fuzz
    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]
    exts = args.extensions.split(",") if args.extensions else None
    fuzz(
        url=args.target,
        wordlist=wordlist,
        threads=args.threads,
        timeout=args.timeout,
        extensions=exts,
        output_json=args.output,
    )


def cmd_hash(args):
    from modules.hash_tools import analyze
    analyze(
        hash_str=args.hash,
        wordlist_path=args.wordlist,
        crack_it=not args.no_crack,
        output_json=args.output,
    )


def cmd_info(args):
    from modules.network_info import gather
    gather(
        target=args.target,
        do_whois=not args.no_whois,
        do_geo=not args.no_geo,
        do_headers=not args.no_headers,
        output_json=args.output,
    )


# ââ Argument parser âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghost",
        description=c("Ghost Toolkit â Modular Python Security Toolkit", Colors.GREEN),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{c('Examples:', Colors.CYAN)}
  {c('python ghost.py scan', Colors.GREEN)} example.com --ports 1-1000
  {c('python ghost.py enum', Colors.GREEN)} example.com --threads 100
  {c('python ghost.py grab', Colors.GREEN)} 192.168.1.1 --ports 22,80,443
  {c('python ghost.py fuzz', Colors.GREEN)} http://example.com -e .php,.bak
  {c('python ghost.py hash', Colors.GREEN)} 5f4dcc3b5aa765d61d8327deb882cf99
  {c('python ghost.py info', Colors.GREEN)} example.com

{c('Always use on systems you own or have explicit permission to test.', Colors.YELLOW)}
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ââ scan ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    p_scan = sub.add_parser("scan", help="TCP port scanner")
    p_scan.add_argument("target",                       help="Target host/IP")
    p_scan.add_argument("-p", "--ports",  default="1-1024", help="Port range (e.g. 1-65535 or 80,443,8080)")
    p_scan.add_argument("-t", "--timeout",type=float, default=1.0, help="Connection timeout (default 1.0s)")
    p_scan.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrent connections (default 500)")
    p_scan.add_argument("-o", "--output",                help="Save results to JSON file")

    # ââ enum ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    p_enum = sub.add_parser("enum", help="Subdomain enumerator")
    p_enum.add_argument("target",                       help="Target domain (e.g. example.com)")
    p_enum.add_argument("-w", "--wordlist",              help="Custom wordlist file")
    p_enum.add_argument("-T", "--threads", type=int, default=50, help="Threads (default 50)")
    p_enum.add_argument("-o", "--output",                help="Save results to JSON file")

    # ââ grab ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    p_grab = sub.add_parser("grab", help="Service banner grabber")
    p_grab.add_argument("target",                       help="Target host/IP")
    p_grab.add_argument("-p", "--ports",                 help="Ports to probe (e.g. 22,80,443 or 1-1024)")
    p_grab.add_argument("-t", "--timeout", type=float, default=3.0, help="Socket timeout (default 3.0s)")
    p_grab.add_argument("-T", "--threads", type=int, default=20, help="Threads (default 20)")
    p_grab.add_argument("-o", "--output",                help="Save results to JSON file")

    # ââ fuzz ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    p_fuzz = sub.add_parser("fuzz", help="Directory/file fuzzer")
    p_fuzz.add_argument("target",                       help="Target URL (e.g. http://example.com)")
    p_fuzz.add_argument("-w", "--wordlist",              help="Custom wordlist file")
    p_fuzz.add_argument("-e", "--extensions",            help="File extensions to append (e.g. .php,.bak,.txt)")
    p_fuzz.add_argument("-T", "--threads", type=int, default=30, help="Threads (default 30)")
    p_fuzz.add_argument("-t", "--timeout", type=float, default=5.0, help="Request timeout (default 5.0s)")
    p_fuzz.add_argument("-o", "--output",                help="Save results to JSON file")

    # ââ hash ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    p_hash = sub.add_parser("hash", help="Hash identifier & cracker")
    p_hash.add_argument("hash",                         help="Hash string to analyze")
    p_hash.add_argument("-w", "--wordlist",              help="Wordlist for cracking (default: built-in sample)")
    p_hash.add_argument("--no-crack", action="store_true", help="Skip cracking attempt")
    p_hash.add_argument("-o", "--output",                help="Save results to JSON file")

    # ââ info ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
    p_info = sub.add_parser("info", help="Network information gatherer")
    p_info.add_argument("target",                       help="Target domain, hostname, or IP")
    p_info.add_argument("--no-whois",   action="store_true", help="Skip WHOIS lookup")
    p_info.add_argument("--no-geo",     action="store_true", help="Skip IP geolocation")
    p_info.add_argument("--no-headers", action="store_true", help="Skip HTTP header fetch")
    p_info.add_argument("-o", "--output",                help="Save results to JSON file")

    return parser


# ââ Entry point âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def main():
    banner()

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "scan": cmd_scan,
        "enum": cmd_enum,
        "grab": cmd_grab,
        "fuzz": cmd_fuzz,
        "hash": cmd_hash,
        "info": cmd_info,
    }

    try:
        handlers[args.command](args)
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user")
        sys.exit(0)
    except Exception as ex:
        error(f"Unexpected error: {ex}")
        if os.getenv("GHOST_DEBUG"):
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
