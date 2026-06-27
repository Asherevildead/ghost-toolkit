"""
Ghost Toolkit - Shared utilities: colors, logging, banners, output formatting.
"""

import sys
import json
import logging
import datetime
from typing import Any

# ââ ANSI Color Codes ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    @staticmethod
    def supports_color() -> bool:
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def c(text: str, color: str) -> str:
    """Wrap text in ANSI color if terminal supports it."""
    if Colors.supports_color():
        return f"{color}{text}{Colors.RESET}"
    return text


# ââ Logging âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
def setup_logger(name: str = "ghost", log_file: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ââ Output Helpers ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
def info(msg: str):    print(f"  {c('[*]', Colors.BLUE)}  {msg}")
def success(msg: str): print(f"  {c('[+]', Colors.GREEN)}  {c(msg, Colors.GREEN)}")
def warn(msg: str):    print(f"  {c('[!]', Colors.YELLOW)}  {c(msg, Colors.YELLOW)}")
def error(msg: str):   print(f"  {c('[â]', Colors.RED)}  {c(msg, Colors.RED)}")
def result(msg: str):  print(f"  {c('[â]', Colors.CYAN)}  {msg}")


def banner():
    logo = r"""
   _____ _               _     _______          _ _   _ _
  / ____| |             | |   |__   __|        | | | (_) |
 | |  __| |__   ___  ___| |_     | | ___   ___ | | |  _| |_
 | | |_ | '_ \ / _ \/ __| __|    | |/ _ \ / _ \| | | | | __|
 | |__| | | | | (_) \__ \ |_     | | (_) | (_) | | |_| | |_
  \_____|_| |_|\___/|___/\__|    |_|\___/ \___/|_|_(_)_|\__|
    """
    print(c(logo, Colors.GREEN))
    print(c("  by Asherevildead  |  github.com/Asherevildead/ghost-toolkit", Colors.GRAY))
    print(c("  " + "â" * 60, Colors.GRAY))
    print()


def print_table(headers: list[str], rows: list[list[Any]], color=Colors.CYAN):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    sep = "  " + "â" * (sum(widths) + len(widths) * 3 + 1)
    header_row = "  â " + " â ".join(c(h.ljust(w), color) for h, w in zip(headers, widths)) + " â"

    print(sep)
    print(header_row)
    print(sep)
    for row in rows:
        print("  â " + " â ".join(str(cell).ljust(w) for cell, w in zip(row, widths)) + " â")
    print(sep)


def save_json(data: Any, filename: str):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    success(f"Results saved â {filename}")


def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
