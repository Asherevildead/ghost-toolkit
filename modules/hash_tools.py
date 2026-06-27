"""
Ghost Toolkit - Hash Tools
Identify hash types and attempt dictionary-based cracking.
"""

import hashlib
import re
import time
from pathlib import Path
from .utils import info, success, warn, error, result, print_table, Colors, c

# Hash signatures: (name, bit_length, regex)
HASH_PATTERNS = [
    ("MD5",          128, re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("SHA-1",        160, re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("SHA-224",      224, re.compile(r"^[a-f0-9]{56}$", re.I)),
    ("SHA-256",      256, re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA-384",      384, re.compile(r"^[a-f0-9]{96}$", re.I)),
    ("SHA-512",      512, re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("SHA3-256",     256, re.compile(r"^[a-f0-9]{64}$", re.I)),
    ("SHA3-512",     512, re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("NTLM",         128, re.compile(r"^[a-f0-9]{32}$", re.I)),
    ("bcrypt",       None, re.compile(r"^\$2[aby]\$\d{2}\$.{53}$")),
    ("MD5-crypt",    None, re.compile(r"^\$1\$")),
    ("SHA-256-crypt",None, re.compile(r"^\$5\$")),
    ("SHA-512-crypt",None, re.compile(r"^\$6\$")),
    ("Argon2",       None, re.compile(r"^\$argon2")),
    ("scrypt",       None, re.compile(r"^\$scrypt\$")),
    ("PBKDF2",       None, re.compile(r"^pbkdf2")),
    ("CRC32",        32,   re.compile(r"^[a-f0-9]{8}$", re.I)),
    ("Whirlpool",    512,  re.compile(r"^[a-f0-9]{128}$", re.I)),
    ("RIPEMD-160",  160,   re.compile(r"^[a-f0-9]{40}$", re.I)),
    ("Adler-32",    32,    re.compile(r"^[a-f0-9]{8}$", re.I)),
    ("Base64",       None, re.compile(r"^[A-Za-z0-9+/]+=*$")),
]

HASHLIB_MAP = {
    "md5":    "MD5",
    "sha1":   "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_512": "SHA3-512",
}

ROCKYOU_SAMPLE = [
    "123456", "password", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "p@ssw0rd", "admin", "welcome", "login", "pass",
    "hello", "charlie", "donald", "password123", "qwerty123", "iloveyou1",
]


def identify(hash_str: str) -> list[str]:
    """Return list of possible hash types for the given string."""
    hash_str = hash_str.strip()
    matches = []
    for name, bits, pattern in HASH_PATTERNS:
        if pattern.match(hash_str):
            matches.append((name, bits))
    return matches


def crack(
    hash_str: str,
    wordlist_path: str = None,
    algorithms: list[str] = None,
) -> tuple[str, str] | None:
    """
    Attempt to crack a hash using a wordlist.

    Args:
        hash_str:      The hash to crack
        wordlist_path: Path to a newline-delimited wordlist file
        algorithms:    List of hashlib algorithm names to try

    Returns:
        (plaintext, algorithm) if cracked, else None
    """
    hash_str = hash_str.strip().lower()
    algorithms = algorithms or list(HASHLIB_MAP.keys())

    # Load wordlist
    words = ROCKYOU_SAMPLE[:]
    if wordlist_path:
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
            info(f"Loaded {c(str(len(words)), Colors.YELLOW)} words from {wordlist_path}")
        except FileNotFoundError:
            warn(f"Wordlist not found: {wordlist_path} â using built-in sample")

    info(f"Trying {c(str(len(algorithms)), Colors.YELLOW)} algorithm(s) Ã "
         f"{c(str(len(words)), Colors.YELLOW)} words")

    start = time.time()
    attempts = 0

    for algo in algorithms:
        try:
            h = hashlib.new(algo)
        except ValueError:
            continue
        algo_name = HASHLIB_MAP.get(algo, algo.upper())
        for word in words:
            digest = hashlib.new(algo, word.encode()).hexdigest()
            attempts += 1
            if digest == hash_str:
                elapsed = time.time() - start
                return (word, algo_name)

    return None


def analyze(
    hash_str: str,
    wordlist_path: str = None,
    crack_it: bool = True,
    output_json: str = None,
):
    """
    Full hash analysis: identify type + attempt to crack.

    Args:
        hash_str:      Hash string to analyze
        wordlist_path: Optional wordlist path for cracking
        crack_it:      Whether to attempt cracking (default True)
        output_json:   Optional path to save JSON results
    """
    from .utils import save_json

    hash_str = hash_str.strip()
    info(f"Analyzing: {c(hash_str[:30] + ('â¦' if len(hash_str) > 30 else ''), Colors.CYAN)}")
    print()

    # Identify
    matches = identify(hash_str)
    if not matches:
        warn("Hash type not recognized")
    else:
        success(f"Possible type(s): {', '.join(c(m[0], Colors.GREEN) for m in matches)}")
        rows = [[name, str(bits) + " bits" if bits else "variable"] for name, bits in matches]
        print()
        print_table(["HASH TYPE", "BIT LENGTH"], rows)

    print()

    output = {
        "hash": hash_str,
        "identified_as": [m[0] for m in matches],
        "cracked": False,
        "plaintext": None,
        "algorithm": None,
    }

    # Crack
    if crack_it:
        info("Attempting dictionary crackâ¦")
        cracked = crack(hash_str, wordlist_path)
        if cracked:
            plaintext, algo = cracked
            print()
            success(f"CRACKED! [{algo}] {c(hash_str[:16] + 'â¦', Colors.GRAY)} = {c(plaintext, Colors.GREEN + Colors.BOLD)}")
            output.update({"cracked": True, "plaintext": plaintext, "algorithm": algo})
        else:
            warn("Not found in wordlist â try a larger dictionary (rockyou.txt)")
    else:
        info("Crack skipped (pass --crack to enable)")

    if output_json:
        save_json(output, output_json)

    return output
