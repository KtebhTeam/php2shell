# https://t.me/alktebh
# Coded By A8FitHaCkEr & 1337-TE4M , KTEBH WARRIORS.
import sys
import re
import ssl
import json
import socket
import argparse
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import colorama
    colorama.init(autoreset=False)
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

if sys.platform == "win32" and not _HAS_COLORAMA:
    os.system("")

WHITE = "\033[97m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def c(text, *styles):
    codes = ""
    for s in styles:
        codes += {"white": WHITE, "blue": BLUE, "bold": BOLD, "dim": DIM}.get(s, "")
    return f"{codes}{text}{RESET}"


LOGO = r"""
 ██ ██████  ██████  ███████       ███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  
███      ██      ██      ██       ██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ 
 ██  █████   █████      ██  █████ ███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  
 ██      ██      ██    ██              ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ 
 ██ ██████  ██████     ██         ███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██ 
"""

BANNER = (
    f"{c(LOGO, 'blue', 'bold')}"
    f"{c('  telegram:', 'blue')} {c('https://t.me/alktebh', 'white')}   "
    f"{c('credits:', 'blue')} {c('A8FitHaCkEr & KTEBH WARRIORS', 'white')}\n"
)

FIXED = {
    (8, 5): 12,
    (8, 4): 27,
    (8, 3): 36,
    (8, 2): 35,
}
EOL_BRANCHES = {(7, 4), (8, 0), (8, 1)}
VERSION_HEADERS = ["X-Powered-By", "Server", "X-PHP-Version", "X-Backend-Server"]

DEFAULT_TARGETS_FILE = "targets.txt"


def build_session(verify_tls=True, timeout=10):
    s = requests.Session()
    retries = Retry(total=2, backoff_factor=0.4,
                    status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (BlueTeam-Assessment/1.0)",
        "Accept": "text/html,application/xhtml+xml",
    })
    s.verify = verify_tls
    s.timeout = timeout
    return s


def parse_php_version(text):
    m = re.search(r"PHP[/ ]?(\d+)\.(\d+)\.(\d+)", text, re.IGNORECASE)
    if m:
        return tuple(int(x) for x in m.groups())
    m = re.search(r"PHP[/ ]?(\d+)\.(\d+)", text, re.IGNORECASE)
    if m:
        return (int(m.group(1)), int(m.group(2)), None)
    return None


def classify(version):
    if version is None:
        return "UNKNOWN", "PHP version could not be detected — cannot be assessed externally."
    major, minor, patch = version
    branch = (major, minor)
    human = f"{major}.{minor}" + (f".{patch}" if patch is not None else ".x")

    if branch in EOL_BRANCHES:
        return "VULNERABLE", f"PHP {human} is an end-of-life branch — vulnerable to PHP2Shell with no official fix."
    if branch in FIXED:
        if patch is None:
            return "UNKNOWN", f"PHP {human}.x — patch level unknown; safe minimum is {FIXED[branch]}."
        if patch >= FIXED[branch]:
            return "PATCHED", f"PHP {human} >= safe minimum ({major}.{minor}.{FIXED[branch]}) — appears patched."
        return "VULNERABLE", f"PHP {human} < {major}.{minor}.{FIXED[branch]} — vulnerable to PHP2Shell. Upgrade required."
    if branch > (8, 5):
        return "PATCHED", f"PHP {human} is newer than known branches — check release notes to confirm."
    return "UNKNOWN", f"PHP {human} is not in the local advisory database."


def check_headers(session, url):
    findings = []
    try:
        r = session.get(url, allow_redirects=True, timeout=session.timeout)
    except requests.exceptions.SSLError:
        findings.append(("WARN", "TLS error — retry with --insecure if the certificate is self-signed."))
        return None, findings, None
    except requests.exceptions.RequestException as e:
        findings.append(("ERROR", f"Connection failed: {e}"))
        return None, findings, None

    headers = r.headers
    for h in VERSION_HEADERS:
        if h in headers:
            findings.append(("INFO", f"{h}: {headers[h]}"))

    if "PHP" in headers.get("X-Powered-By", ""):
        findings.append(("WARN", "expose_php is enabled — the version is disclosed to attackers. Consider disabling it."))

    return r, findings, r.status_code
# https://t.me/alktebh
# Coded By A8FitHaCkEr & 1337-TE4M , KTEBH WARRIORS.


def check_tls(host, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "unknown")
                return [("INFO", f"TLS: {ssock.version()}, certificate expires {not_after}")]
    except Exception as e:
        return [("WARN", f"Could not verify TLS: {e}")]


def assess_target(session, raw_url):
    url = raw_url if "://" in raw_url else "https://" + raw_url
    parsed = urlparse(url)
    host = parsed.hostname

    result = {
        "target": raw_url,
        "normalized": url,
        "host": host,
        "status": "UNKNOWN",
        "message": "",
        "php_version": None,
        "http_status": None,
        "headers": [],
        "tls": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if not host:
        result["message"] = "Invalid URL."
        return result

    resp, header_findings, http_status = check_headers(session, url)
    result["headers"] = [{"level": l, "message": m} for l, m in header_findings]
    result["http_status"] = http_status
    result["tls"] = [{"level": l, "message": m} for l, m in check_tls(host)]

    version = None
    if resp is not None:
        version = parse_php_version(resp.headers.get("X-Powered-By", "")) or \
                  parse_php_version(resp.headers.get("Server", ""))
    if version:
        result["php_version"] = ".".join(str(x) for x in version if x is not None)

    status, message = classify(version)
    result["status"] = status
    result["message"] = message
    return result


def read_targets(path):
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def _level_color(level):
    return {"INFO": "white", "WARN": "blue", "ERROR": "blue"}.get(level, "white")


def _status_color(status):
    if status == "VULNERABLE":
        return "blue", "bold"
    return "white", "bold"
# https://t.me/alktebh
# Coded By A8FitHaCkEr & 1337-TE4M , KTEBH WARRIORS.


def print_result(idx, total, r):
    print()
    print(c(f"[{idx}/{total}] ", "blue", "bold") + c(r["target"], "white", "bold"))
    print(c("    HTTP status : ", "blue") + c(str(r["http_status"]), "white"))
    print(c("    PHP version : ", "blue") + c(r["php_version"] or "unknown", "white"))
    for h in r["headers"]:
        print(c(f"    [{h['level']}] ", _level_color(h["level"])) + c(h["message"], "white"))
    for t in r["tls"]:
        print(c(f"    [{t['level']}] ", _level_color(t["level"])) + c(t["message"], "white"))
    sc, sb = _status_color(r["status"])
    print(c("    VERDICT     : ", "blue") + c(f"[{r['status']}]", sc, sb) + c(f" {r['message']}", "white"))


def print_menu():
    print(c(BANNER, "white"))
    print(c("  [", "white") + c("1", "blue", "bold") + c("] ", "white")
          + c("Custom Target", "white", "bold")
          + c("  — enter a single URL to assess", "dim"))
    print(c("  [", "white") + c("2", "blue", "bold") + c("] ", "white")
          + c(f'Target From File "{DEFAULT_TARGETS_FILE}"', "white", "bold")
          + c("  — assess every URL in the file", "dim"))
    print(c("  [", "white") + c("q", "blue", "bold") + c("] ", "white")
          + c("Quit", "white", "bold"))
    print()


def prompt(text, default=""):
    sys.stdout.write(c(text, "blue", "bold"))
    sys.stdout.flush()
    try:
        return input().strip() or default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def interactive_select():
    print_menu()
    choice = prompt("  select > ")
    if choice.lower() == "q":
        return None, None
    if choice == "1":
        url = prompt("  Enter URL: ")
        if not url:
            print(c("  No URL provided — exiting.", "blue", "bold"))
            return None, None
        return "single", url
    if choice == "2":
        if not os.path.isfile(DEFAULT_TARGETS_FILE):
            print(c(f"  [!] File '{DEFAULT_TARGETS_FILE}' not found in current directory.", "blue", "bold"))
            print(c(f"      Create it and put one URL per line.", "white"))
            return None, None
        targets = read_targets(DEFAULT_TARGETS_FILE)
        if not targets:
            print(c(f"  [!] '{DEFAULT_TARGETS_FILE}' is empty.", "blue", "bold"))
            return None, None
        return "file", DEFAULT_TARGETS_FILE
    print(c("  Invalid choice.", "blue", "bold"))
    return None, None


def run_scan(targets, args):
    session = build_session(verify_tls=not args.insecure, timeout=args.timeout)
    results = []
    summary = {"PATCHED": 0, "VULNERABLE": 0, "UNKNOWN": 0, "ERROR": 0}

    print()
    print(c(f"[*] Assessing {len(targets)} target(s)", "blue", "bold"))
    print(c("=" * 60, "blue"))

    for i, t in enumerate(targets, 1):
        r = assess_target(session, t)
        results.append(r)
        print_result(i, len(targets), r)
        key = r["status"] if r["status"] in summary else "ERROR"
        summary[key] += 1

    print()
    print(c("=" * 60, "blue"))
    print(c("[*] Summary", "blue", "bold"))
    print(c("    PATCHED    : ", "blue") + c(str(summary['PATCHED']), "white", "bold"))
    print(c("    VULNERABLE : ", "blue") + c(str(summary['VULNERABLE']), "white", "bold"))
    print(c("    UNKNOWN    : ", "blue") + c(str(summary['UNKNOWN']), "white", "bold"))
    print(c("    ERROR      : ", "blue") + c(str(summary['ERROR']), "white", "bold"))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2, ensure_ascii=False)
        print()
        print(c(f"[+] JSON report written to {args.json}", "blue", "bold"))

    return 0 if summary["VULNERABLE"] == 0 else 1


def build_parser():
    parser = argparse.ArgumentParser(
        description=c("1337Scanner v1.2 — defensive assessment for the PHP2Shell vulnerability", "white"))
    parser.add_argument("target", nargs="?", default=None,
                        help="Target URL or path to a targets file (omit to open the menu)")
    parser.add_argument("--insecure", action="store_true", help="Ignore TLS certificate errors")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", metavar="FILE", help="Write a JSON report to FILE")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.target is None:
        mode, value = interactive_select()
        if mode is None:
            sys.exit(0)
        if mode == "single":
            targets = [value]
        else:
            targets = read_targets(value)
            if not targets:
                print(c("[-] Targets file is empty.", "blue", "bold"))
                sys.exit(2)
    else:
        if os.path.isfile(args.target):
            targets = read_targets(args.target)
            if not targets:
                print(c("[-] Targets file is empty.", "blue", "bold"))
                sys.exit(2)
        else:
            targets = [args.target]

    sys.exit(run_scan(targets, args))


if __name__ == "__main__":
    main()
    
# https://t.me/alktebh
# Coded By A8FitHaCkEr & 1337-TE4M , KTEBH WARRIORS.
