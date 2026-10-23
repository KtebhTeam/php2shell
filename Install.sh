#!/usr/bin/env bash
set -e

B='\033[94m'; W='\033[97m'; BOLD='\033[1m'; D='\033[2m'; N='\033[0m'
c() { printf "%b%s%b" "$1" "$2" "$N"; }

clear
c "$B$BOLD" "  ============================================\n"
c "$W$BOLD" "   1337Scanner + 1337Assessor - Unix Installer\n"
c "$B"      "   Telegram: https://t.me/alktebh\n"
c "$W"      "   Credits: A8FitHaCkEr & KTEBH WARRIORS\n"
c "$B$BOLD" "  ============================================\n\n"

if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else c "$W$BOLD" "[!] Python not found. sudo apt install python3 python3-pip\n"; exit 1; fi

c "$B" "[+] "; c "$W" "Detected: $($PY --version 2>&1)\n\n"

[ "$1" = "--venv" ] && {
    [ ! -d .venv ] && $PY -m venv .venv
    source .venv/bin/activate; PY=python
    c "$W" "[+] venv activated.\n\n"
}

c "$B" "[*] "; c "$W" "Upgrading pip...\n"
$PY -m pip install --upgrade pip --quiet
c "$W" "[+] pip upgraded.\n\n"

c "$B" "[*] "; c "$W" "Installing libraries...\n"
$PY -m pip install --quiet requests rich beautifulsoup4 urllib3 colorama || {
    c "$W$BOLD" "[!] pip failed. Try: sudo apt install python3-pip\n"; exit 1; }
c "$W" "[+] Libraries installed.\n\n"

if [ ! -f targets.txt ]; then
    printf 'example.com\nhttps://www.google.com\n# one URL per line, # = comment\n' > targets.txt
    c "$W" "[+] targets.txt created.\n\n"
fi

c "$B" "[*] "; c "$W" "Verifying...\n"
$PY -c "import requests, rich, bs4, urllib3, colorama; print('[+] All modules OK')" || exit 1

# تحديث الأسماء لتكون آمنة
chmod +x 1337scanner.py 1337assessor.py 2>/dev/null || true

while true; do
    echo
    c "$B$BOLD" "  ============================================\n"
    c "$W$BOLD" "   Select what to launch:\n"
    c "$B$BOLD" "  ============================================\n\n"
    c "$W" "    [1] "; c "$B$BOLD" "1337Scanner"; c "$D" " (defensive)\n"
    c "$W" "    [2] "; c "$B$BOLD" "1337Assessor"; c "$D" " (validation)\n"
    c "$W" "    [3] "; c "$B$BOLD" "README.md\n"
    c "$W" "    [5] "; c "$B$BOLD" "Reinstall libraries\n"
    c "$W" "    [6] "; c "$B$BOLD" "Edit targets.txt\n"
    c "$W" "    [Q] "; c "$B$BOLD" "Quit\n\n"
    printf "%b  select > %b" "$B$BOLD" "$N"
    read -r ch

    case "$ch" in
        1) clear; $PY 1337scanner.py || true ;;
        2) clear
           c "$W$BOLD" "  WARNING: 1337Assessor performs active validation tests.\n"
           c "$W" "  Use ONLY on targets you have WRITTEN authorization for.\n\n"
           printf "%b  Type YES to continue: %b" "$B$BOLD" "$N"
           read -r ok
           [ "$ok" = "YES" ] && { clear; $PY 1337assessor.py || true; } || c "$W" "[*] Aborted.\n" ;;
        3) clear; [ -f README.md ] && ${PAGER:-less} README.md || c "$W" "[!] missing.\n" ;;
        5) $PY -m pip install --upgrade --force-reinstall requests rich beautifulsoup4 urllib3 colorama; c "$W" "[+] Done.\n" ;;
        6) [ -f targets.txt ] || echo "example.com" > targets.txt; ${EDITOR:-nano} targets.txt || true ;;
        q|Q) echo; c "$W" "[*] Goodbye.\n"; exit 0 ;;
        *) c "$W" "[!] Invalid choice.\n" ;;
    esac
done
