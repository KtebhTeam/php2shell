# PHP2SHELL · 1337Scanner · 1337Assessor

An educational and defensive security toolkit for authorized vulnerability assessment and PHP version verification. This project combines a non-invasive scanner with an application-level upload handler analyzer for testing system resilience.

- Repository: https://github.com/KtebhTeam/php2shell
- Telegram: https://t.me/alktebh
- Credits: A8FitHaCkEr · KTEBH WARRIORS TEAM · 1337-TE4M
- License: Educational and Authorized Testing Only

---
<img width="1410" height="437" alt="3243w2ge" src="https://github.com/user-attachments/assets/976a07c0-958a-460f-ab53-675683fc0d9a" />

## Table of Contents

1. Overview
2. Tool Matrix
3. Requirements
4. Repository Structure
5. Installation on Windows
6. Installation on Unix (Linux / macOS)
7. Quick Start
8. 1337Scanner (Defensive)
9. 1337Assessor (Validation)
10. Output Files
11. Vulnerability Coverage
12. Legal Notice & Disclaimer

---

## 1. Overview

PHP2SHELL is a Python toolkit composed of two independent tools that share a common library. It is designed strictly for security researchers, system administrators, and educators to verify system configurations safely.

- `1337scanner.py` — reads HTTP headers and TLS metadata, compares detected PHP versions against a local advisory matrix, and reports a verdict. No payloads, no file uploads.
- `1337assessor.py` — an assessment engine covering the PHP core `session.upload_progress` surface, automated include parameter discovery, and application-level upload handler analysis.

Both tools share the same color palette, User-Agent pool, and target-file format, so they can be chained in a single assessment engagement.

---

## 2. Tool Matrix

| Capability | 1337Scanner | 1337Assessor |
|---|---|---|
| PHP version fingerprint | yes | yes |
| TLS metadata inspection | yes | yes |
| Detect exposed headers | yes | yes |
| Core `session.upload_progress` probe | no | yes |
| Memory calibration | no | yes |
| Timing-based detection | no | yes |
| Auto-parameter discovery | no | yes |
| Application upload discovery | no | yes |
| File upload handling test | no | yes |
| Mass scanning | no | yes |

---

## 3. Requirements

- Python 3.8 or newer
- pip
- Network access to target
- Written authorization for any testing

Libraries:

```
requests>=2.31.0
rich>=13.7.0
beautifulsoup4>=4.12.0
urllib3>=2.0.0
colorama>=0.4.6
```

Save these lines as `1337Requirements.txt` in the project root.

---

## 4. Repository Structure

```
php2shell/
├── 1337scanner.py
├── 1337assessor.py
├── 1337Requirements.txt
├── Install.bat
├── install.sh
├── targets.txt
└── README.md
```

---

## 5. Installation on Windows

### 5.1 Clone the repository

Open Command Prompt or PowerShell:

```cmd
git clone https://github.com/KtebhTeam/php2shell.git
cd php2shell
```

### 5.2 Automated installation

```cmd
Install.bat
```

The batch script checks Python, installs requirements, and verifies the setup.

### 5.3 Manual installation

```cmd
python -m pip install --upgrade pip
python -m pip install -r 1337Requirements.txt
```

---

## 6. Installation on Unix (Linux / macOS)

### 6.1 Clone the repository

```bash
git clone https://github.com/KtebhTeam/php2shell.git
cd php2shell
```

### 6.2 Automated installation

```bash
chmod +x install.sh
./install.sh
```

### 6.3 Manual installation

Debian and Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
python3 -m pip install --upgrade pip
python3 -m pip install -r 1337Requirements.txt
```

macOS:

```bash
brew install python git
python3 -m pip install --upgrade pip
python3 -m pip install -r 1337Requirements.txt
```

---

## 7. Quick Start

Run the scanner:
```bash
python 1337scanner.py
```

Run the assessment engine:
```bash
python 1337assessor.py
```

Prepare `targets.txt`:
```
example.com
https://target.example.com/upload.php
10.0.0.5
```

---

## 8. 1337Scanner (Defensive)

The scanner sends a single GET request per target and reads headers without any exploitation.

| Verdict | Meaning |
|---|---|
| PATCHED | PHP version is safe. |
| VULNERABLE | PHP version is outdated. |
| UNKNOWN | Could not detect version. |
| ERROR | Connection failed. |

---

## 9. 1337Assessor (Validation)

The assessment engine tests `session.upload_progress` surface, auto-parameter discovery, and file upload handling to verify system resilience.

---

## 10. Output Files

| File | Content |
|---|---|
| results.txt | TSV of vulnerable targets |
| report.json | JSON report |

---

## 11. Vulnerability Coverage

| Surface | PHP feature | Detection |
|---|---|---|
| 109618 | memory_limit exhaustion | OOM strings, timing |
| 109619 | session.upload_progress write | session strings |
| 115560 | session.serialize_handler | decode errors |
| LFI | include with user path | include errors |

---

## 12. Legal Notice & Disclaimer

Using these tools against any system without prior written authorization is illegal. Authorization must be in writing and name the target scope.

---

## Credits

- Repository: https://github.com/KtebhTeam/php2shell
- Telegram: https://t.me/alktebh
- A8FitHaCkEr
- KTEBH WARRIORS TEAM · 1337-TE4M
