# ☠ Kali Ethical Security Toolkit

**Authorised use only. Always obtain written permission before scanning any system you do not own.**

A private, self-hosted penetration testing dashboard backed by real `nmap` scans. No data leaves your machine — the backend runs locally, the frontend is a static HTML file.

---

## Features

| Module | What it does |
|---|---|
| **Host Discovery** | Ping sweep a range/CIDR — finds live hosts, MACs, latency |
| **Port Scan** | Quick (top 100), Full (all 65535), or UDP scan via nmap |
| **Service Probe** | Version detection + vuln script (`--script vuln`) |
| **DNS Enum** | A/AAAA/MX/NS/TXT/SOA records + subdomain brute-force |
| **WHOIS** | Registrar, dates, nameservers, country |
| **SSL/TLS Audit** | Certificate details, weak ciphers, vulnerability flags |
| **OS Detection** | OS fingerprinting with confidence scores |
| **Audit Log** | Every scan logged with user + timestamp |

---

## Quick Start (Kali Linux)

```bash
# 1. Clone or copy the repo
git clone <your-repo-url> kali-toolkit
cd kali-toolkit

# 2. Install dependencies
pip3 install flask flask-cors --break-system-packages
apt-get install -y nmap whois dnsutils

# 3. Start the backend (as root for full scan capability)
sudo python3 backend/app.py

# 4. Open the frontend
xdg-open frontend/index.html
# or just open frontend/index.html in any browser
```

---

## Default Credentials

| Username | Password |
|---|---|
| `admin` | `KaliAdmin2024!` |
| `analyst` | `Analyst#Sec99` |

**Change these immediately** — edit the `USERS` dict in `backend/app.py`:

```python
import hashlib
hashlib.sha256("YourNewPassword".encode()).hexdigest()
# paste the output as the hash value
```

---

## Adding Users

In `backend/app.py`:

```python
USERS = {
    "admin":   hashlib.sha256("YourAdminPass".encode()).hexdigest(),
    "analyst": hashlib.sha256("YourAnalystPass".encode()).hexdigest(),
    "newuser": hashlib.sha256("NewPass123!".encode()).hexdigest(),
}
```

---

## Architecture

```
kali-toolkit/
├── backend/
│   ├── app.py            # Flask API — all scan logic lives here
│   └── requirements.txt
├── frontend/
│   └── index.html        # Single-file UI (no build step needed)
├── scripts/
│   └── start.sh          # One-click launcher
└── README.md
```

- **Backend**: Flask on `127.0.0.1:5050` — only accessible from localhost
- **Frontend**: Static HTML — open directly in browser, no server needed
- **Auth**: Token-based (8-hour sessions), all routes protected
- **Audit**: Every scan is logged in memory with user + timestamp + target

---

## Production Hardening (optional)

- Put the backend behind **nginx** with HTTPS if exposing on a LAN
- Replace the in-memory `USERS` / `SESSIONS` with a proper DB (SQLite or Postgres)
- Add rate limiting: `pip3 install flask-limiter`
- Restrict CORS to your specific frontend origin in `app.py`

---

## Legal Notice

This tool is for **authorised security testing only**. Using it against systems without explicit written permission is illegal under the Computer Misuse Act, CFAA, and equivalent laws worldwide. The authors accept no liability for misuse.
