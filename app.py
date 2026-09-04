"""
Kali Linux Ethical Security Toolkit — Backend API
Authorised use only. All scans require authenticated session.
Run with: python3 app.py
"""

import os, json, subprocess, re, hashlib, secrets, time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)

# ─── User store ───────────────────────────────────────────────────────────────
USERS = {
    "admin":   hashlib.sha256("KaliAdmin2024!".encode()).hexdigest(),
    "analyst": hashlib.sha256("Analyst#Sec99".encode()).hexdigest(),
}
SESSIONS = {}   # token -> {user, expires}
SCAN_LOG = []   # audit trail

def make_token(user):
    tok = secrets.token_hex(32)
    SESSIONS[tok] = {"user": user, "expires": datetime.utcnow() + timedelta(hours=8)}
    return tok

def require_auth(f):
    @wraps(f)
    def deco(*args, **kwargs):
        tok = request.headers.get("X-Auth-Token")
        if not tok or tok not in SESSIONS:
            return jsonify({"error": "Unauthorized"}), 401
        e = SESSIONS[tok]
        if datetime.utcnow() > e["expires"]:
            del SESSIONS[tok]
            return jsonify({"error": "Session expired"}), 401
        request.current_user = e["user"]
        return f(*args, **kwargs)
    return deco

def valid_target(t):
    t = t.strip()
    if not t or len(t) > 253: return False
    if re.search(r'[;&|`$<>\\\'"()\[\]{}\n\r\t]', t): return False
    return True

def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1

def audit(user, scan_type, target):
    SCAN_LOG.append({
        "user": user, "type": scan_type,
        "target": target, "ts": datetime.utcnow().isoformat()
    })

# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json()
    u, p = d.get("username","").strip(), d.get("password","")
    if u in USERS and USERS[u] == hashlib.sha256(p.encode()).hexdigest():
        return jsonify({"token": make_token(u), "user": u})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    tok = request.headers.get("X-Auth-Token")
    SESSIONS.pop(tok, None)
    return jsonify({"message": "Logged out"})

@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"user": request.current_user})

@app.route("/api/log", methods=["GET"])
@require_auth
def get_log():
    return jsonify({"log": SCAN_LOG[-100:]})

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

# ─── Helper: parse nmap port lines ────────────────────────────────────────────
def parse_ports(stdout):
    ports = []
    for line in stdout.split("\n"):
        m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line)
        if m:
            ports.append({
                "port": int(m.group(1)), "protocol": m.group(2),
                "state": m.group(3), "service": m.group(4),
                "version": m.group(5).strip()
            })
    return ports

# ─── Ping / Host Discovery ────────────────────────────────────────────────────
@app.route("/api/scan/ping", methods=["POST"])
@require_auth
def ping():
    d = request.get_json(); target = d.get("target","").strip()
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    audit(request.current_user, "ping", target)
    out, _, _ = run(["nmap","-sn","-T4", target])
    hosts = []
    lines = out.split("\n")
    for i,line in enumerate(lines):
        if "Nmap scan report for" in line:
            host = line.replace("Nmap scan report for","").strip()
            ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host)
            hostname = re.sub(r'\s*\(.*\)','',host).strip()
            ip = ip_m.group(1) if ip_m else hostname
            lat = mac = None
            for j in range(i+1, min(i+6,len(lines))):
                lm = re.search(r'\(([0-9.]+)s latency\)', lines[j])
                if lm: lat = round(float(lm.group(1))*1000, 2)
                if "MAC Address:" in lines[j]: mac = lines[j].replace("MAC Address:","").strip()
            hosts.append({"hostname":hostname,"ip":ip,"status":"up","latency_ms":lat,"mac":mac})
    return jsonify({"target":target,"hosts_up":len(hosts),"hosts":hosts,
                    "raw":out,"by":request.current_user,"ts":datetime.utcnow().isoformat()})

# ─── Port Scan ────────────────────────────────────────────────────────────────
@app.route("/api/scan/ports", methods=["POST"])
@require_auth
def port_scan():
    d = request.get_json(); target = d.get("target","").strip(); mode = d.get("type","quick")
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    audit(request.current_user, f"ports:{mode}", target)
    cmds = {
        "quick": ["nmap","-T4","-F","--open","-sV","--version-intensity","3", target],
        "full":  ["nmap","-T4","-p-","--open","-sV", target],
        "udp":   ["nmap","-sU","-T4","--top-ports","100", target],
    }
    cmd = cmds.get(mode, cmds["quick"])
    out, _, _ = run(cmd, 180)
    ports = parse_ports(out)
    os_g = next((l.replace("OS details:","").strip() for l in out.split("\n") if "OS details:" in l), None)
    return jsonify({"target":target,"scan_type":mode,"ports":ports,"os_guess":os_g,
                    "raw":out,"by":request.current_user,"ts":datetime.utcnow().isoformat()})

# ─── Service & Version ────────────────────────────────────────────────────────
@app.route("/api/scan/service", methods=["POST"])
@require_auth
def service():
    d = request.get_json(); target = d.get("target","").strip()
    ports = d.get("ports","22,80,443,8080,3306,5432,6379,27017")
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    if not re.match(r'^[\d,\-]+$', str(ports)): return jsonify({"error": "Invalid ports"}), 400
    audit(request.current_user, "service", target)
    out, _, _ = run(["nmap","-sV","--version-intensity","7","-p",str(ports),"-T4", target])
    services = parse_ports(out)
    # Vuln script on open ports
    open_p = [str(s["port"]) for s in services if s["state"]=="open"]
    vulns = []
    if open_p:
        vo, _, _ = run(["nmap","--script","vuln","-p",",".join(open_p),"-sV", target], 180)
        for line in vo.split("\n"):
            if any(k in line for k in ["CVE-","VULNERABLE","CRITICAL","HIGH"]):
                vulns.append(line.replace("|","").strip())
    return jsonify({"target":target,"ports":ports,"services":services,
                    "vulnerabilities":vulns[:30],"raw":out,
                    "by":request.current_user,"ts":datetime.utcnow().isoformat()})

# ─── DNS Enumeration ──────────────────────────────────────────────────────────
@app.route("/api/scan/dns", methods=["POST"])
@require_auth
def dns():
    d = request.get_json(); target = d.get("target","").strip()
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    audit(request.current_user, "dns", target)
    records = {}
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        o, _, rc = run(["host","-t",rtype, target], 15)
        if rc==0 and o.strip() and "not found" not in o.lower() and "has no" not in o.lower():
            records[rtype] = [l.strip() for l in o.strip().split("\n") if l.strip()]
    # Subdomain brute via nmap
    so, _, _ = run(["nmap","-sn","--script","dns-brute","--script-args","dns-brute.threads=5", target], 60)
    subs = []
    for line in so.split("\n"):
        m = re.search(r'\|\s+([a-zA-Z0-9._-]+\.' + re.escape(target) + r')\s+-\s+([\d.]+)', line)
        if m: subs.append({"subdomain":m.group(1),"ip":m.group(2)})
    return jsonify({"target":target,"records":records,"subdomains":subs,
                    "by":request.current_user,"ts":datetime.utcnow().isoformat()})

# ─── WHOIS ────────────────────────────────────────────────────────────────────
@app.route("/api/scan/whois", methods=["POST"])
@require_auth
def whois():
    d = request.get_json(); target = d.get("target","").strip()
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    audit(request.current_user, "whois", target)
    out, _, _ = run(["whois", target], 30)
    parsed = {}
    fields = {
        "Registrar":   r"Registrar:\s*(.+)",
        "Registrant":  r"Registrant (?:Name|Organization):\s*(.+)",
        "Created":     r"Creation Date:\s*(.+)",
        "Expires":     r"Registry Expiry Date:\s*(.+)",
        "Updated":     r"Updated Date:\s*(.+)",
        "Name Servers":r"Name Server:\s*(.+)",
        "Status":      r"Domain Status:\s*(.+)",
        "Country":     r"Registrant Country:\s*(.+)",
    }
    for k,p in fields.items():
        ms = re.findall(p, out, re.IGNORECASE)
        if ms: parsed[k] = [m.strip() for m in ms] if len(ms)>1 else ms[0].strip()
    return jsonify({"target":target,"parsed":parsed,"raw":out[:6000],
                    "by":request.current_user,"ts":datetime.utcnow().isoformat()})

# ─── SSL/TLS ──────────────────────────────────────────────────────────────────
@app.route("/api/scan/ssl", methods=["POST"])
@require_auth
def ssl():
    d = request.get_json(); target = d.get("target","").strip(); port = int(d.get("port",443))
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    audit(request.current_user, "ssl", f"{target}:{port}")
    out, _, _ = run(["nmap","--script","ssl-cert,ssl-enum-ciphers","-p",str(port), target], 60)
    cert, ciphers, warnings = {}, [], []
    for line in out.split("\n"):
        l = line.strip()
        if "Subject:" in l: cert["subject"] = l.replace("|","").replace("Subject:","").strip()
        if "Issuer:"  in l: cert["issuer"]  = l.replace("|","").replace("Issuer:","").strip()
        if "Not valid before:" in l: cert["valid_from"]  = l.replace("|","").replace("Not valid before:","").strip()
        if "Not valid after:"  in l: cert["valid_until"] = l.replace("|","").replace("Not valid after:","").strip()
        if any(w in l.lower() for w in ["md5","rc4","des","null"]): warnings.append(f"Weak: {l}")
        if "TLS_" in l or "SSL_" in l: ciphers.append(l.replace("|","").strip())
        if "VULNERABLE" in l or "WARNING" in l: warnings.append(l.replace("|","").strip())
    return jsonify({"target":f"{target}:{port}","certificate":cert,
                    "ciphers":ciphers[:20],"warnings":warnings,"raw":out,
                    "by":request.current_user,"ts":datetime.utcnow().isoformat()})

# ─── OS Detection ─────────────────────────────────────────────────────────────
@app.route("/api/scan/os", methods=["POST"])
@require_auth
def os_detect():
    d = request.get_json(); target = d.get("target","").strip()
    if not valid_target(target): return jsonify({"error": "Invalid target"}), 400
    audit(request.current_user, "os", target)
    out, _, _ = run(["nmap","-O","--osscan-guess","-T4","-F", target], 90)
    guesses, device = [], None
    for line in out.split("\n"):
        if "OS details:" in line: guesses.append({"os":line.replace("OS details:","").strip(),"acc":100})
        m = re.search(r"OS guesses: (.+)", line)
        if m:
            for g in m.group(1).split(","):
                am = re.search(r'(.+)\((\d+)%\)', g.strip())
                if am: guesses.append({"os":am.group(1).strip(),"acc":int(am.group(2))})
        if "Device type:" in line: device = line.replace("Device type:","").strip()
    return jsonify({"target":target,"guesses":guesses[:5],"device_type":device,
                    "raw":out,"by":request.current_user,"ts":datetime.utcnow().isoformat()})

if __name__ == "__main__":
    print("=" * 60)
    print("  Kali Ethical Toolkit — Backend")
    print("  Default users:  admin / KaliAdmin2024!")
    print("                  analyst / Analyst#Sec99")
    print("  CHANGE PASSWORDS before deploying!")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5050, debug=False)
