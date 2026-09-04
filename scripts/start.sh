#!/usr/bin/env bash
# Kali Ethical Toolkit — Quick Start
# Run as root (required for OS detection & raw packet scans)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔══════════════════════════════════════════════╗"
echo "║   Kali Ethical Security Toolkit              ║"
echo "║   Authorised Use Only                        ║"
echo "╚══════════════════════════════════════════════╝"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Warning: Run as root for full scan capabilities (OS detection, SYN scans)"
fi

# Install system deps
echo "[*] Checking system dependencies..."
apt-get install -y nmap whois dnsutils python3 python3-pip -qq 2>/dev/null || true

# Install Python deps
echo "[*] Installing Python packages..."
pip3 install flask flask-cors --break-system-packages -q

# Generate a fresh secret key
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Start backend
echo "[*] Starting backend on http://127.0.0.1:5050"
cd "$ROOT_DIR/backend"
python3 app.py &
BACKEND_PID=$!
echo "[+] Backend PID: $BACKEND_PID"

sleep 2

# Open frontend if a browser is available
if command -v xdg-open &>/dev/null; then
    echo "[*] Opening frontend..."
    xdg-open "$ROOT_DIR/frontend/index.html" &
fi

echo ""
echo "[+] Ready! Open frontend/index.html in your browser."
echo "[+] Default creds: admin / KaliAdmin2024!  (change in backend/app.py)"
echo "[+] Press Ctrl+C to stop."
echo ""
wait $BACKEND_PID
