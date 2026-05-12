from flask import Flask, request
from pathlib import Path
from datetime import datetime
import hashlib
import csv

app = Flask(__name__)

# ── Paths — all files live in the SAME folder as this script ─────────────────
BASE           = Path(__file__).resolve().parent
LOG_PATH       = BASE / "blocked_ips.txt"
BLOCKLIST_PATH = BASE / "blocked_ips.txt"

LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── Helpers ───────────────────────────────────────────────────────────────────
def is_ip_blocked(ip: str) -> bool:
    """Re-reads file on every request so blocks take effect immediately."""
    if not BLOCKLIST_PATH.exists():
        return False
    blocked = {line.strip() for line in BLOCKLIST_PATH.read_text().splitlines() if line.strip()}
    return ip in blocked


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()[:10]


def write_log(ip: str, username: str, password_hash: str, timestamp: str) -> None:
    with open(LOG_PATH, "a", newline="") as f:
        csv.writer(f).writerow([ip, username, password_hash, timestamp])


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    ip        = request.remote_addr
    username  = request.form.get("username", "")
    password  = request.form.get("password", "")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if is_ip_blocked(ip):
        print(f"[BLOCKED]  {ip} — 403 returned")
        return "Access Denied (IP Blocked)", 403

    write_log(ip, username, hash_password(password), timestamp)
    print(f"[LOGIN]    {ip} | {username} | {timestamp}")
    return "Login received", 200


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}, 200


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print(f"[*] Server starting on http://0.0.0.0:5000")
    print(f"[*] Log file  : {LOG_PATH}")
    print(f"[*] Blocklist : {BLOCKLIST_PATH}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
