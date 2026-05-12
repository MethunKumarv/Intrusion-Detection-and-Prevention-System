"""
ids_monitor.py
--------------
Continuously monitors login_attempts.csv for new entries, runs each through
the trained ML model, and blocks attacker IPs automatically.
"""

from pathlib import Path
from datetime import datetime
import pandas as pd
import joblib
import json
import time

# ── Paths — all files live in the SAME folder as this script ─────────────────
BASE           = Path(__file__).resolve().parent
LOG_PATH       = BASE / "logs" / "login_attempts.csv"
BLOCKLIST_PATH = BASE / "blocked_ips.txt"
AUDIT_DIR      = BASE / "audit_logs"
MODEL_PATH     = BASE / "model" / "model.pkl"

AUDIT_DIR.mkdir(parents=True, exist_ok=True)

FEATURES = [
    "username_len", "password_len",
    "req_count", "unique_users", "unique_pwds",
    "hour", "time_gap"
]

POLL_INTERVAL = 2

# ── Load model ────────────────────────────────────────────────────────────────
if not MODEL_PATH.exists():
    print(f"[!] Model not found at {MODEL_PATH}")
    print("[!] Run train_model.py first.")
    exit(1)

model     = joblib.load(MODEL_PATH)
seen_rows = 0
print(f"[+] Model loaded from {MODEL_PATH}")
print(f"[*] Monitoring  : {LOG_PATH}")
print(f"[*] Blocklist   : {BLOCKLIST_PATH}")
print(f"[*] Poll interval: {POLL_INTERVAL}s\n")

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_blocked_ips() -> set:
    if not BLOCKLIST_PATH.exists():
        return set()
    return {line.strip() for line in BLOCKLIST_PATH.read_text().splitlines() if line.strip()}


def block_ip(ip: str) -> None:
    existing = get_blocked_ips()
    if ip not in existing:
        with open(BLOCKLIST_PATH, "a") as f:
            f.write(ip + "\n")
        print(f"[*] {ip} written to {BLOCKLIST_PATH}")


def to_serializable(val):
    if isinstance(val, pd.Timestamp):
        return val.strftime("%Y-%m-%d %H:%M:%S")
    if hasattr(val, "item"):
        return val.item()
    return str(val)


def log_audit(ip: str, record: dict) -> None:
    filepath = AUDIT_DIR / f"{ip.replace('.', '_')}.json"
    data = []
    if filepath.exists():
        try:
            data = json.loads(filepath.read_text())
        except json.JSONDecodeError:
            data = []
    clean_record = {k: to_serializable(v) for k, v in record.items()}
    data.append(clean_record)
    filepath.write_text(json.dumps(data, indent=2))


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"]    = pd.to_datetime(df["timestamp"])
    df["hour"]         = df["timestamp"].dt.hour
    df["time_unix"]    = df["timestamp"].astype("int64") // 10**9
    df["username_len"] = df["username"].str.len()
    df["password_len"] = df["password"].str.len()

    ip_counts          = df.groupby("ip")["ip"].transform("count")
    df["req_count"]    = ip_counts
    df["unique_users"] = df.groupby("ip")["username"].transform("nunique")
    df["unique_pwds"]  = df.groupby("ip")["password"].transform("nunique")

    df = df.sort_values(["ip", "timestamp"])
    df["time_gap"]     = df.groupby("ip")["time_unix"].diff().fillna(999)
    return df


# ── Main loop ─────────────────────────────────────────────────────────────────
while True:
    try:
        if not LOG_PATH.exists():
            time.sleep(POLL_INTERVAL)
            continue

        df_full = pd.read_csv(
            LOG_PATH, header=None,
            names=["ip", "username", "password", "timestamp"]
        )

        if len(df_full) <= seen_rows:
            time.sleep(POLL_INTERVAL)
            continue

        df_feat   = build_features(df_full)
        new_rows  = df_feat.iloc[seen_rows:]
        seen_rows = len(df_full)

        blocked_ips = get_blocked_ips()

        for idx, row in new_rows.iterrows():
            ip = row["ip"]

            if ip in blocked_ips:
                print(f"[SKIP]  {ip} already blocked")
                continue

            features   = pd.DataFrame([row[FEATURES]], columns=FEATURES)
            prediction = model.predict(features)[0]

            if prediction == 1:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{ts}] INTRUSION DETECTED — blocking {ip}")
                block_ip(ip)
                blocked_ips.add(ip)
                log_audit(ip, {
                    "ip"         : ip,
                    "username"   : row["username"],
                    "timestamp"  : row["timestamp"],
                    "action"     : "BLOCKED",
                    "detected_at": ts
                })
            else:
                print(f"[OK]  Normal request from {ip} | user: {row['username']}")

    except pd.errors.EmptyDataError:
        pass
    except Exception as e:
        print(f"[ERROR] {e}")

    time.sleep(POLL_INTERVAL)
