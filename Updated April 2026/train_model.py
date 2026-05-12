"""
train_model.py
--------------
Trains and compares Random Forest vs XGBoost, saves the better model.
Synthesises normal traffic since attacker.py only generates attack data.
"""

from pathlib import Path
from datetime import datetime, timedelta
import random
import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
from xgboost import XGBClassifier

# ── Paths — all files live in the SAME folder as this script ─────────────────
BASE      = Path(__file__).resolve().parent
LOG_PATH  = BASE / "blocked_ips.txt"
MODEL_DIR = BASE / "model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ── Load real attack data ─────────────────────────────────────────────────────
print("[*] Loading login attempt data...")
df_real = pd.read_csv(
    LOG_PATH, header=None,
    names=["ip", "username", "password", "timestamp"]
)
print(f"    {len(df_real)} real rows loaded.")

if len(df_real) < 10:
    print("[!] Not enough data. Run attacker.py first.")
    exit(1)

df_real["label"] = 1
print(f"    Attack rows : {len(df_real)}")

# ── Synthesise normal traffic ─────────────────────────────────────────────────
print("[*] Generating synthetic normal traffic...")

random.seed(42)
normal_rows  = []
n_normal_ips = len(df_real)
normal_users = [f"user_{i}" for i in range(200)]
normal_pwds  = ["securepass", "mypassword1", "hello123", "pass@2024"]

df_real["timestamp"] = pd.to_datetime(df_real["timestamp"])
start_ts = df_real["timestamp"].min()
end_ts   = df_real["timestamp"].max()
ts_range = max((end_ts - start_ts).total_seconds(), 3600)

for i in range(n_normal_ips):
    fake_ip    = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    username   = random.choice(normal_users)
    n_attempts = random.randint(1, 3)
    base_time  = start_ts + timedelta(seconds=random.uniform(0, ts_range))

    for j in range(n_attempts):
        ts = base_time + timedelta(seconds=j * random.uniform(30, 300))
        normal_rows.append({
            "ip"        : fake_ip,
            "username"  : username,
            "password"  : random.choice(normal_pwds),
            "timestamp" : ts.strftime("%Y-%m-%d %H:%M:%S"),
            "label"     : 0
        })

df_normal = pd.DataFrame(normal_rows)
print(f"    Normal rows : {len(df_normal)}")

# ── Combine & engineer features ───────────────────────────────────────────────
df = pd.concat([df_real, df_normal], ignore_index=True)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values(["ip", "timestamp"]).reset_index(drop=True)

df["hour"]         = df["timestamp"].dt.hour
df["time_unix"]    = df["timestamp"].astype("int64") // 10**9
df["username_len"] = df["username"].str.len()
df["password_len"] = df["password"].str.len()

ip_counts          = df.groupby("ip")["ip"].transform("count")
df["req_count"]    = ip_counts
df["unique_users"] = df.groupby("ip")["username"].transform("nunique")
df["unique_pwds"]  = df.groupby("ip")["password"].transform("nunique")
df["time_gap"]     = df.groupby("ip")["time_unix"].diff().fillna(999)

print(f"\n    Total rows  : {len(df)}")
print(f"    Attack (1)  : {(df['label'] == 1).sum()}")
print(f"    Normal (0)  : {(df['label'] == 0).sum()}")

FEATURES = [
    "username_len", "password_len",
    "req_count", "unique_users", "unique_pwds",
    "hour", "time_gap"
]

X = df[FEATURES]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train & compare ───────────────────────────────────────────────────────────
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced"),
    "XGBoost"      : XGBClassifier(n_estimators=100, eval_metric="logloss", random_state=42, verbosity=0),
}

best_name, best_model, best_f1 = None, None, -1

print("\n" + "=" * 55)
for name, model in models.items():
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    f1    = f1_score(y_test, preds, average="weighted", zero_division=0)
    print(f"\n--- {name} ---")
    print(classification_report(y_test, preds, zero_division=0))
    if f1 > best_f1:
        best_f1, best_name, best_model = f1, name, model

print("=" * 55)
print(f"\n[*] Best model : {best_name}  (weighted F1 = {best_f1:.3f})")

# ── Feature importance ────────────────────────────────────────────────────────
try:
    importances = dict(zip(FEATURES, best_model.feature_importances_))
    for feat, imp in sorted(importances.items(), key=lambda x: x[1], reverse=True):
        print(f"    {feat:<20} {'█' * int(imp * 40)}  {imp:.3f}")
except AttributeError:
    pass

# ── Save ──────────────────────────────────────────────────────────────────────
save_path = MODEL_DIR / "model.pkl"
joblib.dump(best_model, save_path)
print(f"\n[+] Model saved to {save_path}")
