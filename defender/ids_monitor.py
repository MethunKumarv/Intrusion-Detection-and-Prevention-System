import pandas as pd
import joblib
import os
import time
from datetime import datetime
import json

LOG_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\server\logs\login_attempts.csv"
BLOCKLIST_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\defender\blocked_ips.txt"
AUDIT_DIR = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\defender\audit_logs"
MODEL_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\defender\model\model.pkl"

os.makedirs(AUDIT_DIR, exist_ok=True)

model = joblib.load(MODEL_PATH)
seen_rows = 0

def block_ip(ip):
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(ip + "\n")

def log_audit(ip, record):
    filepath = f"{AUDIT_DIR}/{ip.replace('.', '_')}.json"
    if os.path.exists(filepath):
        with open(filepath) as f:
            data = json.load(f)
    else:
        data = []
    data.append(record)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

while True:
    try:
        df = pd.read_csv(LOG_PATH, header=None, names=["ip", "username", "password", "timestamp"])
        new_df = df.iloc[seen_rows:]
        seen_rows = len(df)

        for _, row in new_df.iterrows():
            features = [[len(row['username']), len(row['password']), pd.to_datetime(row['timestamp']).timestamp()]]
            prediction = model.predict(features)[0]

            if prediction == 1:  # Detected attack
                print(f"⚠️ Intrusion detected from IP: {row['ip']}")

                block_ip(row['ip'])

                log = {
                    "ip": row["ip"],
                    "username": row["username"],
                    "password": row["password"],
                    "timestamp": row["timestamp"],
                    "action": "BLOCKED"
                }
                log_audit(row["ip"], log)
    except Exception as e:
        print("Error:", e)
    
    time.sleep(2)
