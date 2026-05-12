import requests
import time
import random

TARGET_URL = "http://127.0.0.1:5000/login"
DELAY      = 0.3

USERNAMES = ["admin", "user", "test", "root", "administrator", "guest"]
PASSWORDS = ["123", "admin", "pass", "password", "test", "letmein", "123456", "qwerty"]

print(f"[*] Starting brute-force simulation against {TARGET_URL}")
print(f"[*] {len(USERNAMES)} usernames x {len(PASSWORDS)} passwords = {len(USERNAMES)*len(PASSWORDS)} attempts\n")

success_count = 0
blocked_count = 0
total         = 0

for username in USERNAMES:
    for password in PASSWORDS:
        try:
            r = requests.post(TARGET_URL, data={"username": username, "password": password}, timeout=5)
            total += 1
            if r.status_code == 403:
                blocked_count += 1
                print(f"[BLOCKED]  {username}:{password} -> 403")
            else:
                success_count += 1
                print(f"[SENT]     {username}:{password} -> {r.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Cannot connect to {TARGET_URL} — is app.py running?")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
        time.sleep(DELAY + random.uniform(0, 0.2))

print(f"\n[*] Done. Total={total}  Sent={success_count}  Blocked={blocked_count}")
