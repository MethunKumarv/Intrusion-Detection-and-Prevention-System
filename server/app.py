from flask import Flask, request
import csv
import os
from datetime import datetime

app = Flask(__name__)
LOG_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\server\logs\login_attempts.csv"
BLOCKLIST_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\defender\blocked_ips.txt"

# Ensure log folder
os.makedirs("logs", exist_ok=True)

def is_ip_blocked(ip):
    if not os.path.exists(BLOCKLIST_PATH):
        return False
    with open(BLOCKLIST_PATH) as f:
        return ip in f.read().splitlines()

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if is_ip_blocked(ip):
        return "Access Denied (IP Blocked)", 403

    username = request.form.get("username")
    password = request.form.get("password")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_PATH, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([ip, username, password, timestamp])

    return "Login received"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
