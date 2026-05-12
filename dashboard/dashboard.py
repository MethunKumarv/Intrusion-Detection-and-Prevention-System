import streamlit as st
import pandas as pd
import os
import json

LOG_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\server\logs\login_attempts.csv"
BLOCKLIST_PATH = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\defender\blocked_ips.txt"
AUDIT_DIR = r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\defender\audit_logs"

st.title("🔐 Intrusion Detection & Response Dashboard")

st.header("📄 Login Attempts")
if os.path.exists(LOG_PATH):
    df = pd.read_csv(LOG_PATH, header=None, names=["IP", "Username", "Password", "Timestamp"])
    st.dataframe(df.tail(10))

st.header("⛔ Blocked IPs")
if os.path.exists(BLOCKLIST_PATH):
    blocked_ips = open(BLOCKLIST_PATH).read().splitlines()
    st.write(blocked_ips)

    if st.button("Unblock All"):
        open(BLOCKLIST_PATH, 'w').close()
        st.success("All IPs unblocked.")

st.header("🗂️ IP Audit Logs")
ips = [f.replace('.json', '').replace('_', '.') for f in os.listdir(AUDIT_DIR)]

selected_ip = st.selectbox("View Audit for IP", options=ips)
if selected_ip:
    path = f"{AUDIT_DIR}/{selected_ip.replace('.', '_')}.json"
    if os.path.exists(path):
        with open(path) as f:
            log = json.load(f)
            st.json(log)
