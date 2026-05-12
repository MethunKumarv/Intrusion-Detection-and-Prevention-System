"""
dashboard.py — run with: streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import json
from pathlib import Path
from datetime import datetime

st.set_page_config(page_title="IDPS Dashboard", page_icon="🔐", layout="wide")

# ── Paths — all files live in the SAME folder as this script ─────────────────
BASE           = Path(__file__).resolve().parent
LOG_PATH       = BASE / "logs" / "login_attempts.csv"
BLOCKLIST_PATH = BASE / "blocked_ips.txt"
AUDIT_DIR      = BASE / "audit_logs"

st.markdown('<meta http-equiv="refresh" content="5">', unsafe_allow_html=True)
st.title("🔐 Intrusion Detection & Prevention Dashboard")
st.caption(f"Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  •  Auto-refreshes every 5s")

# ── Load data ─────────────────────────────────────────────────────────────────
@st.cache_data(ttl=4)
def load_logs():
    if not LOG_PATH.exists():
        return pd.DataFrame(columns=["IP", "Username", "Password", "Timestamp"])
    df = pd.read_csv(LOG_PATH, header=None, names=["IP", "Username", "Password", "Timestamp"])
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    return df

@st.cache_data(ttl=4)
def load_blocked():
    if not BLOCKLIST_PATH.exists():
        return []
    return list(dict.fromkeys(
        line.strip() for line in BLOCKLIST_PATH.read_text().splitlines() if line.strip()
    ))

df      = load_logs()
blocked = load_blocked()

# ── Metric cards ──────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total attempts",  len(df))
c2.metric("Unique IPs",      df["IP"].nunique() if not df.empty else 0)
c3.metric("IPs blocked",     len(blocked))
c4.metric("Attack rate",
    f"{len(blocked) / df['IP'].nunique() * 100:.0f}%"
    if not df.empty and df["IP"].nunique() > 0 else "0%"
)

st.divider()

# ── Charts ────────────────────────────────────────────────────────────────────
if not df.empty:
    left, right = st.columns(2)

    with left:
        st.subheader("Requests per IP")
        ip_counts = df["IP"].value_counts().reset_index()
        ip_counts.columns = ["IP", "Count"]
        ip_counts["Status"] = ip_counts["IP"].apply(
            lambda ip: "Blocked" if ip in blocked else "Normal"
        )
        fig = px.bar(ip_counts, x="IP", y="Count", color="Status",
                     color_discrete_map={"Blocked": "#E24B4A", "Normal": "#378ADD"})
        fig.update_layout(margin=dict(t=20, b=0), height=300)
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Attack timeline")
        df["Minute"] = df["Timestamp"].dt.floor("1min")
        timeline = df.groupby("Minute").size().reset_index(name="Requests")
        fig2 = px.line(timeline, x="Minute", y="Requests")
        fig2.update_traces(line_color="#378ADD")
        fig2.update_layout(margin=dict(t=20, b=0), height=300)
        st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Requests by hour of day")
    hour_counts = df.groupby(df["Timestamp"].dt.hour).size().reset_index(name="Count")
    hour_counts.columns = ["Hour", "Count"]
    fig3 = px.bar(hour_counts, x="Hour", y="Count", color="Count", color_continuous_scale="Reds")
    fig3.update_layout(margin=dict(t=20, b=0), height=250)
    st.plotly_chart(fig3, use_container_width=True)

else:
    st.info("No login data yet. Start app.py then run attacker.py.")

st.divider()

# ── Tables ────────────────────────────────────────────────────────────────────
left2, right2 = st.columns(2)

with left2:
    st.subheader("Recent login attempts")
    if not df.empty:
        display = df[["Timestamp", "IP", "Username"]].tail(15).sort_values(
            "Timestamp", ascending=False).reset_index(drop=True)
        display["Flag"] = display["IP"].apply(lambda ip: "🔴" if ip in blocked else "🟢")
        st.dataframe(display, use_container_width=True, height=350)

with right2:
    st.subheader("Blocked IPs")
    if blocked:
        bdf = pd.DataFrame(blocked, columns=["IP Address"])
        if not df.empty:
            counts = df[df["IP"].isin(blocked)]["IP"].value_counts().reset_index()
            counts.columns = ["IP Address", "Attempts"]
            bdf = bdf.merge(counts, on="IP Address", how="left").fillna(0)
            bdf["Attempts"] = bdf["Attempts"].astype(int)
        st.dataframe(bdf, use_container_width=True, height=300)
        if st.button("🔓 Unblock all IPs"):
            BLOCKLIST_PATH.write_text("")
            st.success("All IPs unblocked.")
            st.rerun()
    else:
        st.success("No IPs currently blocked.")

st.divider()

# ── Audit log viewer ──────────────────────────────────────────────────────────
st.subheader("IP audit log viewer")
if AUDIT_DIR.exists():
    audit_files = list(AUDIT_DIR.glob("*.json"))
    if audit_files:
        ip_options  = [f.stem.replace("_", ".") for f in audit_files]
        selected_ip = st.selectbox("Select IP", options=ip_options)
        if selected_ip:
            path = AUDIT_DIR / f"{selected_ip.replace('.', '_')}.json"
            if path.exists():
                try:
                    data = json.loads(path.read_text())
                    st.dataframe(pd.DataFrame(data), use_container_width=True)
                except Exception:
                    st.error("Could not parse audit log.")
    else:
        st.info("No audit logs yet.")
