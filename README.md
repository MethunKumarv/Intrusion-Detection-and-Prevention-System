# Intrusion Detection and Prevention System

This repository contains the original multi-folder version of an intrusion detection and prevention project built with Flask, Streamlit, pandas, and scikit-learn.

## What it does

- Accepts login attempts through a Flask server.
- Simulates attack traffic with the attacker script.
- Monitors login logs and blocks suspicious IPs.
- Shows activity, blocked IPs, and audit logs in a Streamlit dashboard.

## Project Layout

- `server/` - Flask login endpoint and request logging.
- `attacker/` - Login-attempt simulator.
- `defender/` - IDS monitor, training script, blocklist, and audit logs.
- `dashboard/` - Streamlit dashboard for viewing activity.
- `model/` - Saved trained model files.

## Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

## How to Run

Run the components in separate terminals:

1. Start the server:

```bash
python server/app.py
```

2. Start the IDS monitor:

```bash
python defender/ids_monitor.py
```

3. Start the dashboard:

```bash
streamlit run dashboard/dashboard.py
```

4. Optional: generate login traffic with the attacker simulator:

```bash
python attacker/attacker.py
```

## Notes

- This version keeps the original folder layout used in the project submission.
- Some scripts use absolute local paths from the original machine. If you clone the repo into a different folder, update those paths inside `server/app.py`, `defender/ids_monitor.py`, and `dashboard/dashboard.py`.

## Files Included

- Source code for the server, attacker, dashboard, and IDS monitor.
- Trained model and sample audit logs.
- Supporting project documents and archive files.