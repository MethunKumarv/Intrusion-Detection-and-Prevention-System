# Intrusion Detection and Prevention System - Updated Version

This repository contains the updated and cleaner April 2026 version of the project. It uses local relative paths, so it is easier to run after cloning or moving the folder.

## What it does

- Runs a Flask login endpoint and stores login attempts.
- Trains an ML model for intrusion detection.
- Monitors login activity and blocks suspicious IPs automatically.
- Shows live activity and audit logs in a Streamlit dashboard.

## Project Layout

- `app.py` - Flask login endpoint.
- `attacker.py` - Login-attempt simulator.
- `ids_monitor.py` - Real-time IDS monitor and auto-blocking.
- `dashboard.py` - Streamlit dashboard.
- `train_model.py` - Model training script.
- `logs/` - Captured login attempts.
- `audit_logs/` - Per-IP audit trail.
- `blocked_ips.txt` - Blocklist file.
- `model/` - Saved trained model files.

## Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

## How to Run

Run the components in separate terminals:

1. Train the model:

```bash
python train_model.py
```

2. Start the Flask app:

```bash
python app.py
```

3. Start the IDS monitor:

```bash
python ids_monitor.py
```

4. Start the dashboard:

```bash
streamlit run dashboard.py
```

5. Optional: simulate login attempts:

```bash
python attacker.py
```

## Outputs

- `logs/login_attempts.csv` stores captured login activity.
- `blocked_ips.txt` stores blocked IP addresses.
- `audit_logs/` stores per-IP JSON audit records.
- `model/model.pkl` stores the trained model.

## Notes

- This version is the recommended backup copy for a reset because it is self-contained.
- The dashboard auto-refreshes and reads directly from the local project files.