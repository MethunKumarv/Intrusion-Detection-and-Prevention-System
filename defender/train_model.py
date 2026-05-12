import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv(r"E:\VIT SYLLABUS\6th Sem\ISM\Project\intrusion-detection-project\server\logs\login_attempts.csv", header=None, names=["ip", "username", "password", "timestamp"])

# Simple label assignment for simulation
df['label'] = df['ip'].apply(lambda x: 1 if (x == '127.0.0.1')  else 0)

df['time'] = pd.to_datetime(df['timestamp']).astype(int) / 10**9
df['username_len'] = df['username'].apply(len)
df['password_len'] = df['password'].apply(len)

X = df[['username_len', 'password_len', 'time']]
y = df['label']

model = RandomForestClassifier()
model.fit(X, y)

os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/model.pkl")
print("✅ Model trained and saved.")
