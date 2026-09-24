import os
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier


# Training data
#
# Features:
# 1. Deception trigger
# 2. High severity
# 3. Critical severity

X = np.array([
    [0, 0, 0],
    [0, 0, 0],
    [0, 0, 0],
    [0, 1, 0],
    [0, 1, 0],
    [1, 1, 0],
    [1, 1, 0],
    [1, 0, 1],
    [1, 0, 1],
    [1, 1, 1],
    [1, 1, 1],
    [1, 1, 1]
])


# Labels
# NORMAL       = normal activity
# SUSPICIOUS   = suspicious activity
# MALICIOUS    = highly suspicious activity

y = np.array([
    "NORMAL",
    "NORMAL",
    "NORMAL",
    "SUSPICIOUS",
    "SUSPICIOUS",
    "SUSPICIOUS",
    "SUSPICIOUS",
    "MALICIOUS",
    "MALICIOUS",
    "MALICIOUS",
    "MALICIOUS",
    "MALICIOUS"
])


# Create AI model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train
model.fit(X, y)


# Create model directory
os.makedirs("model", exist_ok=True)


# Save trained model
model_path = os.path.join("model", "threat_model.pkl")

joblib.dump(model, model_path)


print("=" * 50)
print(" AI THREAT DETECTION MODEL")
print("=" * 50)
print("Model trained successfully!")
print(f"Model saved at: {model_path}")
print("=" * 50)