import joblib
import os

try:
    le = joblib.load("models/protocol_encoder.joblib")
    print(f"Encoder classes: {le.classes_}")
except Exception as e:
    print(f"Error loading encoder: {e}")
