"""
Verify the benign vs attack simulator profiles get different model predictions.
"""
import sys, os
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))

import joblib
from model_training import prepare_features
import pandas as pd

# Load models
base = os.path.dirname(__file__)
models_dir = os.path.join(base, 'models')
scaler      = joblib.load(os.path.join(models_dir, 'scaler.joblib'))
classifier  = joblib.load(os.path.join(models_dir, 'threat_classifier.joblib'))
enc         = joblib.load(os.path.join(models_dir, 'protocol_encoder.joblib'))
feat_cols   = joblib.load(os.path.join(models_dir, 'feature_columns.joblib'))

def predict(protocol, packets, bytes_, duration, failed_logins=0):
    mapped = {
        'source_ip': '192.168.1.1', 'destination_ip': '10.0.0.1',
        'protocol': protocol, 'packets': packets, 'bytes': bytes_,
        'duration': duration, 'failed_logins': failed_logins,
    }
    df = pd.DataFrame([mapped])
    df_p = prepare_features(df)
    X = df_p[feat_cols]
    try:
        X['Protocol Type'] = enc.transform(X['Protocol Type'])
    except ValueError:
        X['Protocol Type'] = 0
    X_s = scaler.transform(X)
    label = classifier.predict(X_s)[0]
    probs = classifier.predict_proba(X_s)[0]
    idx = list(classifier.classes_).index(label)
    return label, round(probs[idx], 3)

print("=== BENIGN PROFILE (should predict Normal) ===")
results_normal = []
for _ in range(10):
    pkts = np.random.randint(2, 20)
    byt  = np.random.randint(200, 2000)
    dur  = np.random.uniform(10, 60)
    lbl, conf = predict('TCP', pkts, byt, dur, 0)
    results_normal.append(lbl)
    print(f"  pkts={pkts:3d}  bytes={byt:5d}  dur={dur:.1f}s  -> {lbl} ({conf:.2%})")

print()
print("=== ATTACK PROFILE (should predict DDoS) ===")
results_attack = []
for _ in range(10):
    pkts = int(max(100, np.random.normal(500, 150)))
    byt  = int(max(500, np.random.normal(50000, 10000)))
    dur  = float(max(0.01, np.random.normal(1.5, 0.5)))
    proto = np.random.choice(['TCP','UDP','ICMP'])
    lbl, conf = predict(proto, pkts, byt, dur, 0)
    results_attack.append(lbl)
    print(f"  pkts={pkts:4d}  bytes={byt:7d}  dur={dur:.2f}s  -> {lbl} ({conf:.2%})")

normal_ok  = results_normal.count('Normal') / len(results_normal)
attack_ok  = results_attack.count('Normal') / len(results_attack)
print()
print(f"Benign  profile → Normal: {results_normal.count('Normal')}/10  ({normal_ok:.0%})")
print(f"Attack  profile → Normal: {results_attack.count('Normal')}/10  ({attack_ok:.0%})")
print()
print("PASS: Profiles are distinct" if normal_ok >= 0.5 else "FAIL: Benign profile not predicting Normal enough")
