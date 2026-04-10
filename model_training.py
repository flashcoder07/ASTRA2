import pandas as pd
import numpy as np
import joblib
import os
import logging
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
try:
    from data_loader import load_data, SELECTED_FEATURES
except ImportError:
    # For when running from wrong cwd
    import sys
    sys.path.append(os.getcwd())
    from data_loader import load_data, SELECTED_FEATURES

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('astra_training')

MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

def prepare_features(input_df):
    """
    Transform raw network events (from app.py) into features for the model.
    Expected input columns: ['source_ip', 'destination_ip', 'protocol', 'packets', 'bytes', 'duration', 'failed_logins']
    Target output columns: All columns in SELECTED_FEATURES
    """
    df = input_df.copy()
    
    # 1. Basic Mappings
    df['Duration'] = df['duration']
    df['flow_duration'] = df['duration'] # Assuming similar
    
    # 2. Rate (packets/sec)
    df['Rate'] = df.apply(lambda row: row['packets'] / row['duration'] if row['duration'] > 0 else 0, axis=1)
    
    # 3. Srate (bytes/sec)
    df['Srate'] = df.apply(lambda row: row['bytes'] / row['duration'] if row['duration'] > 0 else 0, axis=1)
    
    # 4. Protocol Type
    # Map raw protocol strings to IANA numbers strings (e.g. '6', '17')
    proto_map = {
        'TCP': '6',
        'UDP': '17',
        'ICMP': '1',
        'HOPOPT': '0',
    }
    df['Protocol Type'] = df['protocol'].map(lambda x: proto_map.get(str(x).upper(), '6')) 
    
    # 5. Fill Missing Features with 0
    # The dataset has many features we cannot compute from simple packet summaries.
    # We will initialize them to 0. Ideally, a real Perception Module would extract these.
    for feature in SELECTED_FEATURES:
        if feature not in df.columns:
            df[feature] = 0.0
            
    # Reorder
    return df[SELECTED_FEATURES]

def train_models():
    logger.info("Loading data...")
    X_train, X_test, y_train, y_test, features = load_data()
    
    logger.info(f"Training with {len(features)} features")
    
    # -----------------------------
    # PREPROCESSING
    # -----------------------------
    
    # 1. Protocol Encoding
    # Ensure consistent string type before encoding
    X_train['Protocol Type'] = X_train['Protocol Type'].fillna(0).astype(int).astype(str)
    X_test['Protocol Type'] = X_test['Protocol Type'].fillna(0).astype(int).astype(str)
    
    le_proto = LabelEncoder()
    # Fit on both for coverage (in a real scenario, handle unknown handle_unknown=ignore equivalent)
    # Combining just to fit encoder
    all_protos = pd.concat([X_train['Protocol Type'], X_test['Protocol Type']]).unique()
    le_proto.fit(all_protos)
    
    X_train['Protocol Type'] = le_proto.transform(X_train['Protocol Type'])
    X_test['Protocol Type'] = le_proto.transform(X_test['Protocol Type'])
    
    # 2. Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # -----------------------------
    # MODEL 1: ANOMALY DETECTION (Isolation Forest)
    # -----------------------------
    logger.info("Training Isolation Forest (Anomaly Detection) on NORMAL traffic only...")
    
    # Filter for Normal traffic in train set
    normal_indices = y_train == 'Normal'
    X_train_normal = X_train_scaled[normal_indices]
    
    iso_forest = IsolationForest(contamination=0.02, random_state=42, n_jobs=-1)
    iso_forest.fit(X_train_normal) 
    
    # Evaluate Anomaly Detector
    logger.info("Evaluating Isolation Forest...")
    y_test_binary = (y_test == 'Normal').map({True: 1, False: -1})
    y_pred_iso = iso_forest.predict(X_test_scaled)
    
    print("\n--- Isolation Forest Report ---")
    print(classification_report(y_test_binary, y_pred_iso, target_names=['Anomaly', 'Normal']))
    print("Confusion Matrix (Isolation Forest):")
    print(confusion_matrix(y_test_binary, y_pred_iso))

    # -----------------------------
    # SMOTE — oversample BruteForce (and any other minority class)
    # Applied to training set ONLY, AFTER scaling so distances are meaningful.
    # k_neighbors=3 because BruteForce has very few samples.
    # -----------------------------
    logger.info("Applying SMOTE to training set...")
    print(f"\nClass distribution BEFORE SMOTE:\n{pd.Series(y_train).value_counts()}")

    smote = SMOTE(random_state=42, k_neighbors=3)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train_scaled, y_train)

    print(f"\nClass distribution AFTER SMOTE:\n{pd.Series(y_train_resampled).value_counts()}")

    # -----------------------------
    # MODEL 2: THREAT CLASSIFICATION (Random Forest)
    # -----------------------------
    logger.info("Training Random Forest (Threat Classifier) on SMOTE-resampled data...")
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',
    )
    clf.fit(X_train_resampled, y_train_resampled)
    
    y_pred_clf = clf.predict(X_test_scaled)
    
    logger.info("Evaluating Random Forest...")
    print("\n--- Random Forest Classification Report ---")
    print(classification_report(y_test, y_pred_clf))
    
    print("\n--- Confusion Matrix (Random Forest) ---")
    print(confusion_matrix(y_test, y_pred_clf))
    
    # -----------------------------
    # SAVE ARTIFACTS
    # -----------------------------
    logger.info("Saving models...")
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(le_proto, os.path.join(MODEL_DIR, "protocol_encoder.joblib"))
    joblib.dump(iso_forest, os.path.join(MODEL_DIR, "anomaly_detector.joblib"))
    joblib.dump(clf, os.path.join(MODEL_DIR, "threat_classifier.joblib"))
    joblib.dump(features, os.path.join(MODEL_DIR, "feature_columns.joblib"))
    
    logger.info("Training complete.")

if __name__ == "__main__":
    train_models()
