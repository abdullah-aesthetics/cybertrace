"""
ML Retraining Module
Retrains the Random Forest model using real saved investigations.
The model gets smarter over time as more cases are added.
"""
import os
import json
import pickle
import sqlite3
from datetime import datetime

DB_PATH    = "database/cybertrace.db"
MODEL_PATH = "database/rf_model.pkl"
LOG_PATH   = "database/training_log.json"


def get_training_data():
    """
    Pull all closed/verified investigations from the database
    and convert them into ML feature vectors with labels.
    Returns (X, y, count) where X=features, y=labels(0/1).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM investigations")
    rows = c.fetchall()
    conn.close()

    from modules.ml_model import extract_features, features_to_vector

    X, y = [], []
    skipped = 0

    for row in rows:
        try:
            osint = json.loads(row["osint_data"] or "{}")
            pkt   = json.loads(row["packet_data"] or "{}")
            mal   = json.loads(row["malware_data"] or "{}")

            features = extract_features(osint, pkt or None, mal or None)
            vector   = features_to_vector(features)

            # Label: 1 = malicious/high risk, 0 = clean/low risk
            level = row["threat_level"] or "CLEAN"
            label = 1 if level in ("CRITICAL", "HIGH") else 0

            # Only include cases with some signal (not all zeros)
            if any(v != 0 for v in vector):
                X.append(vector)
                y.append(label)
        except Exception:
            skipped += 1

    return X, y, skipped


def retrain_model():
    """
    Retrain the Random Forest on all saved investigation data.
    Returns a result dict with training stats.
    """
    result = {
        "timestamp":     datetime.now().isoformat(),
        "status":        "failed",
        "samples_used":  0,
        "samples_skipped": 0,
        "accuracy":      None,
        "feature_importance": {},
        "message":       ""
    }

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        from sklearn.preprocessing import StandardScaler
        import numpy as np
        from modules.ml_model import SEED_DATA
    except ImportError:
        result["message"] = "scikit-learn not installed. Run: pip install scikit-learn"
        return result

    # Get real data from DB
    X_real, y_real, skipped = get_training_data()
    result["samples_skipped"] = skipped

    # Always include seed data so model has baseline knowledge
    X_seed = [row for row, _ in SEED_DATA]
    y_seed = [label for _, label in SEED_DATA]

    X = X_seed + X_real
    y = y_seed + y_real

    if len(X) < 5:
        result["message"] = f"Not enough data to retrain (need at least 5 samples, have {len(X)}). Run more investigations first."
        return result

    X_np = np.array(X, dtype=float)
    y_np = np.array(y)

    # Train model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_split=2,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_np, y_np)

    # Cross-validation accuracy
    try:
        scores = cross_val_score(model, X_np, y_np, cv=min(5, len(X)), scoring="accuracy")
        result["accuracy"] = round(float(scores.mean()) * 100, 1)
    except Exception:
        result["accuracy"] = None

    # Feature importance
    feature_names = [
        "vt_malicious","vt_suspicious","vt_harmless","vt_reputation",
        "abuse_score","abuse_reports","is_tor","high_risk_country",
        "bad_asn","dangerous_open_port","total_open_ports",
        "has_mx_record","has_txt_record","suspicious_packets",
        "malware_detected","malware_suspicious"
    ]
    importance = {}
    for name, imp in zip(feature_names, model.feature_importances_):
        importance[name] = round(float(imp) * 100, 2)
    result["feature_importance"] = dict(
        sorted(importance.items(), key=lambda x: -x[1])[:8]
    )

    # Save model
    os.makedirs("database", exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    # Save training log
    result["status"]       = "success"
    result["samples_used"] = len(X)
    result["real_samples"] = len(X_real)
    result["seed_samples"] = len(X_seed)
    result["message"]      = f"Model retrained on {len(X)} samples ({len(X_real)} real + {len(X_seed)} seed). Accuracy: {result['accuracy']}%"

    _save_log(result)
    return result


def get_training_history():
    """Return previous training runs."""
    if not os.path.exists(LOG_PATH):
        return []
    try:
        with open(LOG_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def _save_log(result):
    history = get_training_history()
    history.insert(0, result)
    history = history[:20]  # Keep last 20 runs
    with open(LOG_PATH, "w") as f:
        json.dump(history, f, indent=2)
