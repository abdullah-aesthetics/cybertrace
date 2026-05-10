"""
ML Threat Prediction Module
Uses Random Forest to predict threat probability from combined features.
Falls back to rule-based scoring if scikit-learn is not installed.
"""
import os
import json
import pickle
import math
from datetime import datetime

MODEL_PATH = "database/rf_model.pkl"
TRAINING_DATA_PATH = "database/training_data.json"

# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(osint_data, packet_data=None, malware_data=None):
    """Convert raw investigation data into a numeric feature vector."""
    vt    = osint_data.get("virustotal", {})
    abuse = osint_data.get("abuseipdb", {})
    geo   = osint_data.get("geolocation", {})
    ports = osint_data.get("open_ports", [])
    dns   = osint_data.get("dns", {})

    # High-risk ASNs / hosting providers commonly used by attackers
    bad_asns = ["serverius", "frantech", "m247", "combahton", "hostkey",
                "tele2", "vultr", "digitalocean", "linode", "choopa"]
    isp_lower = (abuse.get("isp") or geo.get("isp") or "").lower()
    bad_asn_flag = int(any(b in isp_lower for b in bad_asns))

    # High-risk country codes
    high_risk_countries = {"RU","CN","KP","IR","BY","SY","CU","VE","UA"}
    country_code = (abuse.get("country") or geo.get("country_code") or "")
    high_risk_country = int(country_code.upper() in high_risk_countries)

    # Dangerous open ports
    dangerous_ports = {4444, 6667, 1337, 31337, 9001, 8888, 23}
    open_port_nums  = {p["port"] for p in ports}
    dangerous_open  = int(bool(open_port_nums & dangerous_ports))
    total_open_ports = len(ports)

    # DNS anomaly score
    dns_records = dns.get("records", {})
    has_mx  = int(bool(dns_records.get("MX")))
    has_txt = int(bool(dns_records.get("TXT")))

    features = {
        "vt_malicious":       min(vt.get("malicious", 0), 70),
        "vt_suspicious":      min(vt.get("suspicious", 0), 70),
        "vt_harmless":        min(vt.get("harmless", 0), 70),
        "vt_reputation":      max(min(vt.get("reputation", 0), 0), -100),
        "abuse_score":        abuse.get("abuse_score", 0),
        "abuse_reports":      min(abuse.get("total_reports", 0), 500),
        "is_tor":             int(abuse.get("is_tor", False)),
        "high_risk_country":  high_risk_country,
        "bad_asn":            bad_asn_flag,
        "dangerous_open_port":dangerous_open,
        "total_open_ports":   total_open_ports,
        "has_mx_record":      has_mx,
        "has_txt_record":     has_txt,
        "suspicious_packets": min((packet_data or {}).get("suspicious_count", 0), 200),
        "malware_detected":   int((malware_data or {}).get("verdict") == "malicious"),
        "malware_suspicious": int((malware_data or {}).get("verdict") == "suspicious"),
    }
    return features


def features_to_vector(features):
    """Convert feature dict to ordered numeric list."""
    keys = [
        "vt_malicious","vt_suspicious","vt_harmless","vt_reputation",
        "abuse_score","abuse_reports","is_tor","high_risk_country",
        "bad_asn","dangerous_open_port","total_open_ports",
        "has_mx_record","has_txt_record","suspicious_packets",
        "malware_detected","malware_suspicious"
    ]
    return [features.get(k, 0) for k in keys]


# ── Training data (seeded examples) ──────────────────────────────────────────

SEED_DATA = [
    # [vt_mal,vt_sus,vt_harm,vt_rep,abuse,reports,tor,hrc,bad_asn,danger_port,ports,mx,txt,susp_pkt,mal,sus_mal] label
    ([45,3,2,-90,95,300,1,1,1,1,2,0,0,80,1,0], 1),
    ([0,0,65,5,0,0,0,0,0,0,0,1,1,0,0,0],       0),
    ([12,2,40,-30,60,50,0,1,0,0,3,0,0,20,0,0], 1),
    ([0,1,60,0,5,2,0,0,0,0,1,1,1,0,0,0],       0),
    ([30,5,10,-60,85,150,1,0,1,1,1,0,0,50,0,1],1),
    ([0,0,70,10,0,0,0,0,0,0,0,1,1,0,0,0],      0),
    ([2,1,55,0,10,5,0,0,0,0,2,1,1,5,0,0],      0),
    ([20,4,15,-40,70,80,0,1,1,0,4,0,0,30,1,0], 1),
    ([0,0,68,8,0,0,0,0,0,0,0,1,1,0,0,0],       0),
    ([50,8,1,-95,98,400,1,1,1,1,3,0,0,100,1,0],1),
    ([5,2,50,-5,15,10,0,0,0,0,1,1,1,2,0,0],    0),
    ([35,6,5,-70,80,200,1,1,0,1,2,0,0,60,0,1], 1),
    ([1,0,65,5,2,1,0,0,0,0,0,1,1,0,0,0],       0),
    ([25,3,20,-50,55,60,0,0,1,0,3,0,0,15,0,0], 1),
    ([0,0,72,12,0,0,0,0,0,0,0,1,1,0,0,0],      0),
]


def train_model():
    """Train a Random Forest model on seed data. Returns trained model."""
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        import numpy as np

        X = np.array([row for row, _ in SEED_DATA], dtype=float)
        y = np.array([label for _, label in SEED_DATA])

        model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=6)
        model.fit(X, y)

        os.makedirs("database", exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)

        return model
    except ImportError:
        return None


def load_or_train_model():
    try:
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        return train_model()
    except Exception:
        return None


# ── Prediction ────────────────────────────────────────────────────────────────

def predict_threat(osint_data, packet_data=None, malware_data=None):
    """
    Returns ML-based threat probability (0-100) and feature breakdown.
    Falls back to rule-based score if sklearn not available.
    """
    features = extract_features(osint_data, packet_data, malware_data)
    vector   = features_to_vector(features)

    model = load_or_train_model()

    if model is not None:
        try:
            import numpy as np
            prob = model.predict_proba([vector])[0][1]
            ml_score = round(prob * 100)
            method = "Random Forest (scikit-learn)"

            # Feature importance
            importance = {}
            feature_names = [
                "vt_malicious","vt_suspicious","vt_harmless","vt_reputation",
                "abuse_score","abuse_reports","is_tor","high_risk_country",
                "bad_asn","dangerous_open_port","total_open_ports",
                "has_mx_record","has_txt_record","suspicious_packets",
                "malware_detected","malware_suspicious"
            ]
            if hasattr(model, "feature_importances_"):
                for name, imp in zip(feature_names, model.feature_importances_):
                    importance[name] = round(float(imp), 4)

        except Exception:
            ml_score, method, importance = _rule_based_score(features), "Rule-based fallback", {}
    else:
        ml_score, method, importance = _rule_based_score(features), "Rule-based fallback", {}

    return {
        "ml_score":          ml_score,
        "method":            method,
        "features":          features,
        "feature_importance":importance,
        "verdict":           _verdict(ml_score),
        "confidence":        _confidence(ml_score)
    }


def _rule_based_score(f):
    score = 0
    score += min(f["vt_malicious"] * 2, 40)
    score += min(f["abuse_score"] * 0.4, 30)
    score += f["is_tor"] * 10
    score += f["high_risk_country"] * 8
    score += f["bad_asn"] * 8
    score += f["dangerous_open_port"] * 12
    score += f["malware_detected"] * 25
    return min(int(score), 100)


def _verdict(score):
    if score >= 75: return "MALICIOUS"
    if score >= 50: return "LIKELY MALICIOUS"
    if score >= 30: return "SUSPICIOUS"
    if score >= 10: return "LOW RISK"
    return "CLEAN"


def _confidence(score):
    if score >= 85 or score <= 10: return "High"
    if score >= 60 or score <= 25: return "Medium"
    return "Low"
