from flask import Flask, request, jsonify
import pandas as pd
import joblib
import requests

app = Flask(__name__)

# Load models
scaler = joblib.load("ml_models/scaler.joblib")
pca = joblib.load("ml_models/pca.joblib")
model = joblib.load("ml_models/rf_best_model.joblib")

expected_features = [
    "network_threats", "network_dns", "network_http",
    "network_connections", "apis", "registry_total"
]

@app.route('/analyze', methods=['POST'])
def analyze_packet():
    data = request.get_json()

    features = {
        "network_threats": 1 if "malware" in data.get("url", "").lower() else 0,
        "network_dns": 1,
        "network_http": 1 if "http" in data.get("url", "").lower() else 0,
        "network_connections": 1,
        "apis": 10,  # You can later replace with tab count or storage
        "registry_total": 0
    }

    df = pd.DataFrame([features])
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0
    df = df[expected_features]

    scaled = scaler.transform(df)
    reduced = pca.transform(scaled)
    prob = model.predict_proba(reduced)[0][1]

    if prob >= 0.4:
        alert = {
            "ip": data.get("url", "unknown"),
            "source": "extension",
            "probability": float(prob),
            "features": features,
            "suspicious_processes": []
        }
        requests.post("http://localhost:5001/alert", json=alert)
        return jsonify({"alert_sent": True})
    return jsonify({"alert_sent": False})

if __name__ == "__main__":
    app.run(port=5002)
