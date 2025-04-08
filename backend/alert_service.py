from flask import Flask, request, jsonify
from datetime import datetime
import os
import json

app = Flask(__name__)

log_file_path = os.path.abspath("alerts_log.txt")

def classify_severity(probability):
    if probability >= 0.90:
        return "High"
    elif probability >= 0.70:
        return "Medium"
    else:
        return "Low"

@app.route('/alert', methods=['POST'])
def receive_alert():
    data = request.get_json()
    ip = data.get("ip", "unknown")
    probability = data.get("probability", 0.0)
    severity = classify_severity(probability)
    suspicious_processes = data.get("suspicious_processes", [])

    alert = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "severity": severity,
        "probability": probability,
        "features": data.get("features", {}),
        "processes": suspicious_processes
    }

    try:
        with open(log_file_path, "a") as f:
            f.write(json.dumps(alert) + "\n")
        print(f"🔔 Logged {severity} alert from {ip}")
        return jsonify({"message": "Alert received and logged", "severity": severity}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5001)
