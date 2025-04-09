from flask import Flask, request, jsonify
from datetime import datetime
import os
import json
import time

app = Flask(__name__)

log_file_path = os.path.abspath("alerts_log.txt")
incident_log_path = os.path.abspath("incident_log.txt")

# Prevent duplicate alerts within a short time window
recent_alerts = {}

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
    source = data.get("source", "unknown")
    severity = classify_severity(probability)
    suspicious_processes = data.get("suspicious_processes", [])

    # Avoid duplicate alerts from the same source within 10 seconds
    key = f"{ip}-{source}"
    now = time.time()
    if key in recent_alerts and (now - recent_alerts[key] < 10):
        return jsonify({"message": "Duplicate alert ignored"}), 200

    recent_alerts[key] = now

    alert = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "source": source,
        "severity": severity,
        "probability": probability,
        "features": data.get("features", {}),
        "processes": suspicious_processes
    }

    try:
        with open(log_file_path, "a") as f:
            f.write(json.dumps(alert) + "\n")
        print(f"🔔 Logged {severity} alert from {ip} via {source}")
        return jsonify({"message": "Alert received and logged", "severity": severity}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/latest-alert', methods=['GET'])
def latest_alert():
    try:
        with open(log_file_path, "r") as f:
            lines = f.readlines()
            if not lines:
                return jsonify({})
            return jsonify(json.loads(lines[-1]))
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/incident-log', methods=['POST'])
def receive_incident_log():
    data = request.get_json()
    try:
        with open(incident_log_path, "a") as f:
            f.write(json.dumps(data) + "\n")
        print(f"📒 Incident response logged: {data}")
        return jsonify({"message": "Incident response logged"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5001)
