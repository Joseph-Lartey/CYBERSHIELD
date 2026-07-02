import json
import tempfile
import os
import sys
import pytest

# ✅ Fix the import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from alert_service import app, classify_severity  # Now it should work

# ✅ Flask test client fixture
@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()

# ✅ Test 1: Severity classification
def test_classify_severity():
    assert classify_severity(0.95) == "High"
    assert classify_severity(0.75) == "Medium"
    assert classify_severity(0.5) == "Low"

# ✅ Test 2: /alert POST
def test_receive_alert(client):
    response = client.post("/alert", json={
        "ip": "127.0.0.1",
        "probability": 0.92,
        "source": "chrome",
        "features": {},
        "suspicious_processes": ["notepad.exe"]
    })
    assert response.status_code == 200
    res_json = response.get_json()
    assert "message" in res_json
    assert res_json["severity"] == "High"

# ✅ Test 3: /latest-alert GET
def test_latest_alert(client):
    response = client.get("/latest-alert")
    assert response.status_code == 200
    if response.get_json():
        assert "ip" in response.get_json()

# ✅ Test 4: /incident-log POST
def test_receive_incident_log(client):
    response = client.post("/incident-log", json={
        "ip": "127.0.0.1",
        "timestamp": "2025-04-25T14:30:00",
        "action": "Blocked IP"
    })
    assert response.status_code == 200
    assert response.get_json()["message"] == "Incident response logged"
