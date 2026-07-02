import sys
import os
import pytest

# ✅ Add backend folder to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from alert_service import app as alert_app

# ✅ Flask test client
@pytest.fixture
def alert_client():
    alert_app.config["TESTING"] = True
    return alert_app.test_client()

# ✅ Integration Test for Incident Logging
def test_incident_log_submission(alert_client):
    """
    Test that an incident log can be submitted and acknowledged correctly.
    """

    # Send a fake incident log
    response = alert_client.post("/incident-log", json={
        "ip": "192.168.1.5",
        "timestamp": "2025-04-26T12:30:00",
        "action": "User manually reported suspicious activity."
    })

    # Validate response
    assert response.status_code == 200
    data = response.get_json()
    assert "message" in data
    assert data["message"] == "Incident response logged"

