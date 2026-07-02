import sys
import os
import pytest
import requests
from unittest.mock import patch

# ✅ Add backend folder to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_api import app as detection_app
from alert_service import app as alert_app

# ✅ Flask test clients
@pytest.fixture
def detection_client():
    detection_app.config["TESTING"] = True
    return detection_app.test_client()

@pytest.fixture
def alert_client():
    alert_app.config["TESTING"] = True
    return alert_app.test_client()

# ✅ Integration Test
@patch('detection_api.requests.post')
def test_detection_to_alert_integration(mock_post, detection_client):
    """
    Test that detection API triggers an alert POST to the alert service.
    """

    # Mock alert service response
    mock_post.return_value.status_code = 200
    mock_post.return_value.text = "Alert received and logged"

    # Send suspicious URL to detection API
    response = detection_client.post("/analyze", json={
        "url": "http://malware-website.com"
    })

    assert response.status_code == 200
    data = response.get_json()
    assert data["alert_sent"] == True

    # Confirm alert_service was called
    mock_post.assert_called_once()
