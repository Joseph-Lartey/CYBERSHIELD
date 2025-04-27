import sys
import os
import pytest
import json
from unittest.mock import patch, MagicMock

# ✅ Add backend folder to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_api import app

# ✅ Flask test client fixture
@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()

# ✅ Test 1: Test analyze_packet normal URL
@patch('detection_api.scaler')
@patch('detection_api.pca')
@patch('detection_api.model')
@patch('detection_api.requests.post')
def test_analyze_packet_normal(mock_post, mock_model, mock_pca, mock_scaler, client):
    # Mock scaler and pca transformation
    mock_scaler.transform.return_value = [[0] * 6]
    mock_pca.transform.return_value = [[0] * 6]
    mock_model.predict_proba.return_value = [[0.1, 0.3]]  # low probability

    response = client.post("/analyze", json={"url": "http://example.com"})
    data = response.get_json()

    assert response.status_code == 200
    assert data["alert_sent"] == False

# ✅ Test 2: Test analyze_packet malware URL
@patch('detection_api.scaler')
@patch('detection_api.pca')
@patch('detection_api.model')
@patch('detection_api.requests.post')
def test_analyze_packet_malware(mock_post, mock_model, mock_pca, mock_scaler, client):
    mock_scaler.transform.return_value = [[0] * 6]
    mock_pca.transform.return_value = [[0] * 6]
    mock_model.predict_proba.return_value = [[0.1, 0.95]]  # very high probability

    response = client.post("/analyze", json={"url": "http://malware-site.com"})
    data = response.get_json()

    assert response.status_code == 200
    assert data["alert_sent"] == True
    mock_post.assert_called_once()  # Check that an alert was sent
