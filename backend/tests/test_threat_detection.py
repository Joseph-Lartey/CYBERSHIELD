import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP, Raw

# ✅ Add backend folder to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Threat_detection import get_running_processes_count, detect_suspicious_processes, extract_features, detect_threat

# ✅ Test 1: Process Count
def test_get_running_processes_count():
    count = get_running_processes_count()
    assert isinstance(count, int)
    assert count > 0  # Assuming at least one process is running

# ✅ Test 2: Detect Suspicious Processes (Mocked)
@patch('Threat_detection.psutil.process_iter')
def test_detect_suspicious_processes(mock_process_iter):
    # Mock an empty list of processes to avoid delay
    mock_process_iter.return_value = []
    suspicious = detect_suspicious_processes()
    assert isinstance(suspicious, list)

# ✅ Test 3: Extract Features
def test_extract_features():
    # Create a fake packet
    packet = IP(dst="8.8.8.8")/TCP()/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n")
    features = extract_features(packet)
    assert isinstance(features, dict)
    expected_keys = ["network_threats", "network_dns", "network_http", "network_connections", "apis", "registry_total"]
    for key in expected_keys:
        assert key in features

# ✅ Test 4: Full Threat Detection (Mocked)
@patch('threat_detection.scaler')
@patch('threat_detection.pca')
@patch('threat_detection.model')
@patch('threat_detection.requests.post')
def test_detect_threat_once(mock_post, mock_model, mock_pca, mock_scaler):
    # Mock behavior
    mock_scaler.transform.return_value = [[0]*6]
    mock_pca.transform.return_value = [[0]*6]
    mock_model.predict_proba.return_value = [[0.1, 0.9]]  # high threat

    # Create a simple fake packet
    from scapy.all import IP, TCP, Raw
    packet = IP(dst="8.8.8.8")/TCP()/Raw(load=b"attack")

    # Only detect ONCE
    detect_threat(packet)

    mock_post.assert_called()  # Confirm alert sent
