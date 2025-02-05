import pandas as pd
import joblib
import psutil
import platform
import os
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS  # Correct import for DNS
from scapy.packet import Raw  # Correct import for Raw
from datetime import datetime
import time

# Load trained models
scaler = joblib.load("CYBERSHIELD/scaler.joblib")
pca = joblib.load("CYBERSHIELD/pca.joblib")
model = joblib.load("CYBERSHIELD/rf_best_model.joblib")

# Get the exact features used during model training
expected_features = ["network_threats", "network_dns", "network_http", "network_connections", "apis", "registry_total"]

# Global cache to prevent duplicate alerts
alert_cache = {}

# Define log file path
log_file_path = os.path.abspath("CYBERSHIELD/threat_log.txt")
print(f"⚡ Logging to: {log_file_path}")  # Debugging step

# Log all detected packets
def log_packet(packet_info):
    """Logs all packets (both safe and threat)."""
    try:
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"{datetime.now()} - {packet_info}\n")
            log_file.flush()
            os.fsync(log_file.fileno())  # Force immediate write to disk
    except Exception as e:
        print(f"❌ ERROR: Could not write to log file: {e}")

# Get the number of running processes (API usage indicator)
def get_running_processes_count():
    """Returns the total number of running processes."""
    return len(list(psutil.process_iter()))

# Detect suspicious processes based on behavior
def detect_suspicious_processes():
    """Identifies suspicious processes based on high CPU/memory usage."""
    suspicious_processes = []
    
    for process in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
        name, path, cpu, memory = "Unknown", "Unknown", 0, 0  # Initialize variables
        
        try:
            if process.info.get('name'):
                name = process.info['name']
            if process.info.get('exe'):
                path = process.info['exe']
            if process.info.get('cpu_percent') is not None:
                cpu = process.info['cpu_percent']
            if process.info.get('memory_percent') is not None:
                memory = process.info['memory_percent']

            # Ignore common safe processes
            safe_processes = ["Python", "Code Helper", "Google Chrome", "Safari", "Finder", "WindowServer"]
            if name not in safe_processes and (cpu > 70 and memory > 25):  # Stricter threshold
                
                # Prevent multiple alerts for the same process within 5 seconds
                if name in alert_cache and (time.time() - alert_cache[name]) < 5:
                    continue  # Ignore duplicate alerts
                
                alert_cache[name] = time.time()  # Update last alert time
                suspicious_processes.append((name, path, cpu, memory))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return suspicious_processes

# Feature extraction function
def extract_features(packet):
    """Extracts relevant features from a network packet and system activity."""
    features = {
        "network_threats": 0,
        "network_dns": 0,
        "network_http": 0,
        "network_connections": 0,
        "apis": get_running_processes_count(),  # Active API usage indicator
        "registry_total": 0  # Windows registry tracking (if applicable)
    }

    if IP in packet:
        features["network_connections"] = 1

    if TCP in packet or UDP in packet:
        features["network_connections"] += 1

    if DNS in packet:
        features["network_dns"] = 1

    if Raw in packet:
        payload = packet[Raw].load.decode(errors="ignore").lower()
        if "http" in payload:
            features["network_http"] = 1
        if "malware" in payload or "attack" in payload:
            features["network_threats"] = 1

    # **Ensure no None values exist**
    for key in features:
        if features[key] is None:
            features[key] = 0  # Replace None with 0

    return features

# Threat detection function
def detect_threat(packet):
    """Processes captured packet, extracts features, and classifies it."""
    features = extract_features(packet)

    if features:
        df = pd.DataFrame([features])

        # Ensure missing features are filled with 0s
        for col in expected_features:
            if col not in df.columns:
                df[col] = 0

        df = df[expected_features]  # Ensure correct feature order

        # Apply transformations
        scaled_data = scaler.transform(df)
        pca_data = pca.transform(scaled_data)

        # Predict threat with probability threshold
        prediction_proba = model.predict_proba(pca_data)[0][1]  # Get probability score
        threshold = 0.7  # Adjust threshold (higher = fewer false positives)
        
        prediction = 1 if prediction_proba >= threshold else 0
        
        # Detect suspicious processes (ransomware indicators)
        suspicious_processes = detect_suspicious_processes()

        # Print and log threats
        if prediction == 1 or suspicious_processes:  # If network OR system activity is suspicious
            alert_message = f"\U0001F6A8 THREAT DETECTED \U0001F6A8 - {features}"
            if suspicious_processes:
                alert_message += f" | Suspicious Processes: {suspicious_processes}"
            print(alert_message)
            log_packet(alert_message)
        else:
            safe_message = f"✅ Safe Packet: {features}"
            print(safe_message)
            log_packet(safe_message)

# Start real-time monitoring
print("🔍 Starting CyberShield Threat Detection...")
sniff(prn=detect_threat, store=False)
