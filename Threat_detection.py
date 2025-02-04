import pandas as pd
import joblib
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

# Load trained models
scaler = joblib.load("scaler.joblib")
pca = joblib.load("pca.joblib")
model = joblib.load("rf_best_model.joblib")

# Define the numerical features used for scaling/PCA
num_features = ["packet_length", "src_port", "dst_port"]

# Log detected threats
def log_threat(threat_info):
    with open("threat_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {threat_info}\n")

# Feature extraction function
def extract_features(packet):
    """Extracts relevant features from a network packet."""
    features = {}
    if IP in packet:
        features["src_ip"] = packet[IP].src
        features["dst_ip"] = packet[IP].dst
        features["packet_length"] = len(packet)
        
        if TCP in packet:
            features["protocol"] = "TCP"
            features["src_port"] = packet[TCP].sport
            features["dst_port"] = packet[TCP].dport
            features["flags"] = str(packet[TCP].flags)
        elif UDP in packet:
            features["protocol"] = "UDP"
            features["src_port"] = packet[UDP].sport
            features["dst_port"] = packet[UDP].dport
    return features

# Threat detection function
def detect_threat(packet):
    """Processes captured packet, extracts features, and classifies it."""
    features = extract_features(packet)
    
    if features:
        df = pd.DataFrame([features])
        
        # Fill missing numerical fields
        df_num = df[num_features].fillna(0)
        
        # Apply transformations
        scaled_data = scaler.transform(df_num)
        pca_data = pca.transform(scaled_data)

        # Predict threat
        prediction = model.predict(pca_data)[0]

        # Print result and log if a threat is detected
        if prediction == 1:  # Assuming '1' means a detected threat
            alert_message = f"🚨 THREAT DETECTED 🚨 - {features}"
            print(alert_message)
            log_threat(alert_message)
        else:
            print(f"Safe Packet: {features}")

# Start real-time monitoring
print("🔍 Starting CyberShield Threat Detection...")
sniff(prn=detect_threat, store=False)
