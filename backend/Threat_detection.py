import pandas as pd
import joblib
import psutil
import os
import time
import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.packet import Raw

# Load ML models
scaler = joblib.load("ml_models/scaler.joblib")
pca = joblib.load("ml_models/pca.joblib")
model = joblib.load("ml_models/rf_best_model.joblib")

expected_features = [
    "network_threats", "network_dns", "network_http",
    "network_connections", "apis", "registry_total"
]

# Avoid duplicate alerts
alert_cache = {}

# Process Monitoring
def get_running_processes_count():
    return len(list(psutil.process_iter()))

def detect_suspicious_processes():
    suspicious = []
    for process in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
        try:
            name = process.info.get('name', 'Unknown')
            path = process.info.get('exe', 'Unknown')
            cpu = process.info.get('cpu_percent', 0)
            memory = process.info.get('memory_percent', 0)

            if name not in ["Python", "Google Chrome", "Safari", "Finder", "WindowServer"] and cpu > 10 and memory > 5:
                if name in alert_cache and (time.time() - alert_cache[name]) < 5:
                    continue
                alert_cache[name] = time.time()
                suspicious.append((name, path, cpu, memory))
        except:
            continue
    return suspicious

# Packet Feature Extraction
def extract_features(packet):
    features = {
        "network_threats": 0,
        "network_dns": 0,
        "network_http": 0,
        "network_connections": 0,
        "apis": get_running_processes_count(),
        "registry_total": 0
    }

    if IP in packet:
        features["network_connections"] = 1
    if TCP in packet or UDP in packet:
        features["network_connections"] += 1
    if DNS in packet:
        features["network_dns"] = 1
    if Raw in packet:
        raw_payload = packet[Raw].load
        print(f"Raw payload: {raw_payload}")
        payload_str = raw_payload.decode(errors="ignore").lower()
        if "http" in payload_str:
            features["network_http"] = 1
        if "malware" in payload_str or "attack" in payload_str:
            features["network_threats"] = 1

    print(f"🧐 Extracted Features: {features}")
    return features

# Threat Detection Pipeline
def detect_threat(packet):
    print(f"\n📦 Captured Packet:\n{packet.summary()}")
    print(packet.show(dump=True))

    features = extract_features(packet)
    if not features:
        return

    df = pd.DataFrame([features])
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0
    df = df[expected_features]

    scaled = scaler.transform(df)
    reduced = pca.transform(scaled)
    proba = model.predict_proba(reduced)[0][1]
    print(f"🔎 Threat Probability: {proba:.4f}")

    suspicious_processes = detect_suspicious_processes()

    if proba >= 0.4 or suspicious_processes:
        payload = {
            "ip": packet[IP].src if IP in packet else "unknown",
            "features": features,
            "probability": float(proba),
            "suspicious_processes": suspicious_processes,
            "source": "scapy"
        }
        try:
            res = requests.post("http://localhost:5001/alert", json=payload)
            print(f"📤 Alert sent to Alerting Subsystem: {res.status_code}")
        except Exception as e:
            print(f"❌ Could not send alert: {e}")
    else:
        print("✅ Packet is safe.")

# Start Packet Sniffing
# iface_name = "Wi-Fi"
# print(f"🔍 Starting packet sniffing on interface: {iface_name}")
# sniff(iface=iface_name, prn=detect_threat, store=False)


#made this change because of a cicd error
# if __name__ == "__main__":
#     iface_name = "Wi-Fi"
#     print(f"🔍 Starting packet sniffing on interface: {iface_name}")
#     sniff(iface=iface_name, prn=detect_threat, store=False)








# # ===============================
# # UPDATED THREAT DETECTION SYSTEM
# # ===============================

# import pandas as pd
# import joblib
# import psutil
# import platform
# import os
# import requests
# from scapy.all import sniff, send
# from scapy.layers.inet import IP, TCP, UDP
# from scapy.layers.dns import DNS
# from scapy.packet import Raw
# from datetime import datetime
# import time

# # Load trained models
# scaler = joblib.load("ml_models/scaler.joblib")
# pca = joblib.load("ml_models/pca.joblib")
# model = joblib.load("ml_models/rf_best_model.joblib")

# # Features used during model training
# expected_features = [
#     "network_threats",
#     "network_dns",
#     "network_http",
#     "network_connections",
#     "apis",
#     "registry_total"
# ]

# # Global cache to prevent duplicate alerts
# alert_cache = {}

# # ------------------------------------------------------------------------
# # Process Monitoring
# # ------------------------------------------------------------------------
# def get_running_processes_count():
#     return len(list(psutil.process_iter()))

# def detect_suspicious_processes():
#     suspicious_processes = []
#     for process in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
#         try:
#             name = process.info.get('name', 'Unknown')
#             path = process.info.get('exe', 'Unknown')
#             cpu = process.info.get('cpu_percent', 0)
#             memory = process.info.get('memory_percent', 0)

#             if (name not in ["Python", "Code Helper", "Google Chrome", "Safari", "Finder", "WindowServer"]
#                 and cpu > 10 and memory > 5):

#                 if name in alert_cache and (time.time() - alert_cache[name]) < 5:
#                     continue

#                 alert_cache[name] = time.time()
#                 suspicious_processes.append((name, path, cpu, memory))
#         except:
#             continue
#     return suspicious_processes

# # ------------------------------------------------------------------------
# # Feature Extraction
# # ------------------------------------------------------------------------
# def extract_features(packet):
#     features = {
#         "network_threats": 0,
#         "network_dns": 0,
#         "network_http": 0,
#         "network_connections": 0,
#         "apis": get_running_processes_count(),
#         "registry_total": 0
#     }

#     if IP in packet:
#         features["network_connections"] = 1
#     if TCP in packet or UDP in packet:
#         features["network_connections"] += 1
#     if DNS in packet:
#         features["network_dns"] = 1

#     if Raw in packet:
#         raw_payload = packet[Raw].load
#         print(f"Raw payload (debug): {raw_payload}")
#         payload_str = raw_payload.decode(errors="ignore").lower()
#         if "http" in payload_str:
#             features["network_http"] = 1
#         if "malware" in payload_str or "attack" in payload_str:
#             features["network_threats"] = 1

#     print(f"🧐 Extracted Features: {features}")
#     return features

# # ------------------------------------------------------------------------
# # Threat Detection and Alert API Trigger
# # ------------------------------------------------------------------------
# def detect_threat(packet):
#     print(f"\n📦 Captured Packet:\n{packet.summary()}")
#     print(packet.show(dump=True))

#     features = extract_features(packet)
#     if not features:
#         return

#     df = pd.DataFrame([features])
#     for col in expected_features:
#         if col not in df.columns:
#             df[col] = 0
#     df = df[expected_features]

#     scaled_data = scaler.transform(df)
#     pca_data = pca.transform(scaled_data)

#     prediction_proba = model.predict_proba(pca_data)[0][1]
#     print(f"🔎 Model probability: {prediction_proba:.4f}")

#     threshold = 0.4
#     prediction = 1 if prediction_proba >= threshold else 0

#     suspicious_processes = detect_suspicious_processes()

#     if prediction == 1 or suspicious_processes:
#         payload = {
#             "ip": packet[IP].src if IP in packet else "unknown",
#             "features": features,
#             "probability": float(prediction_proba),
#             "suspicious_processes": suspicious_processes
#         }
#         try:
#             response = requests.post("http://localhost:5001/alert", json=payload)
#             print(f"📤 Sent alert to Alerting Subsystem: {response.status_code}")
#         except Exception as e:
#             print(f"❌ Failed to send alert: {e}")
#     else:
#         print(f"✅ Safe Packet: {features}")

# # ------------------------------------------------------------------------
# # Start Packet Sniffing
# # ------------------------------------------------------------------------
# iface_name = "en0"
# print(f"🔍 Starting CyberShield Threat Detection on interface: {iface_name}")
# sniff(iface=iface_name, prn=detect_threat, store=False)



# import pandas as pd
# import joblib
# import psutil
# import platform
# import os
# from scapy.all import sniff, send
# from scapy.layers.inet import IP, TCP, UDP
# from scapy.layers.dns import DNS
# from scapy.packet import Raw
# from datetime import datetime
# import time

# # Load trained models
# scaler = joblib.load("ml_models/scaler.joblib")
# pca = joblib.load("ml_models/pca.joblib")
# model = joblib.load("ml_models/rf_best_model.joblib")

# # Features used during model training
# expected_features = [
#     "network_threats",
#     "network_dns",
#     "network_http",
#     "network_connections",
#     "apis",
#     "registry_total"
# ]

# # Global cache to prevent duplicate alerts (for suspicious processes)
# alert_cache = {}

# # Define log file path
# log_file_path = os.path.abspath("threat_log.txt")
# print(f"⚡ Logging to: {log_file_path}")  # Debugging

# # ------------------------------------------------------------------------
# # Logging
# # ------------------------------------------------------------------------
# def log_packet(packet_info):
#     """Logs packets or alerts to a file."""
#     try:
#         with open(log_file_path, "a", encoding="utf-8") as log_file:
#             log_file.write(f"{datetime.now()} - {packet_info}\n")
#             log_file.flush()
#             os.fsync(log_file.fileno())  # Force immediate write to disk
#     except Exception as e:
#         print(f"❌ ERROR: Could not write to log file: {e}")

# # ------------------------------------------------------------------------
# # Process Monitoring (Suspicious Processes)
# # ------------------------------------------------------------------------
# def get_running_processes_count():
#     """Returns the total number of running processes."""
#     return len(list(psutil.process_iter()))

# def detect_suspicious_processes():
#     """
#     Identifies suspicious processes based on CPU/memory usage.
#     We lower thresholds for testing to see results more easily.
#     """
#     suspicious_processes = []
    
#     for process in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
#         try:
#             name = process.info.get('name', 'Unknown')
#             path = process.info.get('exe', 'Unknown')
#             cpu = process.info.get('cpu_percent', 0)
#             memory = process.info.get('memory_percent', 0)

#             # Lower thresholds for testing (raise them for production use).
#             if (name not in ["Python", "Code Helper", "Google Chrome", "Safari", 
#                              "Finder", "WindowServer"] 
#                 and cpu > 10 and memory > 5):

#                 # Prevent multiple alerts for the same process within 5 seconds
#                 if name in alert_cache and (time.time() - alert_cache[name]) < 5:
#                     continue

#                 alert_cache[name] = time.time()  # Update last alert time
#                 suspicious_processes.append((name, path, cpu, memory))

#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             continue
    
#     return suspicious_processes

# # ------------------------------------------------------------------------
# # Feature Extraction from Packets
# # ------------------------------------------------------------------------
# def extract_features(packet):
#     """Extracts relevant features from a network packet and system activity."""
#     features = {
#         "network_threats": 0,
#         "network_dns": 0,
#         "network_http": 0,
#         "network_connections": 0,
#         "apis": get_running_processes_count(),  # Active process count
#         "registry_total": 0
#     }

#     # Increment for IP
#     if IP in packet:
#         features["network_connections"] = 1

#     # Increment more if TCP/UDP is present
#     if TCP in packet or UDP in packet:
#         features["network_connections"] += 1

#     # Check for DNS traffic
#     if DNS in packet:
#         features["network_dns"] = 1

#     # Check payload for keywords
#     if Raw in packet:
#         # Print the raw payload for debugging
#         raw_payload = packet[Raw].load
#         print(f"Raw payload (debug): {raw_payload}")

#         # Convert to lowercase for keyword checks
#         payload_str = raw_payload.decode(errors="ignore").lower()

#         if "http" in payload_str:
#             features["network_http"] = 1
#         if "malware" in payload_str or "attack" in payload_str:
#             features["network_threats"] = 1

#     # Debugging: Print extracted features
#     print(f"🧐 Extracted Features: {features}")

#     return features

# # ------------------------------------------------------------------------
# # Threat Detection Logic
# # ------------------------------------------------------------------------
# def detect_threat(packet):
#     """Processes captured packet, extracts features, and classifies it."""

#     # Print raw packet details to confirm capture
#     print(f"\n📦 Captured Packet:\n{packet.summary()}")
#     print(packet.show(dump=True))  # Detailed packet view

#     features = extract_features(packet)
#     if not features:
#         return  # No features extracted, skip

#     # Convert to DataFrame
#     df = pd.DataFrame([features])

#     # Ensure all expected features exist
#     for col in expected_features:
#         if col not in df.columns:
#             df[col] = 0

#     # Re-order columns
#     df = df[expected_features]

#     # Apply scaler & PCA transformations
#     scaled_data = scaler.transform(df)
#     pca_data = pca.transform(scaled_data)

#     # Predict threat probability
#     prediction_proba = model.predict_proba(pca_data)[0][1]
#     print(f"🔎 Model probability: {prediction_proba:.4f}")  # Debugging

#     # Threshold for classification
#     threshold = 0.4  # Adjust as needed
#     prediction = 1 if prediction_proba >= threshold else 0

#     # Check suspicious processes
#     suspicious_processes = detect_suspicious_processes()

#     # If the model or suspicious processes indicate a threat
#     if prediction == 1 or suspicious_processes:
#         alert_message = f"🚨 THREAT DETECTED - Features: {features}"
#         if suspicious_processes:
#             alert_message += f" | Suspicious Processes: {suspicious_processes}"
#         print(alert_message)
#         log_packet(alert_message)
#     else:
#         safe_message = f"✅ Safe Packet: {features}"
#         print(safe_message)
#         log_packet(safe_message)

# # ------------------------------------------------------------------------
# # Choose the Interface
# # ------------------------------------------------------------------------
# # Otherwise, "en0" is typically Wi-Fi/Ethernet on a Mac
# iface_name = "en0"

# print(f"🔍 Starting CyberShield Threat Detection on interface: {iface_name}")
# sniff(iface=iface_name, prn=detect_threat, store=False)











# import pandas as pd
# import joblib
# import psutil
# import platform
# import os
# from scapy.all import sniff, send
# from scapy.layers.inet import IP, TCP, UDP
# from scapy.layers.dns import DNS
# from scapy.packet import Raw
# from datetime import datetime
# import time

# # Load trained models
# scaler = joblib.load("ml_models/scaler.joblib")
# pca = joblib.load("ml_models/pca.joblib")
# model = joblib.load("ml_models/rf_best_model.joblib")

# # Features used during model training
# expected_features = [
#     "network_threats",
#     "network_dns",
#     "network_http",
#     "network_connections",
#     "apis",
#     "registry_total"
# ]

# # Global cache to prevent duplicate alerts (for suspicious processes)
# alert_cache = {}

# # Define log file path
# log_file_path = os.path.abspath("threat_log.txt")
# print(f"⚡ Logging to: {log_file_path}")  # Debugging

# # ------------------------------------------------------------------------
# # Logging
# # ------------------------------------------------------------------------
# def log_packet(packet_info):
#     """Logs packets or alerts to a file."""
#     try:
#         with open(log_file_path, "a", encoding="utf-8") as log_file:
#             log_file.write(f"{datetime.now()} - {packet_info}\n")
#             log_file.flush()
#             os.fsync(log_file.fileno())  # Force immediate write to disk
#     except Exception as e:
#         print(f"❌ ERROR: Could not write to log file: {e}")

# # ------------------------------------------------------------------------
# # Process Monitoring (Suspicious Processes)
# # ------------------------------------------------------------------------
# def get_running_processes_count():
#     """Returns the total number of running processes."""
#     return len(list(psutil.process_iter()))

# def detect_suspicious_processes():
#     """
#     Identifies suspicious processes based on CPU/memory usage.
#     We lower thresholds for testing to see results more easily.
#     """
#     suspicious_processes = []
    
#     for process in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
#         try:
#             name = process.info.get('name', 'Unknown')
#             path = process.info.get('exe', 'Unknown')
#             cpu = process.info.get('cpu_percent', 0)
#             memory = process.info.get('memory_percent', 0)

#             # Lower thresholds for testing (raise them for production use).
#             if (name not in ["Python", "Code Helper", "Google Chrome", "Safari", 
#                              "Finder", "WindowServer"] 
#                 and cpu > 10 and memory > 5):

#                 # Prevent multiple alerts for the same process within 5 seconds
#                 if name in alert_cache and (time.time() - alert_cache[name]) < 5:
#                     continue

#                 alert_cache[name] = time.time()  # Update last alert time
#                 suspicious_processes.append((name, path, cpu, memory))

#         except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
#             continue
    
#     return suspicious_processes

# # ------------------------------------------------------------------------
# # Feature Extraction from Packets
# # ------------------------------------------------------------------------
# def extract_features(packet):
#     """Extracts relevant features from a network packet and system activity."""
#     features = {
#         "network_threats": 0,
#         "network_dns": 0,
#         "network_http": 0,
#         "network_connections": 0,
#         "apis": get_running_processes_count(),  # Active process count
#         "registry_total": 0
#     }

#     # Increment for IP
#     if IP in packet:
#         features["network_connections"] = 1

#     # Increment more if TCP/UDP is present
#     if TCP in packet or UDP in packet:
#         features["network_connections"] += 1

#     # Check for DNS traffic
#     if DNS in packet:
#         features["network_dns"] = 1

#     # Check payload for keywords
#     if Raw in packet:
#         # Print the raw payload for debugging
#         raw_payload = packet[Raw].load
#         print(f"Raw payload (debug): {raw_payload}")

#         # Convert to lowercase for keyword checks
#         payload_str = raw_payload.decode(errors="ignore").lower()

#         if "http" in payload_str:
#             features["network_http"] = 1
#         if "malware" in payload_str or "attack" in payload_str:
#             features["network_threats"] = 1

#     # Debugging: Print extracted features
#     print(f"🧐 Extracted Features: {features}")

#     return features

# # ------------------------------------------------------------------------
# # Threat Detection Logic
# # ------------------------------------------------------------------------
# def detect_threat(packet):
#     """Processes captured packet, extracts features, and classifies it."""
#     features = extract_features(packet)
#     if not features:
#         return  # No features extracted, skip

#     # Convert to DataFrame
#     df = pd.DataFrame([features])

#     # Ensure all expected features exist
#     for col in expected_features:
#         if col not in df.columns:
#             df[col] = 0

#     # Re-order columns
#     df = df[expected_features]

#     # Apply scaler & PCA transformations
#     scaled_data = scaler.transform(df)
#     pca_data = pca.transform(scaled_data)

#     # Predict threat probability
#     prediction_proba = model.predict_proba(pca_data)[0][1]
#     print(f"🔎 Model probability: {prediction_proba:.4f}")  # Debugging

#     # Threshold for classification
#     threshold = 0.4  # Adjust as needed
#     prediction = 1 if prediction_proba >= threshold else 0

#     # Check suspicious processes
#     suspicious_processes = detect_suspicious_processes()

#     # If the model or suspicious processes indicate a threat
#     if prediction == 1 or suspicious_processes:
#         alert_message = f"🚨 THREAT DETECTED - Features: {features}"
#         if suspicious_processes:
#             alert_message += f" | Suspicious Processes: {suspicious_processes}"
#         print(alert_message)
#         log_packet(alert_message)
#     else:
#         safe_message = f"✅ Safe Packet: {features}"
#         print(safe_message)
#         log_packet(safe_message)

# # ------------------------------------------------------------------------
# # Choose the Interface
# # ------------------------------------------------------------------------
# # If you're sending packets to 127.0.0.1, set iface_name = "lo0"
# # Otherwise, "en0" is typically Wi-Fi/Ethernet on a Mac
# iface_name = "en0"

# print(f"🔍 Starting CyberShield Threat Detection on interface: {iface_name}")
# sniff(iface=iface_name, prn=detect_threat, store=False)

