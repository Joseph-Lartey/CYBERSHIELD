"""
test_traffic.py
---------------
Sends fake "malware" packets to 127.0.0.1 by default.
Use lo0 in cybershield.py if you're sniffing localhost traffic.
"""

from scapy.all import IP, TCP, Raw, send

def send_test_packet(dst_ip="127.0.0.1", dport=4444):
    # Create a packet that contains "malware" in the payload
    packet = IP(dst=dst_ip) / TCP(dport=dport) / Raw(load="This is a MALWARE test")
    send(packet, verbose=False)
    print(f"Packet sent to {dst_ip}:{dport} with 'MALWARE' in the payload.")

if __name__ == "__main__":
    send_test_packet()
