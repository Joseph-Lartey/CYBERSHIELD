# debug_sniff.py
from scapy.all import sniff

def debug_packet(packet):
    print(packet.summary())

print("Sniffing 5 packets on en0 (or lo0)...")
sniff(iface="en0", count=5, prn=debug_packet, store=False)
print("Done.")
