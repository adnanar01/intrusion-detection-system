# Importing necessary libraries
from scapy.all import sniff, IP, TCP, UDP
import logging
import datetime

# Configure logging to save alerts in a file
logging.basicConfig(filename="intrusion_alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# List of suspicious IPs for testing
suspicious_ips = ["192.168.1.100", "203.0.113.5"]

# Function to detect suspicious activities
def detect_intrusion(packet):
    if packet.haslayer(IP):  # Check if the packet contains an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"

        # Alert for suspicious IPs
        if src_ip in suspicious_ips:
            alert_msg = f"🚨 ALERT: Suspicious IP {src_ip} communicating with {dst_ip} via {protocol}"
            logging.info(alert_msg)
            print(alert_msg)

        # Port scanning detection (SYN flag in TCP packets)
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN flag
            alert_msg = f"⚠️ WARNING: Possible port scan from {src_ip} to {dst_ip}"
            logging.info(alert_msg)
            print(alert_msg)

# Start sniffing network packets
print("🚀 Intrusion Detection System is running... Press Ctrl+C to stop.")
sniff(filter="ip", prn=detect_intrusion, store=False)
