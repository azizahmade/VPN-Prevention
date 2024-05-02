from telnetlib import IP
from scapy.all import *

class VPNServerIpDetector:

    vpn_server_ips = []
    with open('ipv4.txt', 'r') as file:
        for line in file:
            vpn_server_ips.append(line.strip())

    def analyze_packet(packet):
        if IP in packet:
            source_ip = packet[IP].src
            if source_ip in vpn_server_ips:
                print("VPN Traffic Detected from:", source_ip)

