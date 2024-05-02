from scapy.all import sniff, IP, TCP, UDP , DNS
from telnetlib import IP

class VPNServerIpDetector:

    vpn_server_ips = []
    with open('ip.txt', 'r') as ip:
        for line in ip:
            vpn_server_ips.append(line.strip())

    def analyze_packet(packet):
        if IP in packet:
            source_ip = packet[IP].src
            if source_ip in vpn_server_ips:
                print("VPN Traffic Detected from:", source_ip)

    vpn_server_domin = []
    with open ('domin.txt' , 'r') as domin:
        for line in domin:
            vpn_server_domin.append(line.strip())

    def analyze_dns(packet):

         if DNS in packet:
            if packet[DNS].qd.qname.decode() in vpn_server_domin:
                print("VPN DNS Query Detected:", packet[DNS].qd.qname.decode())

