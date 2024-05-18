# from scapy.all import sniff
# import dpkt
# import socket


# def capture_packets(packet):
#     if packet.haslayer('TCP') or packet.haslayer('UDP'):
#         try:
#             raw_packet = bytes(packet)
#             analyze_packet(raw_packet, packet)
#         except Exception as e:
#             print(f"Error analyzing packet: {e}")


# def analyze_packet(raw_packet, scapy_packet):
#     try:
#         eth = dpkt.ethernet.Ethernet(raw_packet)
#         if isinstance(eth.data, dpkt.ip.IP):
#             ip = eth.data

#             if isinstance(ip.data, dpkt.tcp.TCP):
#                 tcp = ip.data
#                 handle_tcp_packet(tcp, ip, scapy_packet)

#             elif isinstance(ip.data, dpkt.udp.UDP):
#                 udp = ip.data
#                 handle_udp_packet(udp, ip, scapy_packet)
#     except Exception as e:
#         print(f"Error parsing packet: {e}")


# def handle_tcp_packet(tcp, ip, scapy_packet):
#     if tcp.dport == 443:
#         if len(tcp.data) > 0 and tcp.data[0] == 0x16:  # SSL/TLS handshake
#             analyze_ssl_tls(tcp)
#     elif tcp.dport in [1194, 1723]:  # OpenVPN or PPTP
#         print(f"Detected VPN Traffic on TCP port {tcp.dport}")


# def handle_udp_packet(udp, ip, scapy_packet):
#     if udp.dport in [500, 1701, 4500, 1194]:  # IKEv2, L2TP, IPSec, OpenVPN
#         print(f"Detected VPN Traffic on UDP port {udp.dport}")


# def analyze_ssl_tls(tcp):
#     try:
#         records, _ = dpkt.ssl.tls_multi_factory(tcp.data)
#         for record in records:
#             if isinstance(record, dpkt.ssl.TLSRecord) and isinstance(record.data, dpkt.ssl.TLSHandshake):
#                 handshake = record.data
#                 if isinstance(handshake, dpkt.ssl.TLSClientHello):
#                     if is_sstp_traffic(handshake):
#                         print("Detected SSTP Traffic")
#                     else:
#                         print("Detected HTTPS Traffic")
#     except dpkt.ssl.SSL3Exception as e:
#         print(f"SSL parsing error: {e}")


# def is_sstp_traffic(handshake):
#     for ext in handshake.extensions:
#         if isinstance(ext, dpkt.ssl.TLSExtServerName):
#             server_name = ext.data
#             if b'sstp' in server_name.lower():
#                 return True
#     return False


# if __name__ == "__main__":
#     print("Listening for TCP and UDP traffic on relevant VPN ports...")
#     sniff(filter="tcp port 443 or tcp port 1194 or tcp port 1723 or udp port 500 or udp port 1701 or udp port 4500 or udp port 1194",
#           prn=capture_packets, store=0)

import requests
from scapy.all import sniff, IP

# API configuration
API_KEY = "553fcf3c78a54bab880f8e0455fc3973"
API_URL = "https://vpnapi.io/api/{ip_address}?key={API_key}"

# Function to query the VPN detection API


def check_vpn(ip):
    url = API_URL.format(ip_address=ip, API_key=API_KEY)
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get('security', {}).get('vpn', False)
    else:
        print(f"Failed to query API: {response.status_code}")
        return False

# Function to handle captured packets


def handle_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        print(f"Checking source IP: {ip_src}")
        if check_vpn(ip_src):
            print(f"Detected VPN traffic from source IP: {ip_src}")

        print(f"Checking destination IP: {ip_dst}")
        if check_vpn(ip_dst):
            print(f"Detected VPN traffic to destination IP: {ip_dst}")

# Capture packets on a specific interface (e.g., eth0)


def start_sniffing(interface="eth0"):
    print(f"Starting packet sniffing on interface {interface}")
    sniff(iface=interface, prn=handle_packet, store=0)


if __name__ == "__main__":
    # Change the interface name to match your system's network interface
    start_sniffing(interface="wlp2s0")
