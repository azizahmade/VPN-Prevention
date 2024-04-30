from scapy.all import sniff, IP, TCP, UDP

class VPNProtocolDetector:
    def __init__(self):
        self.vpn_protocols = {
            "OpenVPN": {
                "port": 1194,
                "payload_signature": b"OpenVPN",
                "header_length": 5,
                "header_offset": 8
            },
            "IPSec": {
                "ports": [500, 4500],
                "payload_signature": b"IPSec",
                "header_length": 5,
                "header_offset": 4
            },
            "L2TP": {
                "port": 1701,
                "payload_signature": b"L2TP",
                "header_length": 5,
                "header_offset": 8
            },
            "PPTP": {
                "port": 1723,
                "payload_signature": b"PPTP",
                "header_length": 4,
                "header_offset": 2
            },
            "SSTP": {
                "port": 443,
                "payload_signature": b"SSTP",
                "header_length": 5,
                "header_offset": 8
            },
            "WireGuard": {
                "port": 51820,
                "payload_signature": b"WireGuard",
                "header_length": None,
                "header_offset": None
            },
            "IKEv2": {
                "port": 500,
                "payload_signature": b"IKEv2",
                "header_length": 5,
                "header_offset": 4
            }
        }

    def packet_callback(self, packet):
        if IP in packet:
            ip_packet = packet[IP]
            
            if TCP in ip_packet:
                self.analyze_tcp(ip_packet[TCP])
            elif UDP in ip_packet:
                self.analyze_udp(ip_packet[UDP])

    def analyze_tcp(self, tcp_packet):
        source_port = tcp_packet.sport
        destination_port = tcp_packet.dport
        payload = bytes(tcp_packet.payload)

        for protocol, config in self.vpn_protocols.items():
            if destination_port == config.get("port"):
                if payload.startswith(config["payload_signature"]):
                    if self.check_header(tcp_packet, config):
                        print(f"Detected VPN Protocol: {protocol}")
                        break

    def analyze_udp(self, udp_packet):
        source_port = udp_packet.sport
        destination_port = udp_packet.dport
        payload = bytes(udp_packet.payload)

        for protocol, config in self.vpn_protocols.items():
            if destination_port in config.get("ports", []):
                if payload.startswith(config["payload_signature"]):
                    if self.check_header(udp_packet, config):
                        print(f"Detected VPN Protocol: {protocol}")
                        break

    def check_header(self, packet, config):
        header_length = config.get("header_length")
        header_offset = config.get("header_offset")

        if header_length is None or header_offset is None:
            return True

        if len(packet) >= header_offset + header_length:
            header_data = bytes(packet)[:header_offset+header_length]
            return header_data == bytes(packet)[:header_offset+header_length]

        return False

    def start_sniffing(self, interface):
        sniff(iface=interface, prn=self.packet_callback, filter="ip")

# Usage
detector = VPNProtocolDetector()
detector.start_sniffing("eth0")