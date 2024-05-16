import pyshark


class VPNServerIpDetector:

    def __init__(self):
        self.vpn_server_ips = []
        self.vpn_server_domains = []

        # Read VPN server IPs from file
        with open('ip.txt', 'r') as ip_file:
            for line in ip_file:
                self.vpn_server_ips.append(line.strip())

        # Read VPN server domains from file
        with open('domin.txt', 'r') as domain_file:
            for line in domain_file:
                self.vpn_server_domains.append(line.strip())

    def analyze_packet(self, packet):
        try:
            if 'IP' in packet:
                source_ip = packet.ip.src
                if source_ip in self.vpn_server_ips:
                    print("VPN Traffic Detected from:", source_ip)
            if 'DNS' in packet:
                dns_query = packet.dns.qry_name
                if dns_query in self.vpn_server_domains:
                    print("VPN DNS Query Detected:", dns_query)
        except AttributeError:
            # Ignore packets that do not have the required attributes
            pass

    def capture_vpn_traffic(self, interface):
        capture = pyshark.LiveCapture(interface=interface)
        print(f"Listening on {interface}...")

        for packet in capture.sniff_continuously():
            self.analyze_packet(packet)


if __name__ == "__main__":
    detector = VPNServerIpDetector()
    detector.capture_vpn_traffic('wlp2s0')
