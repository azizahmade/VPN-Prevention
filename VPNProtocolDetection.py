import pyshark


class VPNProtocolDetector:
    # Define the ports to monitor for VPN traffic
    VPN_PORTS = {1194, 500, 4500, 1701, 1723, 51820, 6881, 6882, 6883, 6884, 6885,
                 6886, 6887, 6888, 6889, 6969, 17000, 18000, 4662, 4665, 4672, 6346, 6347, 411, 412, 1214,
                 2234, 6257, 6699, 8888, 9001, 9030, 53, 22}

    def __init__(self, interface, tshark_path=None):
        self.interface = interface
        self.tshark_path = tshark_path

    def capture_vpn_traffic(self):
        capture = pyshark.LiveCapture(
            interface=self.interface, tshark_path=self.tshark_path)
        print(f"Listening on {self.interface}...")

        for packet in capture.sniff_continuously():
            try:
                # Check for IP layer presence
                if not hasattr(packet, 'ip'):
                    continue

                source_ip = packet.ip.src
                dest_ip = packet.ip.dst

                # Check TCP layer
                if 'TCP' in packet:
                    tcp_packet = packet.tcp
                    if int(tcp_packet.srcport) in self.VPN_PORTS or int(tcp_packet.dstport) in self.VPN_PORTS:
                        print(
                            f"TCP VPN traffic detected from {source_ip} to {dest_ip} on port {tcp_packet.srcport if int(tcp_packet.srcport) in self.VPN_PORTS else tcp_packet.dstport}")

                # Check UDP layer
                elif 'UDP' in packet:
                    udp_packet = packet.udp
                    if int(udp_packet.srcport) in self.VPN_PORTS or int(udp_packet.dstport) in self.VPN_PORTS:
                        print(
                            f"UDP VPN traffic detected from {source_ip} to {dest_ip} on port {udp_packet.srcport if int(udp_packet.srcport) in self.VPN_PORTS else udp_packet.dstport}")

            except AttributeError:
                # Ignore packets that don't have the required attributes
                continue
            except Exception as e:
                # Log other exceptions for debugging
                print(f"An error occurred: {e}")


if __name__ == "__main__":
    tshark_path = '/usr/bin/tshark'
    detector = VPNProtocolDetector('enp1s0f1', tshark_path)
    detector.capture_vpn_traffic()
