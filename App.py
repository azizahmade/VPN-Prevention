from scapy.all import *
from VPNProtocolDetection import VPNProtocolDetector
from VPNServerIP import VPNServerIpDetector
from CIP_P2P import CIP_P2P

if __name__ == "__main__":
    packets = sniff(iface="wlp2s0", count=10)

    # output_file = "captured_packets.pcap"
    # wrpcap(output_file, packets)

    # pd = VPNProtocolDetector()
    # pd.packet_callback(packets)

    # ipd = VPNServerIpDetector()
    # ipd.analyze_packet(packets)

    ri = CIP_P2P()
    ri.analyze_packet(packets)
          

