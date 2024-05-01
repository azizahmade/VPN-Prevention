from scapy.all import  UDP , TCP , IP , sniff ,Ether
from VPNProtocolDetection import VPNProtocolDetector

if __name__ == "__main__":
    packets = sniff(iface="wlp2s0", count=10)

    pd = VPNProtocolDetector()
    pd.packet_callback(packets)
    
          
