from scapy.all import sniff
import dpkt
import socket


def capture_packets(packet):
    if packet.haslayer('TCP') or packet.haslayer('UDP'):
        try:
            raw_packet = bytes(packet)
            analyze_packet(raw_packet, packet)
        except Exception as e:
            print(f"Error analyzing packet: {e}")


def analyze_packet(raw_packet, scapy_packet):
    try:
        eth = dpkt.ethernet.Ethernet(raw_packet)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                handle_tcp_packet(tcp, ip, scapy_packet)

            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                handle_udp_packet(udp, ip, scapy_packet)
    except Exception as e:
        print(f"Error parsing packet: {e}")


def handle_tcp_packet(tcp, ip, scapy_packet):
    if tcp.dport == 443:
        # SSL/TLS handshake or encrypted application data
        if len(tcp.data) > 0 and tcp.data[0] in {0x16, 0x17}:
            analyze_ssl_tls(tcp)
    elif tcp.dport in [1194, 1723]:  # OpenVPN or PPTP
        print(f"Detected VPN Traffic on TCP port {tcp.dport}")


def handle_udp_packet(udp, ip, scapy_packet):
    if udp.dport in [500, 1701, 4500, 1194]:  # IKEv2, L2TP, IPSec, OpenVPN
        print(f"Detected VPN Traffic on UDP port {udp.dport}")


def analyze_ssl_tls(tcp):
    try:
        if tcp.data[0] == 0x16:  # TLS Handshake
            records, _ = dpkt.ssl.tls_multi_factory(tcp.data)
            for record in records:
                if isinstance(record, dpkt.ssl.TLSRecord) and isinstance(record.data, dpkt.ssl.TLSHandshake):
                    handshake = record.data
                    if isinstance(handshake, dpkt.ssl.TLSClientHello):
                        if is_sstp_traffic(handshake):
                            print("Detected SSTP Traffic")
                        else:
                            print("Detected HTTPS Traffic")
        elif tcp.data[0] == 0x17:  # TLS Application Data
            print("Detected TLS Application Data (could be HTTPS or VPN)")
    except dpkt.ssl.SSL3Exception as e:
        print(f"SSL parsing error: {e}")
    except Exception as e:
        print(f"General parsing error: {e}")


def is_sstp_traffic(handshake):
    for ext in handshake.extensions:
        if isinstance(ext, dpkt.ssl.TLSExtServerName):
            server_name = ext.data
            if b'sstp' in server_name.lower():
                return True
    return False


if __name__ == "__main__":
    print("Listening for TCP and UDP traffic on relevant VPN ports...")
    sniff(prn=capture_packets, store=0)
