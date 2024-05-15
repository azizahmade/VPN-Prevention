import geoip2.database
from scapy.all import IP, sniff
from ipaddress import IPv4Address


class CIP_P2P:

    def __init__(self, database_path):
        self.reader = geoip2.database.Reader(database_path)

    def analyze_packet(self, packet):
        if IP in packet:
            source_ip = IPv4Address(packet[IP].src)
            country = self.get_country(source_ip)

            if country == 'Afghanistan':
                print(f"Allowed packet from {source_ip}")
            else:
                print(f"Blocked packet from {source_ip}")

    def get_country(self, ip):
        try:
            response = self.reader.country(ip.compressed)
            country_name = response.country.name
            return country_name
        except geoip2.errors.AddressNotFoundError:
            return 'Unknown'

    def __del__(self):
        self.reader.close()


if __name__ == "__main__":
    packets = sniff(iface="wlp2s0", count=100)

    ob = CIP_P2P("GeoLite2-Country.mmdb")
    for packet in packets:
        ob.analyze_packet(packet)
