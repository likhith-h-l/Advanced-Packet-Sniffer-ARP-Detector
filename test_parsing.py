"""
Test Parsing Module.

Provides a simple test script to verify that the PacketSniffer correctly
parses various network protocols and handles missing IP information.
"""
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether
from packet_sniffer import PacketSniffer
from typing import Dict

def main() -> None:
    """Run a simulated packet parsing test."""
    sniffer = PacketSniffer()

    packets = [
        Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(),
        Ether()/IPv6(src="2001:db8::1", dst="2001:db8::2")/TCP(),
        Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/ICMP(),
        Ether()/ARP(psrc="192.168.1.100", pdst="192.168.1.101"),
        Ether() # Layer 2 only, should be N/A
    ]

    valid = 0
    missing = 0
    reasons: Dict[str, int] = {}

    print("--- Packet Processing Log ---")
    for p in packets:
        sniffer._process_packet(p)

    for pkt in sniffer.captured_packets:
        if pkt['source_ip'] == "N/A" or pkt['destination_ip'] == "N/A":
            missing += 1
            proto = pkt['protocol']
            reasons[proto] = reasons.get(proto, 0) + 1
        else:
            valid += 1

    print("\n--- Parsing Report ---")
    print(f"Total packets with valid IPs: {valid}")
    print(f"Total packets with missing IPs: {missing}")
    print("Reasons for missing IPs:")
    for proto, count in reasons.items():
        print(f" - Protocol '{proto}' lacks Layer 3 routing data ({count} instances)")

if __name__ == "__main__":
    main()
