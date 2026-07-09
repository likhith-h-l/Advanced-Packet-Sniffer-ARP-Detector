"""
Packet Analyzer Module.

Provides deep packet inspection capabilities to extract protocol information
and relevant details from network packets using Scapy.
"""
import logging
from typing import Dict, Any
from scapy.all import TCP, UDP, ICMP, ARP, IPv6

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketAnalyzer:
    """
    Analyzes network packets to extract protocol-specific metadata.
    Supports TCP, UDP, ICMP, ARP, and IPv6.
    """
    
    def __init__(self) -> None:
        """Initializes the PacketAnalyzer."""
        pass

    def analyze_packet(self, packet: Any) -> Dict[str, Any]:
        """
        Analyzes a single packet to detect TCP, UDP, ICMP, ARP, or IPv6 protocols
        and extracts relevant details.
        
        Args:
            packet (Any): Scapy packet object.
            
        Returns:
            Dict[str, Any]: Dictionary containing the extracted packet details.
        """
        details: Dict[str, Any] = {
            "protocol": "Unknown",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "icmp_type": None,
            "icmp_code": None,
            "arp_op": None,
            "arp_src_mac": None,
            "arp_dst_mac": None,
            "arp_src_ip": None,
            "arp_dst_ip": None,
            "ipv6_src": None,
            "ipv6_dst": None
        }

        try:
            # Check for IPv6
            if packet.haslayer(IPv6):
                details["protocol"] = "IPv6"
                details["ipv6_src"] = packet[IPv6].src
                details["ipv6_dst"] = packet[IPv6].dst

            # Check for TCP
            if packet.haslayer(TCP):
                details["protocol"] = "TCP"
                details["src_port"] = packet[TCP].sport
                details["dst_port"] = packet[TCP].dport
                details["tcp_flags"] = str(packet[TCP].flags)
                
            # Check for UDP
            elif packet.haslayer(UDP):
                details["protocol"] = "UDP"
                details["src_port"] = packet[UDP].sport
                details["dst_port"] = packet[UDP].dport
                
            # Check for ICMP
            elif packet.haslayer(ICMP):
                details["protocol"] = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_type_map = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    4: "Source Quench",
                    5: "Redirect",
                    8: "Echo Request",
                    9: "Router Advertisement",
                    10: "Router Solicitation",
                    11: "Time Exceeded",
                    12: "Parameter Problem",
                    13: "Timestamp Request",
                    14: "Timestamp Reply"
                }
                details["icmp_type"] = icmp_type_map.get(icmp_type, f"Other ({icmp_type})")
                details["icmp_code"] = packet[ICMP].code
                    
            # Check for ARP
            elif packet.haslayer(ARP):
                details["protocol"] = "ARP"
                arp_op = packet[ARP].op
                arp_op_map = {
                    1: "ARP Request",
                    2: "ARP Reply",
                    3: "RARP Request",
                    4: "RARP Reply",
                    8: "InARP Request",
                    9: "InARP Reply"
                }
                details["arp_op"] = arp_op_map.get(arp_op, f"Other ({arp_op})")
                details["arp_src_mac"] = packet[ARP].hwsrc
                details["arp_dst_mac"] = packet[ARP].hwdst
                details["arp_src_ip"] = packet[ARP].psrc
                details["arp_dst_ip"] = packet[ARP].pdst
                    
        except Exception as e:
            logging.error(f"Error during packet analysis: {e}")

        return details
