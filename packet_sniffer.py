"""
Packet Sniffer Module.

Provides the PacketSniffer class for capturing network traffic asynchronously.
Integrates with the PacketAnalyzer for deep packet inspection and supports
callbacks for real-time GUI updates.
"""
import threading
import logging
from typing import Callable, Optional, Dict, Any, List
from scapy.all import sniff, IP, IPv6, ARP, Ether
from datetime import datetime
from packet_analyzer import PacketAnalyzer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketSniffer:
    """
    Captures network packets in a background thread and processes them.
    Uses callbacks to notify other components (like a GUI) of new packets.
    """
    
    def __init__(self, 
                 packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None, 
                 error_callback: Optional[Callable[[str], None]] = None) -> None:
        """
        Initializes the PacketSniffer.
        
        Args:
            packet_callback (Optional[Callable]): Function to call with packet_info when a packet is processed.
                                                  Useful for real-time GUI integration.
            error_callback (Optional[Callable]):  Function called with an error message string
                                                  when the sniffer encounters a fatal error (e.g. missing Npcap).
        """
        self.sniffing: bool = False
        self.thread: Optional[threading.Thread] = None
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self.captured_packets: List[Dict[str, Any]] = []
        self.analyzer = PacketAnalyzer()

    def _get_layer_stack(self, packet: Any) -> str:
        """Extracts the protocol stack of a packet as a string."""
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layers.append(layer.name)
            counter += 1
        return " -> ".join(layers)

    def _process_packet(self, packet: Any) -> None:
        """Callback for sniff() to process each captured packet."""
        try:
            # Extract Timestamp and Packet Length
            timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            packet_length = len(packet)
            
            src_ip = "N/A"
            dst_ip = "N/A"
            src_mac = "N/A"
            dst_mac = "N/A"
            protocol = "Other"

            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

            # Get advanced analysis details to determine precise protocol first
            analysis_details = self.analyzer.analyze_packet(packet)
            
            # Use analyzer's protocol if valid, else attempt basic IP proto mapping
            if analysis_details.get("protocol") != "Unknown":
                protocol = analysis_details.get("protocol")
            elif IP in packet:
                proto = packet[IP].proto
                if proto == 1: 
                    protocol = "ICMP"
                elif proto == 6: 
                    protocol = "TCP"
                elif proto == 17: 
                    protocol = "UDP"
                else: 
                    protocol = f"IP Proto {proto}"

            # Safely extract IP addresses from the correct layer
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            elif ARP in packet:
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                src_mac = packet[ARP].hwsrc
                dst_mac = packet[ARP].hwdst

            # Guarantee no empty strings
            src_ip = src_ip if src_ip else "N/A"
            dst_ip = dst_ip if dst_ip else "N/A"
            src_mac = src_mac if src_mac else "N/A"
            dst_mac = dst_mac if dst_mac else "N/A"

            layer_stack = self._get_layer_stack(packet)
            print(f"[DEBUG] Layer Stack: {layer_stack}")

            if src_ip == "N/A" or dst_ip == "N/A":
                logging.warning(f"Missing IP Info | Timestamp: {timestamp} | Protocol: {protocol} | Layers: {layer_stack}")

            packet_info: Dict[str, Any] = {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_mac": src_mac,
                "destination_mac": dst_mac,
                "protocol": protocol,
                "length": packet_length
            }
            # Merge extra details from analyzer, but do NOT overwrite the
            # protocol we already resolved (analysis_details always has a
            # "protocol" key that may be "Unknown").
            analysis_details.pop("protocol", None)
            packet_info.update(analysis_details)

            self.captured_packets.append(packet_info)
            
            # Call the callback function for GUI integration if provided
            if self.packet_callback:
                self.packet_callback(packet_info)
                
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def _sniff_loop(self) -> None:
        """Continuous sniffing loop run in a separate thread."""
        try:
            # stop_filter stops the sniff when self.sniffing is set to False (requires one packet to trigger evaluation)
            sniff(prn=self._process_packet, store=False, stop_filter=lambda x: not self.sniffing)
        except (RuntimeError, OSError, PermissionError) as e:
            # Common on Windows when Npcap / WinPcap is not installed or lacks privileges
            err_str = str(e).lower()
            if "npcap" in err_str or "winpcap" in err_str or "permission" in err_str or "no such device" in err_str:
                msg = ("Packet capture failed – Npcap (or WinPcap) does not appear to be installed, "
                       "or administrator privileges are missing.\n"
                       "Please run as Administrator or install Npcap from https://npcap.com/ and restart.")
            else:
                msg = f"Sniffing error: {e}"
            logging.error(msg)
            self.sniffing = False
            if self.error_callback:
                self.error_callback(msg)
        except Exception as e:
            logging.error(f"Sniffing error: {e}")
            self.sniffing = False
            if self.error_callback:
                self.error_callback(str(e))

    def start_sniffing(self) -> None:
        """Starts the packet sniffer in a background thread."""
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
            self.thread.start()
            logging.info("Packet sniffing started.")

    def stop_sniffing(self) -> None:
        """Stops the packet sniffer."""
        if self.sniffing:
            self.sniffing = False
            logging.info("Stopping packet sniffer (waiting for next packet to exit loop)...")
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=2.0)
            logging.info("Packet sniffing stopped.")

    def get_captured_packets(self) -> List[Dict[str, Any]]:
        """Returns all captured packets and clears the internal buffer."""
        packets = self.captured_packets[:]
        self.captured_packets.clear()
        return packets
