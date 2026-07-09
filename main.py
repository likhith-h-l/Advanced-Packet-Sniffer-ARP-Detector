"""
Main entry point for the Advanced Packet Sniffer & ARP Threat Detection System.
Provides both a Graphical User Interface (GUI) and a Command-Line Interface (CLI) mode.
"""
import sys
import time
import os

# Ensure the project root is on sys.path so that sibling modules can be imported
# regardless of the working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packet_sniffer import PacketSniffer
from arp_detector import ARPDetector
from logger_manager import log_packet, log_alert


def _cli_mode() -> None:
    """Run the sniffer in headless CLI mode."""
    detector = ARPDetector()

    def print_packet(packet_info: dict) -> None:
        """Callback function to print packet details and log them."""
        print(packet_info)
        # Log every analyzed packet
        log_packet(packet_info)

        # Pass the captured packet details to the ARP Detector
        alert = detector.process_packet(packet_info)
        if alert:
            # Log the ARP spoofing alert
            log_alert(alert)
            print("\n" + "=" * 60)
            print(alert)
            print("=" * 60 + "\n")

    print("Starting packet sniffer (CLI mode)...")
    print("Press Ctrl+C to stop.\n")

    sniffer = PacketSniffer(packet_callback=print_packet)

    try:
        sniffer.start_sniffing()

        # Keep the main thread alive so the background thread can run
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping packet sniffer...")
        sniffer.stop_sniffing()
        print("Packet sniffer stopped.")


def _gui_mode() -> None:
    """Launch the graphical SOC dashboard."""
    from gui.dashboard import Dashboard
    Dashboard().run()


def main() -> None:
    """Determine the mode of operation based on command-line arguments."""
    if "--cli" in sys.argv:
        _cli_mode()
    else:
        _gui_mode()


if __name__ == "__main__":
    main()
