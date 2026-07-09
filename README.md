# Advanced Packet Sniffer & ARP Threat Detection System

## Overview
A professional-grade, multi-threaded packet capture and network security monitoring platform built in Python. This system features a real-time Security Operations Center (SOC) dashboard, live traffic analysis, and Real-Time ARP Monitoring and Threat Detection.

## Features
- **Real-Time Network Monitoring**: Continuous capture and deep packet inspection of IPv4, IPv6, TCP, UDP, ICMP, and ARP traffic.
- **Real-Time ARP Monitoring and Threat Detection**: Advanced state tracking to identify MAC address inconsistencies, poisoning attempts, and potential Man-in-the-Middle (MitM) activities.
- **SOC Console Dashboard**: A modern, responsive dark-themed UI built with CustomTkinter, designed for high-resolution displays and rapid incident response.
- **Dynamic Threat Level Indicator**: Granular threat escalation (INFO, LOW, MEDIUM, HIGH, CRITICAL) based on real-time security alerts and network anomalies.
- **Traffic Analysis & Top Talkers**: Real-time aggregation of top Source and Destination IP addresses to quickly identify bandwidth hogs and anomalous communicators.
- **Live Search & Filtering**: Case-insensitive filtering by IP, protocol, and alert status with instant UI updates.
- **Automated Reporting & Alert Management**: Export captured traffic and security alerts to CSV formats for post-incident forensics and compliance logging.
- **Headless CLI Mode**: Execution capability in terminal environments for headless server deployments.

## Architecture
1. **`main.py`**: Execution entry point handling both CLI and GUI operational modes.
2. **`packet_sniffer.py`**: Background asynchronous engine utilizing `scapy` for continuous packet capture without blocking the main UI thread.
3. **`packet_analyzer.py`**: Deep packet inspection module designed to extract Layer 3 and Layer 4 metadata (ports, ICMP types, ARP opcodes).
4. **`arp_detector.py`**: Maintains isolated IP-to-MAC resolution tables to identify and alert on anomalous ARP behaviors.
5. **`logger_manager.py`**: Asynchronous JSON and plain-text logging mechanisms for persistent traffic and alert retention.
6. **`report_generator.py`**: Dynamically maps and exports captured packet and alert structures to standardized CSV formats.
7. **`gui/dashboard.py`**: Thread-safe presentation layer orchestrating the sniffer, detector, detailed packet views, and live data telemetry.

## 📸 Dashboard Screenshots

| Dashboard | ARP Detection |
|-----------|---------------|
|<img src="assets/dashboard.png" width="450">|

| TCP Capture | UDP Capture |
|-------------|-------------|
| <img src="assets/tcp_capture.png" width="450"> | <img src="assets/udp_capture.png" width="450"> |

| ICMP Capture | IPv6 Capture |
|--------------|--------------|
| <img src="assets/icmp_capture.png" width="450"> | <img src="assets/ipv6_capture.png" width="450"> |

| Report Export | Architecture |
|---------------|--------------|
| <img src="assets/report_export.png" width="450"> | <img src="assets/architecture.png" width="450"> |

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Advanced_Packet_Sniffer_ARP_Detector.git
cd Advanced_Packet_Sniffer_ARP_Detector

# Create and activate a virtual environment (recommended)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Requirements
- Python 3.8+
- Scapy
- CustomTkinter
- **System Level**: [Npcap](https://npcap.com/) (on Windows) or `libpcap` (on Linux/macOS) is required for raw socket packet capturing. 
- **Privileges**: Administrator / root privileges are typically required to sniff network interfaces.

## How It Works

### Packet Capture Workflow
1. The user initiates sniffing from the GUI or CLI.
2. `PacketSniffer` spawns a background daemon thread utilizing `scapy.sniff()`.
3. Captured packets are immediately handed off to `PacketAnalyzer` for protocol classification and metadata extraction.
4. Extracted packet details are pushed via a callback to the GUI for live rendering.
5. `logger_manager` persistently records every packet as a JSON payload for auditing.

### ARP Detection Workflow
1. All captured packets pass through the `ARPDetector` engine.
2. Normal ARP Requests are safely ignored (logged as INFO network events).
3. ARP Replies map an IP to a Source MAC in memory.
4. If a known IP suddenly maps to a *different* MAC address, the detector flags an anomaly.
5. The system elevates the threat level, pushes a `WARNING` severity alert to the SOC dashboard, and archives the incident to `arp_alerts.txt`.

## Project Structure
```text
Advanced_Packet_Sniffer_ARP_Detector/
├── assets/                  # UI assets and screenshots
├── gui/                     # Graphical interface modules
│   └── dashboard.py
├── logs/                    # Persistent application logs
├── reports/                 # Exported CSV forensics reports
├── test_data/               # Mock data for testing and validation
├── arp_detector.py          # Threat detection logic
├── logger_manager.py        # File I/O for logging
├── main.py                  # Entry point
├── packet_analyzer.py       # Deep packet inspection
├── packet_sniffer.py        # Network sniffing engine
├── report_generator.py      # Forensics export utilities
├── test_parsing.py          # Debug script for protocol validation
├── requirements.txt         # Python dependencies
├── .gitignore               # Ignored files (caches, logs, envs)
├── LICENSE                  # Licensing information
└── README.md                # Project documentation
```

## Future Improvements
- **Integration with SIEM Solutions**: Forwarding alerts via Syslog or Webhooks to external SIEM platforms (e.g., Splunk, ELK).
- **Expanded Protocol Support**: Layer 7 application protocol detection (HTTP/HTTPS, DNS).
- **Machine Learning Anomaly Detection**: Implementing baseline behavioral analysis for zero-day threat identification.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

*Disclaimer: This software is provided for educational and authorized professional network diagnostic purposes only. Ensure explicit authorization exists prior to monitoring network traffic.*

