# 🛡️ Advanced Packet Sniffer & ARP Threat Detection System

A professional-grade **Python-based Network Security Monitoring Platform** featuring real-time packet capture, protocol analysis, ARP spoofing detection, and a modern SOC dashboard built with **CustomTkinter**.

---

## ✨ Features

- 📡 Real-Time Network Packet Capture
- 🌐 Supports IPv4, IPv6, TCP, UDP, ICMP, and ARP
- 🛡️ Real-Time ARP Spoofing Detection
- 📊 Live SOC Dashboard
- 🚨 Dynamic Threat Level Indicator
- 🔍 Live Packet Search & Filtering
- 📈 Top Source & Destination IP Analysis
- 📁 CSV Report Export
- 📝 Alert Logging
- ⚡ Multi-threaded Packet Processing
- 💻 GUI & CLI Support

---

# 🏗️ Architecture

| Module | Description |
|---------|-------------|
| `main.py` | Application entry point |
| `packet_sniffer.py` | Real-time packet capture using Scapy |
| `packet_analyzer.py` | Protocol parsing and packet analysis |
| `arp_detector.py` | ARP spoofing detection engine |
| `logger_manager.py` | Logging and alert management |
| `report_generator.py` | CSV report generation |
| `gui/dashboard.py` | CustomTkinter SOC Dashboard |

---

# 📸 Dashboard Screenshots

## Dashboard

![Dashboard](dashboard.png)

---

## ARP Detection

![ARP Detection](arp_detection.png)

---

## TCP Packet Capture

![TCP Capture](tcp_capture.png)

---

## UDP Packet Capture

![UDP Capture](udp_capture.png)

---

## ICMP Packet Capture

![ICMP Capture](icmp_capture.png)

---

## IPv6 Packet Capture

![IPv6 Capture](ipv6_capture.png)

---

## Report Export

![Report Export](report_export.png)

---

## System Architecture

![Architecture](architecture.png)

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/Advanced_Packet_Sniffer_ARP_Detector.git
cd Advanced_Packet_Sniffer_ARP_Detector
```

## Create Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Run Application

```bash
python main.py
```

---

# 📋 Requirements

- Python 3.8+
- Scapy
- CustomTkinter

### Windows

- Npcap

### Linux

- libpcap

> Administrator/root privileges are required for packet sniffing.

---

# 🔄 How It Works

## Packet Capture Workflow

```text
Start Capture
      │
      ▼
Packet Sniffer (Scapy)
      │
      ▼
Packet Analyzer
      │
      ▼
GUI Dashboard
      │
      ▼
Logger
      │
      ▼
CSV Reports
```

---

## ARP Detection Workflow

```text
Capture ARP Packet
        │
        ▼
Check IP → MAC Mapping
        │
        ▼
Known Mapping?
   │            │
  Yes          No
   │            │
MAC Changed?    Store Mapping
   │
 ┌─┴─────────────┐
 │               │
No             Yes
 │               │
Log INFO    Raise Warning
                │
                ▼
Update Threat Level
                │
                ▼
SOC Dashboard Alert
```

---

# 📂 Project Structure

```text
Advanced_Packet_Sniffer_ARP_Detector/
│
├── assets/
│   ├── dashboard.png
│   ├── arp_detection.png
│   ├── tcp_capture.png
│   ├── udp_capture.png
│   ├── icmp_capture.png
│   ├── ipv6_capture.png
│   ├── report_export.png
│   └── architecture.png
│
├── gui/
│   ├── __init__.py
│   └── dashboard.py
│
├── logs/
│   └── .gitkeep
│
├── reports/
│   └── .gitkeep
│
├── test_data/
│
├── arp_detector.py
├── logger_manager.py
├── main.py
├── packet_analyzer.py
├── packet_sniffer.py
├── report_generator.py
├── test_parsing.py
│
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── .gitattributes
```

---

# 🚀 Future Improvements

- SIEM Integration (Splunk, ELK, Sentinel)
- HTTP / HTTPS / DNS Inspection
- Machine Learning-based Threat Detection
- PCAP Import & Analysis
- Email Alert Notifications
- Geo-IP Mapping
- Dark/Light Theme Support

---

# 📜 License

This project is licensed under the **MIT License**.

---

# ⚠️ Disclaimer

This project is intended **only for educational purposes and authorized security testing**.

Always obtain permission before monitoring or capturing network traffic.
