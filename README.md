# NetMonitor: Advanced CLI Packet Sniffer & PCAP Analyzer

NetMonitor is a terminal-based network monitoring tool built in Python using **Scapy**. It allows you to **capture live network traffic** with flexible filters or **analyze existing PCAP files**, providing detailed statistics and top talker insights in a professional and easy-to-read format.

## Features

- Capture live network traffic with protocol filtering: TCP, UDP, ICMP, HTTP, HTTPS.
- Analyze PCAP files with same format and statistics.
- Shows first 10 packets live with source/destination IPs and ports.
- Protocol detection: HTTP, HTTPS, QUIC/HTTPS, DNS, ICMP.
- Capture modes: fixed duration or Ctrl+C to stop manually.
- Option to save packets to PCAP files.

## Installation

```bash
git clone https://github.com/your-username/NetMonitor.git
cd NetMonitor
pip install -r requirements.txt
python PacketSniffer.py
