# 🕵️‍♂️ Network Traffic Analyzer

A simple Python-based network traffic analyzer that captures packets, visualizes protocol usage, and generates an HTML report with graphs and insights.

---

## 🚀 Features

- Live packet capture from any network interface using Scapy
- Supports `.pcap` file analysis
- Protocol breakdown (ARP, IPv4, IPv6, TCP, ICMP)
- Graphs:
  - Protocol bar and pie charts
  - Communication heatmaps
  - Top talkers (source-destination pairs)
  - Packet timeline
- Auto-generated static HTML report
- Clickable terminal link to view report in browser

---

## 🛠️ Requirements

- Python 3.10+
- Linux-based OS (tested on Linux Mint)
- Root/sudo access for packet capture
- Dependencies (install in a virtualenv):

```bash
sudo apt install python3-venv
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
