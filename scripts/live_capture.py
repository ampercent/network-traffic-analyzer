import os
import json
import argparse
from collections import Counter
from scapy.all import sniff, ARP, IP, IPv6, ICMP, TCP, wrpcap
import webbrowser

# --- Argument Parser ---
parser = argparse.ArgumentParser(description="Live packet capture with protocol breakdown")
parser.add_argument("--iface", default=None, help="Network interface to sniff on (e.g. wlan0, eth0)")
parser.add_argument("--count", type=int, default=100, help="Number of packets to capture")
parser.add_argument("--timeout", type=int, default=30, help="Max time to wait (in seconds)")
args = parser.parse_args()

# --- Permission check ---
if os.geteuid() != 0:
    print("❌ ERROR: Run this script with sudo.")
    exit(1)

print(f"[*] Capturing on interface: {args.iface or 'default'}")
print(f"[*] Packet count: {args.count} | Timeout: {args.timeout}s")
print("[*] Press CTRL+C to stop early.")

# --- Capture Packets ---
packets = sniff(count=args.count, timeout=args.timeout, iface=args.iface)

print(f"[+] Captured {len(packets)} packets")

# --- Analyze Protocols ---
protocol_counter = Counter()
arp_packets = []
icmp_packets = []

for pkt in packets:
    if ARP in pkt:
        protocol_counter['ARP'] += 1
        arp_packets.append(pkt)
    if IP in pkt:
        protocol_counter['IPv4'] += 1
    if IPv6 in pkt:
        protocol_counter['IPv6'] += 1
    if ICMP in pkt:
        protocol_counter['ICMP'] += 1
        icmp_packets.append(pkt)
    if TCP in pkt:
        protocol_counter['TCP'] += 1

# --- Save filtered captures ---
capture_dir = os.path.abspath("../captures")
os.makedirs(capture_dir, exist_ok=True)
wrpcap(os.path.join(capture_dir, "live_capture.pcap"), packets)
wrpcap(os.path.join(capture_dir, "arp_only.pcap"), arp_packets)
wrpcap(os.path.join(capture_dir, "icmp_only.pcap"), icmp_packets)

print("[+] Saved: live_capture.pcap, arp_only.pcap, icmp_only.pcap")

# --- Save protocol data for dashboard ---
report_dir = os.path.abspath("../reports")
os.makedirs(report_dir, exist_ok=True)
with open(os.path.join(report_dir, "protocol_data.json"), "w") as f:
    json.dump(dict(protocol_counter), f, indent=4)

print("[+] Saved: protocol_data.json")

# --- Open HTML dashboard (if available) ---
html_report_path = os.path.join(report_dir, "dashboard.html")
if os.path.exists(html_report_path):
    print(f"[→] Opening dashboard: {html_report_path}")
    webbrowser.open(f"file://{html_report_path}")
else:
    print("⚠️  dashboard.html not found. Run analyze.py or create it first.")
