import os
import sys
import json
import subprocess
from scapy.all import rdpcap, ARP, ICMP, IP, IPv6, TCP, wrpcap
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Load packets
pcap_path = "../captures/sample.pcap"
packets = rdpcap(pcap_path)

print(f"[+] Total packets: {len(packets)}\n")

# Protocol counters
protocol_counter = Counter()
arp_packets = []
icmp_packets = []
source_ips = set()
dest_ips = set()
comms = Counter()
timestamps = []

for pkt in packets:
    if ARP in pkt:
        protocol_counter['ARP'] += 1
        arp_packets.append(pkt)
    if IP in pkt:
        protocol_counter['IPv4'] += 1
        source_ips.add(pkt[IP].src)
        dest_ips.add(pkt[IP].dst)
        comms[(pkt[IP].src, pkt[IP].dst)] += 1
        timestamps.append(float(pkt.time))
    if IPv6 in pkt:
        protocol_counter['IPv6'] += 1
        source_ips.add(pkt[IPv6].src)
        dest_ips.add(pkt[IPv6].dst)
        comms[(pkt[IPv6].src, pkt[IPv6].dst)] += 1
        timestamps.append(float(pkt.time))
    if ICMP in pkt:
        protocol_counter['ICMP'] += 1
        icmp_packets.append(pkt)
    if TCP in pkt:
        protocol_counter['TCP'] += 1

# Save filtered packets
wrpcap("../captures/arp_only.pcap", arp_packets)
wrpcap("../captures/icmp_only.pcap", icmp_packets)
print("\n[+] Saved: arp_only.pcap, icmp_only.pcap")

# Visualizations
report_dir = os.path.abspath("../reports")
os.makedirs(report_dir, exist_ok=True)

# Bar chart
plt.figure(figsize=(8, 5))
plt.bar(protocol_counter.keys(), protocol_counter.values(), color='skyblue')
plt.title("Protocol Breakdown")
plt.xlabel("Protocol")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("../captures/protocol_chart.png")

# Pie chart
plt.figure(figsize=(6, 6))
plt.pie(protocol_counter.values(), labels=protocol_counter.keys(), autopct='%1.1f%%', colors=plt.cm.Paired.colors)
plt.title("Protocol Distribution")
plt.tight_layout()
plt.savefig("../captures/protocol_pie_chart.png")

# Top communication pairs
top_src_dst = comms.most_common(10)
srcs = [f"{src}\n→\n{dst}" for (src, dst), _ in top_src_dst]
counts = [count for _, count in top_src_dst]
plt.figure(figsize=(10, 6))
plt.barh(srcs, counts, color='purple')
plt.xlabel("Packet Count")
plt.title("Top 10 Communications")
plt.tight_layout()
plt.savefig("../captures/top_comms.png")

# Packet timeline
if timestamps:
    times = pd.to_datetime(timestamps, unit='s')
    time_series = pd.Series(1, index=times).resample("1S").sum().fillna(0)
    time_series.plot(figsize=(12, 4), title="Packet Timeline", ylabel="Packets/sec")
    plt.tight_layout()
    plt.savefig("../captures/packet_timeline.png")

# Heatmap
comm_matrix = defaultdict(lambda: defaultdict(int))
for (src, dst), count in comms.items():
    comm_matrix[src][dst] = count
comm_df = pd.DataFrame(comm_matrix).fillna(0)
plt.figure(figsize=(12, 8))
sns.heatmap(comm_df, annot=True, fmt=".0f", cmap="YlGnBu", cbar=True)
plt.title("Communication Heatmap")
plt.tight_layout()
plt.savefig("../captures/comm_heatmap.png")

print("[+] Saved graph: protocol_chart.png")
print("[+] Saved graph: protocol_pie_chart.png")
print("[+] Saved graph: top_comms.png")
print("[+] Saved graph: packet_timeline.png")
print("[+] Saved graph: comm_heatmap.png")

# Generate the static HTML report
print("\n[+] Generating final HTML report...")
subprocess.run(["python3", os.path.abspath("generate_report.py")], check=True)

# Show clickable link
html_path = os.path.abspath("../reports/report.html")
print(f"\n📄 Open your report: file://{html_path}")
