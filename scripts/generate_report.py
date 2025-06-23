import os
from datetime import datetime

report_dir = os.path.abspath("../reports")
timestamp = datetime.now().strftime("%d %B %Y, %I:%M:%S %p")
html_file = os.path.join(report_dir, "report.html")

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Traffic Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f7f7f7;
            color: #222;
        }}
        h1 {{
            text-align: center;
            margin-bottom: 5px;
        }}
        p.timestamp {{
            text-align: center;
            font-size: 0.9em;
            color: #555;
            margin-bottom: 40px;
        }}
        h2 {{
            border-bottom: 2px solid #ccc;
            padding-bottom: 4px;
            margin-top: 40px;
        }}
        .chart {{
            text-align: center;
            margin: 20px 0;
        }}
        img {{
            max-width: 90%;
            height: auto;
            border: 1px solid #ccc;
            box-shadow: 2px 2px 8px rgba(0,0,0,0.1);
        }}
        footer {{
            margin-top: 50px;
            text-align: center;
            font-size: 0.9em;
            color: #666;
        }}
    </style>
</head>
<body>
    <h1>Network Traffic Analysis Report</h1>
    <p class="timestamp">Generated: {timestamp}</p>

    <h2>Protocol Breakdown</h2>
    <div class="chart">
        <img src="../captures/protocol_chart.png" alt="Protocol Chart">
    </div>

    <h2>Protocol Distribution (Pie Chart)</h2>
    <div class="chart">
        <img src="../captures/protocol_pie_chart.png" alt="Protocol Pie Chart">
    </div>

    <h2>Top Communication Pairs</h2>
    <div class="chart">
        <img src="../captures/top_comms.png" alt="Top Communication Pairs">
    </div>

    <h2>Packet Timeline</h2>
    <div class="chart">
        <img src="../captures/packet_timeline.png" alt="Packet Timeline">
    </div>

    <h2>IP Communication Heatmap</h2>
    <div class="chart">
        <img src="../captures/comm_heatmap.png" alt="Communication Heatmap">
    </div>

    <footer>
        © {datetime.now().year} Network Analyzer - Report generated using Python, Scapy, Matplotlib
    </footer>
</body>
</html>
"""

with open(html_file, "w") as f:
    f.write(html_content)

print(f"[+] HTML report saved to: {html_file}")
print(f"[✓] Open it in your browser: file://{html_file}")
