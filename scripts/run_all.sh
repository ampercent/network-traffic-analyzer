#!/bin/bash

echo "[*] Starting live capture..."
sudo python3 live_capture.py --iface wlp4s0

echo "[*] Analyzing captured packets and generating report..."
python3 analyze.py

echo ""
echo "[✔] Open the report at:"
report_path="../reports/report.html"
abs_path=$(realpath "$report_path")
echo -e "\033[1;34mfile://$abs_path\033[0m"
