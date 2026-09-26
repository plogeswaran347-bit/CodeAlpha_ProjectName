#!/bin/bash
echo "=== Basic Network Sniffer Quickstart ==="
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo ""
echo "To run the sniffer with administrative privileges:"
echo "sudo ./venv/bin/python sniffer.py"
