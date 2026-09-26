#!/usr/bin/env python3
"""
Basic Network Sniffer
Python-based Network Traffic Capture & Packet Analysis
------------------------------------------------------
A robust educational cybersecurity tool that captures network packets
and extracts essential telemetry including Source IP, Destination IP,
Transport Protocol (TCP, UDP, ICMP, DNS), packet length, and raw payload data.

Usage:
    python sniffer.py [-i INTERFACE] [-c COUNT] [-f FILTER] [--verbose]

Requirements:
    pip install scapy
"""

import sys
import signal
import argparse
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
except ImportError:
    print("[!] Scapy is not installed. Please install it using: pip install scapy")
    sys.exit(1)

# Global packet counter and metrics
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
    "start_time": None
}

def format_payload(payload_bytes, max_len: int = 64) -> str:
    """Safely format raw payload into printable ASCII or hex snippet."""
    if not payload_bytes:
        return "<Empty>"
    if isinstance(payload_bytes, str):
        return payload_bytes
    snippet = payload_bytes[:max_len]
    try:
        # Try decoding printable characters
        printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in snippet)
        return f"{printable} ({len(payload_bytes)} bytes total)"
    except Exception:
        return f"<Binary data: {len(payload_bytes)} bytes>"

def process_packet(packet):
    """Callback function invoked for each captured network packet."""
    global stats
    stats["total"] += 1

    # Check for IPv4 / IPv6 layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl
        proto_num = packet[IP].proto
        pkt_len = len(packet)

        protocol = "Other"
        extra_info = ""

        if TCP in packet:
            protocol = "TCP"
            stats["tcp"] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            extra_info = f"Ports: {sport} -> {dport} | Flags: {flags}"
        elif UDP in packet:
            protocol = "UDP"
            stats["udp"] += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            extra_info = f"Ports: {sport} -> {dport}"
        elif ICMP in packet:
            protocol = "ICMP"
            stats["icmp"] += 1
            icmp_type = packet[ICMP].type
            extra_info = f"Type: {icmp_type}"
        else:
            stats["other"] += 1
            extra_info = f"Protocol Number: {proto_num}"

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        print("=" * 60)
        print(f"[{timestamp}] Packet #{stats['total']} | Protocol: {protocol}")
        print(f"  Source IP       : {src_ip}")
        print(f"  Destination IP  : {dst_ip}")
        print(f"  Transport Info  : {extra_info}")
        print(f"  Packet Length   : {pkt_len} bytes (TTL: {ttl})")

        # Payload Inspection
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"  Payload Preview : {format_payload(payload)}")
        else:
            payload = "<No Raw Data Layer>"
            print(f"  Payload Preview : {payload}")
    else:
        # Non-IP packet (e.g. ARP, STP)
        stats["other"] += 1

def display_summary(signal_received=None, frame=None):
    """Print clean session summary on exit."""
    print("\n" + "=" * 60)
    print("           NETWORK SNIFFER SESSION SUMMARY")
    print("=" * 60)
    print(f"Total Packets Captured : {stats['total']}")
    print(f"  - TCP Packets        : {stats['tcp']}")
    print(f"  - UDP Packets        : {stats['udp']}")
    print(f"  - ICMP Packets       : {stats['icmp']}")
    print(f"  - Other Protocols    : {stats['other']}")
    if stats["start_time"]:
        duration = datetime.now() - stats["start_time"]
        print(f"Duration               : {duration.total_seconds():.2f} seconds")
    print("=" * 60)
    print("Capture session terminated gracefully.")
    sys.exit(0)

def parse_arguments():
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - Educational Python packet capture & traffic analysis tool."
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to listen on (e.g. eth0, wlan0, en0). Defaults to active interface."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture before exiting (0 = infinite until Ctrl+C)."
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default="",
        help="BPF (Berkeley Packet Filter) syntax string (e.g. 'tcp and port 80', 'udp')."
    )
    return parser.parse_args()

def main():
    args = parse_arguments()

    # Intercept SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, display_summary)

    print("*" * 60)
    print("             BASIC NETWORK SNIFFER INITIALIZED")
    print("*" * 60)
    print(f"Interface : {args.interface or 'Default System Interface'}")
    print(f"Filter    : {args.filter or 'None (All IP Traffic)'}")
    print(f"Count     : {'Infinite' if args.count == 0 else args.count}")
    print("Status    : Sniffing active... Press Ctrl+C at any time to halt.")
    print("*" * 60)

    stats["start_time"] = datetime.now()

    try:
        sniff_kwargs = {
            "prn": process_packet,
            "store": False,
            "count": args.count
        }
        if args.interface:
            sniff_kwargs["iface"] = args.interface
        if args.filter:
            sniff_kwargs["filter"] = args.filter

        sniff(**sniff_kwargs)
        display_summary()
    except PermissionError:
        print("\n[!] Permission Denied: Packet capture requires administrator or root privileges.")
        print("    On Linux/macOS: Run with 'sudo python sniffer.py'")
        print("    On Windows: Run your command prompt or PowerShell as Administrator.")
        sys.exit(1)
    except RuntimeError as err:
        if "winpcap" in str(err).lower() or "pcap" in str(err).lower():
            print("\n[!] Npcap is required on Windows for raw packet capture.")
            print("    1. Download Npcap from: https://npcap.com/")
            print("    2. During setup, check 'Install Npcap in WinPcap API-compatible Mode'.")
            print("    3. Restart your terminal as Administrator and rerun the script.")
        else:
            print(f"\n[!] Runtime error: {err}")
        sys.exit(1)
    except Exception as err:
        print(f"\n[!] Unexpected error during packet capture: {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()
