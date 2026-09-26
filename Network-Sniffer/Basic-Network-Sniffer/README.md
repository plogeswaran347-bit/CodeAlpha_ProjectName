# Basic Network Sniffer
**Python-based Network Traffic Capture & Packet Analysis**

An educational cybersecurity and networking tool that captures raw network packets across network interfaces and extracts essential header telemetry including Source IP, Destination IP, Transport Protocol (TCP, UDP, ICMP), packet length, and raw payload data.

---

## 1. Project Overview
A network sniffer is a diagnostic utility used to observe, monitor, and analyze live network traffic traversing an interface. This project utilizes Python 3 and the high-performance Scapy packet manipulation library to capture packets in real-time and inspect their low-level protocol structures.

Designed as an introductory foundation for computer networking fundamentals, cyber forensics, packet dissection, and defensive security monitoring.

---

## 2. Objectives
- **Capture Live Packets**: Tap into available network adapters (Ethernet/Wi-Fi/Loopback) using Python.
- **Understand Packet Architecture**: Deconstruct OSI Layer 3 (Network/IP) and Layer 4 (Transport) encapsulation.
- **Telemetry Extraction**: Extract Source and Destination IP addresses, ports, sequence numbers, and packet flags.
- **Protocol Identification**: Distinguish between connection-oriented (TCP), datagram-based (UDP), and diagnostic (ICMP) streams.
- **Payload Inspection**: Safely preview ASCII and hexadecimal application-layer payloads.
- **Security Awareness**: Learn defensive network telemetry and ethical packet inspection guidelines.

---

## 3. Technologies Used
| Technology | Purpose |
| :--- | :--- |
| **Python 3.8+** | Primary programming language and runtime |
| **Scapy** | Powerful packet crafting, sniffing, and protocol dissection library |
| **TCP/IP Protocol Suite** | Core networking model analyzed by the program |
| **CLI / Standard Streams** | Lightweight, responsive terminal interface for immediate inspection |
| **BPF (Berkeley Packet Filter)** | Kernel-level packet filtering engine |

---

## 4. Key Features
- **Real-Time Packet Capture**: Continuous observation and asynchronous processing.
- **IP Telemetry**: Clear extraction of Source and Destination IPv4/IPv6 addresses and TTL.
- **Transport Layer Detection**: Dynamic identification of TCP (with port flags), UDP, ICMP, and auxiliary protocols.
- **Packet Sizing**: Real-time byte length calculation per frame.
- **Payload Inspection**: Safe conversion of binary payloads to ASCII representations with length counters.
- **BPF Filtering**: Support for targeted packet capture (e.g. `tcp and port 80`).
- **Session Summary**: Clean metrics dashboard displayed automatically on exit (`Ctrl+C`).

---

## 5. Project Structure
```text
Basic-Network-Sniffer/
│
├── sniffer.py              # Main Python script for packet sniffing & analysis
├── README.md               # Complete project documentation & setup guide
├── requirements.txt        # Python dependency manifest
└── data/                   # Task & collaboration data snapshots
```

---

## 6. Installation & Prerequisites

### Step 1 — Verify Python 3
Ensure Python 3.8 or newer is installed on your workstation:
```bash
python --version
# or
python3 --version
```

### Step 2 — Install Dependencies
Install the Scapy library via `pip`:
```bash
pip install scapy
# If pip is mapped to python3:
python3 -m pip install scapy
```

*Note for Windows Users:*
Windows requires Npcap (or WinPcap) for raw network socket access:
1. Download and install **Npcap** from [https://npcap.com/](https://npcap.com/).
2. During installation, select the option *"Install Npcap in WinPcap API-compatible Mode"*.

---

## 7. How to Run

Because raw packet capture interfaces operate at the network kernel level, administrative or superuser privileges are required.

### On Linux & macOS
```bash
sudo python3 sniffer.py
```

### On Windows
Open **PowerShell** or **Command Prompt** as **Administrator**, navigate to the project directory, and execute:
```cmd
python sniffer.py
```

### Command-Line Arguments & Options
```bash
# Capture packets on a specific interface
python3 sniffer.py -i eth0

# Capture only 50 packets then stop
python3 sniffer.py -c 50

# Apply Berkeley Packet Filter (e.g., capture only HTTP traffic)
python3 sniffer.py -f "tcp and (port 80 or port 443)"

# Capture only DNS query/response packets
python3 sniffer.py -f "udp port 53"
```

---

## 8. Sample Implementation (`sniffer.py` Core Snippet)
```python
from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"
            
        print("\n--- Packet Captured ---")
        print("Source IP      :", source)
        print("Destination IP :", destination)
        print("Protocol       :", protocol)
        print("Packet Length  :", len(packet))
        
        if Raw in packet:
            print("Payload        :", packet[Raw].load)

print("Starting Network Sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
```

---

## 9. Example Output
```text
************************************************************
             BASIC NETWORK SNIFFER INITIALIZED
************************************************************
Interface : Default System Interface
Filter    : None (All IP Traffic)
Count     : Infinite
Status    : Sniffing active... Press Ctrl+C at any time to halt.
************************************************************
============================================================
[09:14:22.410] Packet #1 | Protocol: TCP
  Source IP       : 192.168.1.10
  Destination IP  : 142.250.183.14
  Transport Info  : Ports: 54120 -> 443 | Flags: PA
  Packet Length   : 74 bytes (TTL: 64)
  Payload Preview : .....GET / HTTP/1.1..Host: google.com (38 bytes total)
============================================================
[09:14:22.488] Packet #2 | Protocol: UDP
  Source IP       : 192.168.1.10
  Destination IP  : 8.8.8.8
  Transport Info  : Ports: 59312 -> 53
  Packet Length   : 90 bytes (TTL: 64)
  Payload Preview : .....ai.studio...... (42 bytes total)
```

---

## 10. Packet Information Explained
| Field | Meaning |
| :--- | :--- |
| **Source IP** | Logical network address of the sending device. |
| **Destination IP** | Logical network address of the target destination device. |
| **Protocol** | Layer 4 transport protocol header (TCP = 6, UDP = 17, ICMP = 1). |
| **Packet Length** | Overall size of the encapsulated frame in bytes. |
| **Payload** | Application data carried inside the transport segment (HTTP, DNS, etc.). |

---

## 11. Working Flow Architecture
```text
  ┌─────────────────────────────────┐
  │              Start              │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │   Select Network Interface      │
  │     (Promiscuous / Raw)         │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │     Capture Packets via         │
  │   Kernel Filter Engine (BPF)    │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │    Check for IPv4 / IPv6 Layer  │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │ Extract Source & Destination IP │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │ Identify Protocol (TCP/UDP/etc) │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │ Read Packet Length & Payload    │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │ Display Structured Telemetry    │
  └────────────────┬────────────────┘
                   ▼
  ┌─────────────────────────────────┐
  │  Continue capturing or Stop     │
  └─────────────────────────────────┘
```

---

## 12. Protocol Basics
- **IP (Internet Protocol)**: Provides logical addressing and hierarchical routing across heterogeneous networks.
- **TCP (Transmission Control Protocol)**: Reliable, connection-oriented, full-duplex stream protocol featuring sequence acknowledgments, flow control, and retransmissions.
- **UDP (User Datagram Protocol)**: Lightweight, connectionless datagram protocol prioritized for low-latency streaming and real-time gaming without delivery overhead.
- **ICMP (Internet Control Message Protocol)**: Diagnostic protocol used by network devices to send error messages (e.g., `Destination Unreachable`) and operational information (`ping` echo request/reply).

---

## 13. Security & Ethical Use Notice
> [!CAUTION]
> **Legal Notice**: Packet sniffing intercepts communications traversing network segments. Always operate this tool **strictly within networks and devices you own or have obtained explicit, documented authorization to test**. Unauthorized interception of private communications is illegal under computer misuse legislation (such as CFAA, GDPR, and equivalent regulations). Always use controlled virtual lab environments.

---

## 14. Learning Outcomes
- Real-world understanding of packet structure, frame encapsulation, and the OSI stack.
- Mastery of IP, TCP, and UDP transport behaviors.
- Hands-on Python network programming with the Scapy framework.
- Practical experience analyzing network traffic and debugging connectivity issues.
- Solid grounding for cybersecurity certifications and penetration testing curricula.

---

## 15. Future Enhancements
- [x] Protocol & Port-based BPF filtering (`-f` flag).
- [x] Packet counter and graceful termination (`Ctrl+C` summary).
- [ ] Export captured telemetry to JSON / CSV / PCAP format.
- [ ] Interactive Web GUI / Dashboard for live packet streaming.
- [ ] Anomaly detection for unusual port scans or SYN flood patterns.

---

## 16. Conclusion
The Basic Network Sniffer bridges the gap between abstract networking theory and practical hands-on cybersecurity engineering. By dissecting live packets and inspecting header metrics in real time, engineers and students gain deep intuition into how modern digital communications function.
