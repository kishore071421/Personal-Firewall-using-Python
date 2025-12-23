# Advanced Personal Firewall (Python)

**Advanced Personal Firewall** is a lightweight, Python-based application that monitors and controls network traffic in real-time. It uses **Scapy** for packet sniffing and **Tkinter** for GUI-based visualization, providing users with the ability to block or allow traffic based on IP addresses, ports, and protocols.

---

## Features

- Real-time packet sniffing using **Scapy**
- Configurable rules to block/allow:
  - **IP addresses**
  - **TCP/UDP ports**
  - **Protocols** (e.g., ICMP)
- Real-time logging of allowed and blocked packets
- **GUI interface** with scrollable live log
- Threaded design to prevent GUI freezing during monitoring

---

## Project Structure

personal_firewall/
├── firewall.py # Main CLI firewall implementation
├── firewall_gui.py # GUI for live monitoring
├── logger.py # Logging module
├── rules.py # Configuration for firewall rules
└── README.md # Project documentation

yaml
Copy code

---

## Installation

1. Install **Python 3.x** if not already installed  
2. Install required packages:

```bash
pip install scapy
pip install tkinter  # Usually pre-installed with Python
Clone the repository:

bash
Copy code
git clone <repository-url>
cd personal_firewall
Usage
Command-Line Interface (CLI)
bash
Copy code
python firewall.py
Displays allowed and blocked packets in terminal

Logs are recorded in firewall.log

Graphical User Interface (GUI)
bash
Copy code
python firewall_gui.py
Opens a Tkinter window

Scrollable live log of allowed and blocked packets

Firewall operates in a separate thread to ensure GUI responsiveness

Rules Configuration
Rules can be modified in the rules.py file:

python
Copy code
FIREWALL_RULES = {
    "blocked_ips": [
        {"ip": "192.168.1.100", "reason": "Suspicious host", "direction": "any"}
    ],
    "blocked_ports": [
        {"port": 23, "protocol": "TCP", "direction": "any"}
    ],
    "blocked_protocols": [
        {"protocol": "ICMP", "direction": "any"}
    ],
    "default_policy": "deny",
}
direction can be "in", "out", or "any"

default_policy can be "allow" or "deny"

Logging
All events are logged in firewall.log using the following format:

pgsql
Copy code
timestamp LEVEL action reason src dst sport dport proto summary
Example:

pgsql
Copy code
2025-12-23 10:30:12 INFO action=BLOCK reason="IP blocked" src=192.168.1.100 dst=10.0.0.5 sport=* dport=* proto=* summary="IP Packet"
Screenshots
GUI Live Log:


CLI Output Example:

nginx
Copy code
ALLOWED out: 192.168.56.1 → 8.8.8.8
BLOCK IP: 192.168.1.100 → 10.0.0.5
How It Works
Detects local IP automatically

Sniffs incoming and outgoing packets using Scapy

Applies rules for:

Blocking specific IPs

Blocking TCP/UDP ports

Blocking protocols (e.g., ICMP)

Logs all events via logger.py

Displays live logs in Tkinter GUI

Future Enhancements
Implement stateful connection tracking

Add filtering based on packet payload content

Improve cross-platform support (Windows & Linux)

Enable dynamic GUI configuration to update rules in real-time

License
This project is licensed under the MIT License.
© 2025 [B. BHARATH KISHORE]
