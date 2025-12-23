FIREWALL_RULES = {
    "blocked_ips": [
        {"ip": "192.168.1.100", "reason": "Suspicious host", "direction": "any"},
        {"ip": "10.0.0.5", "reason": "Bruteforce", "direction": "in"},
    ],

    "blocked_ports": [
        {"port": 23, "protocol": "TCP", "direction": "any", "reason": "Telnet"},
        {"port": 445, "protocol": "TCP", "direction": "in", "reason": "SMB"},
        {"start": 1024, "end": 2000, "protocol": "UDP", "direction": "out",
         "reason": "High-risk ephemeral range"},
    ],

    "blocked_protocols": [
        {"protocol": "ICMP", "direction": "any", "reason": "Ping flood"},
    ],

    "default_policy": "deny",
}
