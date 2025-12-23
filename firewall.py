from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from rules import FIREWALL_RULES
from logger import log_event
import socket

# 1️⃣ Detect local IP automatically
local_ip = socket.gethostbyname(socket.gethostname())
print("Local IP detected:", local_ip)


# 2️⃣ Function to determine packet direction
def get_direction(packet):
    if packet[IP].dst == local_ip:
        return "in"
    else:
        return "out"


# 3️⃣ Main firewall function
def advanced_firewall(packet):
    if IP not in packet:
        log_event("ALLOW", "Non-IP packet", packet)
        return

    direction = get_direction(packet)
    src_ip, dst_ip = packet[IP].src, packet[IP].dst

    # Windows safe proto handling
    proto = getattr(packet[IP], "proto_name", str(packet[IP].proto)).upper()
    if proto.isdigit():
        proto = f"PROTO_{proto}"  # friendly logging name

    # 3a️⃣ IP Block
    for rule in FIREWALL_RULES["blocked_ips"]:
        if rule["ip"] in [src_ip, dst_ip] and rule["direction"] in [direction, "any"]:
            log_event("BLOCK", f"IP blocked: {src_ip}/{dst_ip}", packet)
            # send_icmp_unreach(packet)  # Commented for beginner-safe
            return

    # 3b️⃣ Protocol Block
    for rule in FIREWALL_RULES["blocked_protocols"]:
        if rule["protocol"] == proto and rule["direction"] in [direction, "any"]:
            log_event("BLOCK", f"Protocol blocked: {proto}", packet)
            return

    # 3c️⃣ TCP Port Block
    if TCP in packet:
        dport = packet[TCP].dport
        for rule in FIREWALL_RULES["blocked_ports"]:
            if rule.get("protocol") == "TCP" and rule.get("direction") in [direction, "any"]:
                if "port" in rule and rule["port"] == dport:
                    log_event("BLOCK", f"TCP port {dport} blocked", packet)
                    return
                if "start" in rule and "end" in rule and rule["start"] <= dport <= rule["end"]:
                    log_event("BLOCK", f"TCP port range {rule['start']}-{rule['end']} blocked", packet)
                    return

    # 3d️⃣ UDP Port Block
    if UDP in packet:
        dport = packet[UDP].dport
        for rule in FIREWALL_RULES["blocked_ports"]:
            if rule.get("protocol") == "UDP" and rule.get("direction") in [direction, "any"]:
                if "port" in rule and rule["port"] == dport:
                    log_event("BLOCK", f"UDP port {dport} blocked", packet)
                    return
                if "start" in rule and "end" in rule and rule["start"] <= dport <= rule["end"]:
                    log_event("BLOCK", f"UDP port range {rule['start']}-{rule['end']} blocked", packet)
                    return

    # 3e️⃣ Allow
    log_event("ALLOW", f"{proto} {direction}", packet)
    print(f"ALLOWED {direction}: {src_ip} → {dst_ip}")


# 4️⃣ Sniff packets on default interface
iface = conf.iface  # auto-detect default interface

print("Advanced Personal Firewall Started...")
print("Use Ctrl+C to stop")
sniff(prn=advanced_firewall, filter="ip", store=0, iface=iface, promisc=True)
