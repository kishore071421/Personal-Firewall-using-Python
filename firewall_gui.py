import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from threading import Thread
from scapy.all import sniff, IP, TCP, UDP, conf
from rules import FIREWALL_RULES
from logger import log_event
import socket

# Detect local IP automatically
local_ip = socket.gethostbyname(socket.gethostname())

# --- GUI Setup ---
root = tk.Tk()
root.title("Personal Firewall Monitor")
root.geometry("700x400")

# Scrollable text for live logs
text_area = ScrolledText(root, state='disabled', wrap='word')
text_area.pack(expand=True, fill='both')

def gui_log(message):
    """Append message to GUI log window"""
    text_area.config(state='normal')
    text_area.insert(tk.END, message + "\n")
    text_area.yview(tk.END)
    text_area.config(state='disabled')

# --- Packet Direction ---
def get_direction(packet):
    return "in" if packet[IP].dst == local_ip else "out"

# --- Firewall Logic ---
def advanced_firewall(packet):
    if IP not in packet:
        log_event("ALLOW", "Non-IP packet", packet)
        gui_log("ALLOW Non-IP packet")
        return

    direction = get_direction(packet)
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    proto = getattr(packet[IP], "proto_name", str(packet[IP].proto)).upper()
    if proto.isdigit():
        proto = f"PROTO_{proto}"

    blocked = False

    # IP Block
    for rule in FIREWALL_RULES["blocked_ips"]:
        if rule["ip"] in [src_ip, dst_ip] and rule["direction"] in [direction, "any"]:
            log_event("BLOCK", f"IP blocked: {src_ip}/{dst_ip}", packet)
            gui_log(f"BLOCK IP: {src_ip} → {dst_ip}")
            blocked = True
            break

    # Protocol Block
    if not blocked:
        for rule in FIREWALL_RULES["blocked_protocols"]:
            if rule["protocol"] == proto and rule["direction"] in [direction, "any"]:
                log_event("BLOCK", f"Protocol blocked: {proto}", packet)
                gui_log(f"BLOCK Protocol {proto}: {src_ip} → {dst_ip}")
                blocked = True
                break

    # TCP/UDP Port Block
    if not blocked:
        if TCP in packet:
            dport = packet[TCP].dport
            for rule in FIREWALL_RULES["blocked_ports"]:
                if rule.get("protocol") == "TCP" and rule.get("direction") in [direction, "any"]:
                    if ("port" in rule and rule["port"] == dport) or \
                       ("start" in rule and "end" in rule and rule["start"] <= dport <= rule["end"]):
                        log_event("BLOCK", f"TCP port {dport} blocked", packet)
                        gui_log(f"BLOCK TCP port {dport}: {src_ip} → {dst_ip}")
                        blocked = True
                        break

        if UDP in packet:
            dport = packet[UDP].dport
            for rule in FIREWALL_RULES["blocked_ports"]:
                if rule.get("protocol") == "UDP" and rule.get("direction") in [direction, "any"]:
                    if ("port" in rule and rule["port"] == dport) or \
                       ("start" in rule and "end" in rule and rule["start"] <= dport <= rule["end"]):
                        log_event("BLOCK", f"UDP port {dport} blocked", packet)
                        gui_log(f"BLOCK UDP port {dport}: {src_ip} → {dst_ip}")
                        blocked = True
                        break

    if not blocked:
        log_event("ALLOW", f"{proto} {direction}", packet)
        gui_log(f"ALLOW {direction}: {src_ip} → {dst_ip}")

# --- Run sniff in separate thread ---
def start_sniff():
    iface = conf.iface  # auto-detect default interface
    sniff(prn=advanced_firewall, filter="ip", store=0, iface=iface, promisc=True)

thread = Thread(target=start_sniff, daemon=True)
thread.start()

# --- Start GUI Loop ---
root.mainloop()
