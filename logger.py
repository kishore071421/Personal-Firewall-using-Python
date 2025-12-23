import logging

# 1️⃣ Logger setup
logging.basicConfig(
    filename="firewall.log",          # Log file name
    level=logging.INFO,               # Capture INFO level logs
    format="%(asctime)s %(levelname)s %(message)s"  # Log format
)

# 2️⃣ Define logger object
logger = logging.getLogger("PersonalFirewall")


# 3️⃣ Convert Scapy packet to dictionary for logging
def packet_to_dict(packet):
    info = {
        "summary": packet.summary()
    }
    if hasattr(packet, "src"):
        info["src"] = packet.src
    if hasattr(packet, "dst"):
        info["dst"] = packet.dst
    if hasattr(packet, "sport"):
        info["sport"] = getattr(packet, "sport", None)
    if hasattr(packet, "dport"):
        info["dport"] = getattr(packet, "dport", None)
    if hasattr(packet, "proto"):
        info["proto"] = getattr(packet, "proto", None)
    return info


# 4️⃣ Log event function
def log_event(action, reason, packet, level=logging.INFO):
    """
    action: BLOCK / ALLOW / DROP
    reason: text reason (rule name, etc.)
    packet: Scapy packet
    """
    pkt = packet_to_dict(packet)
    msg = (
        f"action={action} "
        f"reason=\"{reason}\" "
        f"src={pkt.get('src')} "
        f"dst={pkt.get('dst')} "
        f"sport={pkt.get('sport')} "
        f"dport={pkt.get('dport')} "
        f"proto={pkt.get('proto')} "
        f"summary=\"{pkt.get('summary')}\""
    )
    logger.log(level, msg)
