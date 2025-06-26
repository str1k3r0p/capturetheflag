# challenges/generate_net2.py
# Requires scapy: pip install scapy
from scapy.all import *

# This script generates 'conversation.pcapng' for the "Hidden Conversation" challenge.
packets = []
flag_parts = ["flag{t3l", "n3t_cha", "tt3r_b0x}"]

# --- Simulate a Telnet session with the flag split across packets ---
# The user must follow the TCP stream to reassemble the flag.
packets.append(IP(dst="10.0.0.5", src="10.0.0.4")/TCP(dport=23, sport=2048, flags='S'))
packets.append(IP(dst="10.0.0.4", src="10.0.0.5")/TCP(dport=2048, sport=23, flags='SA'))
packets.append(IP(dst="10.0.0.5", src="10.0.0.4")/TCP(dport=23, sport=2048, flags='A'))

# Some noise to make it less obvious
packets.append(IP(dst="10.0.0.5", src="10.0.0.4")/TCP(dport=23, sport=2048)/"Login: user\r\n")
packets.append(IP(dst="10.0.0.4", src="10.0.0.5")/TCP(dport=2048, sport=23)/"Password: \r\n")
packets.append(IP(dst="10.0.0.5", src="10.0.0.4")/TCP(dport=23, sport=2048)/"********\r\n")

# Interspersed flag parts
packets.append(IP(dst="10.0.0.4", src="10.0.0.5")/TCP(dport=2048, sport=23)/"By the way, the first part is: " + flag_parts[0] + "\r\n")
packets.append(IP(dst="10.0.0.5", src="10.0.0.4")/TCP(dport=23, sport=2048)/"Interesting...\r\n")
packets.append(IP(dst="10.0.0.4", src="10.0.0.5")/TCP(dport=2048, sport=23)/"The second is: " + flag_parts[1] + "\r\n")
packets.append(IP(dst="10.0.0.4", src="10.0.0.5")/TCP(dport=2048, sport=23)/"And the last part is: " + flag_parts[2] + "\r\n")

# --- Save to file ---
wrpcap("../static/conversation.pcapng", packets)
print("Generated '../static/conversation.pcapng' successfully.")

