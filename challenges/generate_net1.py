# challenges/generate_net1.py
# Requires scapy: pip install scapy
from scapy.all import *

# This script generates 'insider.pcapng' for the "Plain Sight" challenge.
packets = []

# --- Simulate an FTP session ---
# Packets are crafted to look like a real FTP login.
packets.append(IP(dst="10.0.0.2", src="10.0.0.1")/TCP(dport=21, sport=1025)/"220 FTP Server ready.\r\n")
packets.append(IP(dst="10.0.0.1", src="10.0.0.2")/TCP(dport=1025, sport=21)/"USER anonymous\r\n")
packets.append(IP(dst="10.0.0.2", src="10.0.0.1")/TCP(dport=21, sport=1025)/"331 Please specify the password.\r\n")

# The password is the flag!
packets.append(IP(dst="10.0.0.1", src="10.0.0.2")/TCP(dport=1025, sport=21)/"PASS flag{ftp_!s_s0_!ns3cur3}\r\n")

packets.append(IP(dst="10.0.0.2", src="10.0.0.1")/TCP(dport=21, sport=1025)/"230 Login successful.\r\n")
packets.append(IP(dst="10.0.0.1", src="10.0.0.2")/TCP(dport=1025, sport=21)/"QUIT\r\n")
packets.append(IP(dst="10.0.0.2", src="10.0.0.1")/TCP(dport=21, sport=1025)/"221 Goodbye.\r\n")

# --- Save to file ---
# The file will be saved in the 'static' directory to be downloadable.
wrpcap("../static/insider.pcapng", packets)

print("Generated '../static/insider.pcapng' successfully.")

