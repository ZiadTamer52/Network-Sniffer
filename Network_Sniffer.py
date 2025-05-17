'''
# Network Sniffer #
## Aouther: Ziad Tamer #
## Date: 2025-5-15 ##
## Description: This script captures and analyzes network packets using Scapy. It identifies the source and destination IP addresses, the protocol used (TCP/UDP), and the source and destination ports. The script runs indefinitely until interrupted by the user. ##
'''

from scapy.all import sniff, IP, TCP, UDP

print("Network Sniffer")
print("White Rabbit")
def packet_callback(packet):
    if IP in packet :
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"[+] IP Packet: {ip_src} -> {ip_dst} || Protocol: {proto}")

        if TCP in packet:
            print(f"    TCP Packet | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")

        elif UDP in packet:
            print(f"    UDP Packet | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")

print("[*] Starting sniffer...")
sniff(prn=packet_callback, store=False)
