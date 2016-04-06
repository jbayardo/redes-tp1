import sys
import scapy.all as scapy
from collections import Counter

scan_time =  int(sys.argv[1]) if len(sys.argv) > 1 else 20

packets = scapy.sniff(timeout=scan_time)

protocols = Counter([p.type for p in packets])
hosts = Counter([p.getlayer(scapy.ARP).hwsrc for p in packets if p.getlayer(scapy.ARP)])