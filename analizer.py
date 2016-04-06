import sys
import scapy.all as scapy
from collections import Counter
from math import log
scan_time =  int(sys.argv[1]) if len(sys.argv) > 1 else 20

packets = scapy.sniff(timeout=scan_time)

protocols = Counter([p.type for p in packets])
hosts = Counter([p.getlayer(scapy.ARP).hwsrc for p in packets if p.getlayer(scapy.ARP)])

def entropy(samples):
  total = sum(samples.values())
  return -sum([(float(samples.get(symbol)) / float(total) * log(float(samples.get(symbol)) / float(total))) for symbol in samples])

#Entropy S Ej1
entropy_s = entropy(protocols)

#Entropy s1 Ej2
entropy_s1 = entropy(hosts)

print("Entropy Protocols: {}\nEntropy Hosts: {}".format(entropy_s, entropy_s1))