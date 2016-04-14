import sys
import os
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
from collections import defaultdict
from math import log10
from datetime import datetime

capture_session = 'captures/{:%Y%m%d_%H%M%S}'.format(datetime.now())


if len(sys.argv) > 1:
  if len(sys.argv[1]) > 3 and sys.argv[1][-4:] == ".cap":
    packets = scapy.rdpcap(sys.argv[1])
  else:
    scan_time = int(sys.argv[1])
    packets = scapy.sniff(timeout=scan_time)
else:
  scan_time = 20
  packets = scapy.sniff(timeout=scan_time)


os.makedirs("{}".format(capture_session))
scapy.wrpcap("{}/dump.cap".format(capture_session), packets)
f = open('{}/data.csv'.format(capture_session),'w')
f.write('protocol, hwsrc, hwdst, ipsrc, ipdst, whois\n')

protocols = defaultdict(int)
arp_mac_src = defaultdict(int)
arp_mac_dst = defaultdict(int)
arp_ip_src = defaultdict(int)
arp_ip_dst = defaultdict(int)

conn_ip = defaultdict(lambda: defaultdict(int))
conn_hw = defaultdict(lambda: defaultdict(int))

connections_ip = nx.Graph()
connections_hw = nx.Graph()

# protocols = Counter([p.type for p in packets])
# hosts = Counter([p.getlayer(scapy.ARP).hwsrc for p in packets if p.getlayer(scapy.ARP)])

for p in packets:
  # For csv
  prot = p.type if hasattr(p, 'type') else -1
  hwsrc = p.src
  hwdst = p.dst
  ipsrc = p.psrc if p.getlayer(scapy.ARP) else p.getlayer(scapy.IP).src if p.getlayer(scapy.IP) else ''
  ipdst = p.pdst if p.getlayer(scapy.ARP) else p.getlayer(scapy.IP).dst if p.getlayer(scapy.IP) else ''
  whois = p.op if p.getlayer(scapy.ARP) else ''
  f.write('{},{},{},{},{},{}\n'.format(prot,hwsrc,hwdst,ipsrc,ipdst,whois))

  # For entropy, increment 'symbol'
  if hasattr(p, "type"):
    protocols[p.type] += 1
  if p.getlayer(scapy.ARP):
    # ARP packet
    if p.op != 1: 
      # is-at packet (has hw destination)
      arp_mac_dst[p.hwdst] += 1

    arp_ip_src[p.psrc] += 1
    arp_ip_dst[p.pdst] += 1
    arp_mac_src[p.hwsrc] += 1

    conn_hw[p.hwsrc][p.hwdst] += 1
    connections_hw.add_edge(p.hwsrc, p.hwdst)

    conn_ip[p.psrc][p.pdst] += 1
    connections_ip.add_edge(p.psrc, p.pdst)

f.close()

# MAC transmissions plot
nx.draw(connections_hw, with_labels=True)
plt.savefig("{}/conn_mac.png".format(capture_session))
plt.show()
# IP transmissions plot
nx.draw(connections_ip, with_labels=True)
plt.savefig("{}/conn_ip.png".format(capture_session))
plt.show()

# Calculates entropy (receives dict with symbol as key and number of times it appeared as value)
def entropy(samples):
  total = sum(samples.values())
  return -sum([(float(samples.get(symbol)) / float(total) * log10(float(samples.get(symbol)) / float(total))) for symbol in samples])

# Entropy S Ej1: protocols as symbols
entropy_s = entropy(protocols) 

# Entropy S1 Ej2: addresses as symbols
entropy_s1_mac_src = entropy(arp_mac_src)
entropy_s1_mac_dst = entropy(arp_mac_dst)
entropy_s1_ip_src = entropy(arp_ip_src)
entropy_s1_ip_dst = entropy(arp_ip_dst)

results = "Entropy Protocols: {}\nEntropy arp source MAC: {}\nEntropy arp dest MAC: {}\nEntropy arp source IP: {}\nEntropy arp dest IP: {}".format(entropy_s, entropy_s1_mac_src, entropy_s1_mac_dst, entropy_s1_ip_src, entropy_s1_ip_dst)
print(results)

with open("{}/res.txt".format(capture_session),'w') as rf:
  rf.write(results)