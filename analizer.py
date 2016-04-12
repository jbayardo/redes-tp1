import sys
import os
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
from collections import defaultdict
from math import log
from time import gmtime, strftime

capture_session = "captures/{}".format(strftime("%4Y%2m%2d_%2H%2M%2S", gmtime()))

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

protocols = defaultdict(int)
arp_mac_src = defaultdict(int)
arp_mac_dst = defaultdict(int)
arp_ip_src = defaultdict(int)
arp_ip_dst = defaultdict(int)

#conn_ip = defaultdict(defaultdict(int))
#conn_hw = defaultdict(defaultdict(int))

connections_ip = nx.Graph()
connections_hw = nx.Graph()

# protocols = Counter([p.type for p in packets])
# hosts = Counter([p.getlayer(scapy.ARP).hwsrc for p in packets if p.getlayer(scapy.ARP)])

for p in packets:
  if hasattr(p, "type"):
    protocols[p.type] += 1
  if p.getlayer(scapy.ARP):
    # ARP packet
    if p.op == 2: 
      # is-at packet (has hw destination)
      arp_mac_dst[p.hwdst] += 1
      #conn_hw[p.hwsrc][p.hwdst] += 1
      connections_hw.add_edge(p.hwsrc, p.hwdst)

    arp_ip_src[p.psrc] += 1
    arp_ip_dst[p.pdst] += 1
    arp_mac_src[p.hwsrc] += 1

    #conn_ip[p.psrc][p.pdst] += 1
    connections_ip.add_edge(p.psrc, p.pdst)


nx.draw(connections_hw, with_labels=True)
plt.savefig("{}/conn_mac.png".format(capture_session))
plt.show()
nx.draw(connections_ip, with_labels=True)
plt.savefig("{}/conn_ip.png".format(capture_session))
plt.show()

def entropy(samples):
  total = sum(samples.values())
  return -sum([(float(samples.get(symbol)) / float(total) * log(float(samples.get(symbol)) / float(total))) for symbol in samples])

# Entropy S Ej1
entropy_s = entropy(protocols)

# Entropy s1 Ej2
entropy_s1_mac_src = entropy(arp_mac_src)
entropy_s1_mac_dst = entropy(arp_mac_dst)
entropy_s1_ip_src = entropy(arp_ip_src)
entropy_s1_ip_dst = entropy(arp_ip_dst)

def plot(dic, name):
  try:
    x = np.arange(len(dic))
    fig, ax = plt.subplots()
    plt.bar(x ,protocols.values())
    plt.xticks(x + 0.5, dic.keys())
    plt.savefig("{}/{}.png".format(capture_session, name))
    plt.show()
  except AssertionError as e: 
    return

plot(protocols, "protocols")
plot(arp_mac_src, "arp_mac_src")
plot(arp_mac_dst, "arp_mac_dst")
plot(arp_ip_src, "arp_ip_src")
plot(arp_ip_dst, "arp_ip_dst")

results = "Entropy Protocols: {}\nEntropy arp source MAC: {}\nEntropy arp dest MAC: {}\nEntropy arp source IP: {}\nEntropy arp dest IP: {}".format(entropy_s, entropy_s1_mac_src, entropy_s1_mac_dst, entropy_s1_ip_src, entropy_s1_ip_dst)
print(results)

with open("{}/res.txt".format(capture_session),'w') as rf:
  rf.write(results)