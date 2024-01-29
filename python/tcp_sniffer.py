# from scapy.all import *

# def print_pkt(pkt):
#     if pkt[TCP] is not None:
#         print("TCP Packet=====")
#         print("\tSource: {}".format(pkt[IP].src))
#         print("\tDestination: {}".format(pkt[IP].dst))
#         print("\tSource Port: {}".format(pkt[TCP].sport))
#         print("\tDestination Port: {}".format(pkt[TCP].dport))

# interfaces = ['enp0s3', 'lo']
# pkt = sniff(iface=interfaces, filter='tcp port 22 and src host 10.0.2.3', prn=print_pkt)
# prn=print_pkt

from scapy.all import *

def print_pkt(pkt):
    if TCP in pkt:
        print("TCP Packet=====")
        print("\tSource: {}".format(pkt[IP].src))
        print("\tDestination: {}".format(pkt[IP].dst))
        print("\tSource Port: {}".format(pkt[TCP].sport))
        print("\tDestination Port: {}".format(pkt[TCP].dport))

interfaces = ['enp0s3', 'lo']
pkt = sniff(iface=interfaces, filter='tcp port 23 and src host 10.0.2.4', prn=print_pkt)
