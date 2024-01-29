from scapy.all import *

def print_pkt(pkt):
    if TCP in pkt:
        print("TCP Packet=====")
        print("\tSource: {}".format(pkt[IP].src))
        print("\tDestination: {}".format(pkt[IP].dst))
        print("\tTCP Source port: {}".format(pkt[TCP].sport))
        print("\tTCP Destination port: {}".format(pkt[TCP].dport))

interfaces = ['enp0s3', 'lo']  
pkt = sniff(iface=interfaces, filter='tcp port 23 and src host 10.0.2.4', prn=print_pkt)
