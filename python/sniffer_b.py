from scapy.all import *

def print_pkt(pkt):
    pkt.show()

interfaces = ['enp0s3', 'lo']
pkt = sniff(iface=interfaces, filter='icmp', prn=print_pkt)