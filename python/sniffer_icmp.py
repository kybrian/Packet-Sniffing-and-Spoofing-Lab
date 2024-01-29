from scapy.all import *

def print_pkt(pkt):
    if pkt[ICMP] is not None:
        if pkt[ICMP].type == 0 or pkt[ICMP].type == 8:
            print("ICMP Packet=====")
            print("\tSource: {}".format(pkt[IP].src))
            print("\tDestination: {}".format(pkt[IP].dst))

            if pkt[ICMP].type == 0:
                print("\tICMP type: echo-reply")
            if pkt[ICMP].type == 8:
                print("\tICMP type: echo-request")

interfaces = ['enp0s3', 'lo']
pkt = sniff(iface=interfaces, filter='icmp', prn=print_pkt)
