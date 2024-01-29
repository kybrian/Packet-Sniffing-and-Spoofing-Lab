from scapy.all import *

def print_pkt(pkt):
    if IP in pkt and ICMP in pkt:
        print("ICMP Packet=====")
        print("\tSource: {}".format(pkt[IP].src))
        print("\tDestination: {}".format(pkt[IP].dst))

        if pkt[ICMP].type == 0:
            print("\tICMP type: {}".format("echo-reply"))
        elif pkt[ICMP].type == 8:
            print("\tICMP type: {}".format("echo-request"))

interfaces = ['enp0s3', 'lo']
pkt = sniff(iface=interfaces, filter='icmp', prn=print_pkt)