from scapy.all import *

def send_packet(pkt):
    if pkt[2].type == 8:
        src = pkt[1].src
        dst = pkt[1].dst 
        seq = pkt[2].seq
        id = pkt[2].id
        load = pkt[3].load
        print("Flip: src {} dst {} type 8 REQUEST".format(src, dst))
        print("Flip: src {} dst {} type 8 REPLY\n".format(src, dst))
        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        send(reply, verbose=0)

interfaces = ['enp0s3', 'lo']
pkt = sniff(iface=interfaces, filter='icmp', prn=send_packet)
