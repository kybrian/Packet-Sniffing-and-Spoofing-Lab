# from scapy.all import *

# ip = IP()
# ip.dst='128.230.0.0/16'
# send(ip,4)

from scapy.all import *

ip = IP()
ip.dst = '128.230.0.0/16'
# Creating an ICMP packet for demonstration, change it according to your needs
icmp_pkt = ICMP()
send(ip/icmp_pkt)
