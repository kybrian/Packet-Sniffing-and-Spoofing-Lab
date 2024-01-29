from scapy.all import *

inRoute = True
i = 1
while inRoute:
    a = IP(dst='216.58.210.36', ttl=i)
    response = sr1(a/ICMP(), timeout=7, verbose=0)

    if response is None:
        print("{} Requests timed out".format(i))
    elif response.type == 0:
        print("{} {}".format(i, response.src))
        inRoute = False
    else:
        print("{} {}".format(i, response.src))

    i += 1  # Increment i inside the loop
