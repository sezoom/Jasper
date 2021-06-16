#! /usr/bin/env python3
try:
    from scapy.all import *
except:
    print("pip3 install --pre scapy[complete]")

import sys


conf.verb=0

def advanceMode():
    interact(mydict=globals(),mybanner="== Jasper Advanced Mode ==",loglevel=2)


def arpPing(network):
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=2)
    print (r"List of all hosts in the network:")
    for snd,rcv in ans:
        print (rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))

    return ans ,unans

#ans,unans= arpPing(network="192.168.1.0/24")


#advanceMode()

