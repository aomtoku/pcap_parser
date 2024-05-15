#!/bin/env python3

import sys, os
from random import randint
from scapy.all import *

def generate_load(length):
    load = ''
    for i in range(length):
        load += chr(randint(0,255))
    return load

def main(argv):
    outputfile = 'test.pcap'
    pkts_num = 1
    pktlen = 60
    found_option = False
    default_sMAC = True
    default_dMAC = True
    sMAC = "aa:bb:cc:dd:ee:ff"
    dMAC = "de:ad:be:ef:f0:01"
    sIP = "192.168.0.1"
    dIP = "192.168.10.100"

    pkts = []

    for i in range(pkts_num):
        pkt = Ether(src=sMAC, dst=dMAC)/IP(src=sIP, dst=dIP)/UDP(sport=12345, dport=12346)/generate_load(46)
        pkts.append(pkt)

    scapy.utils.wrpcap(outputfile, pkts)

if __name__ == "__main__":
   main(sys.argv[1:])
