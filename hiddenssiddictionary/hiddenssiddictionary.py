#!/usr/bin/python

import sys
from scapy.all import *

mymac = 'aa:aa:aa:aa:aa:aa'
brdmac = 'ff:ff:ff:ff:ff:ff'

for ssid in open(sys.argv[1], 'r').readlines() :

	pkt = RadioTap() / Dot11( type = 0, subtype = 4, addr1 = brdmac, addr2 = mymac, addr3 = brdmac) / Dot11ProbeReq() / Dot11Elt(ID=0, info = ssid.strip()) /  Dot11Elt(ID=1, info = "\x02\x04\x0b\x16") / Dot11Elt(ID=3, info = "\x08")

	print "\nTrying SSID : ", ssid
	sendp(pkt, iface = "mon0", count = 3, inter = .3)
