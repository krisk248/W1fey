#!/usr/bin/python

import sys
from scapy.all import * 

ssids = set()

def PacketHandler(pkt) :

	if pkt.haslayer(Dot11Beacon) : 

		if (pkt.info not in ssids) and pkt.info :
			ssids.add(pkt.info)
			print len(ssids), pkt.addr3, pkt.info 


sniff(iface = sys.argv[1], count = int( sys.argv[2]), prn = PacketHandler)


