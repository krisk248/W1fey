#!/usr/bin/python

import sys
from scapy.all import * 

ssids = set()

def PacketHandler(pkt) :

	if pkt.haslayer(Dot11Beacon) : 

		temp = pkt 

		while temp:
			temp = temp.getlayer(Dot11Elt) 
			if temp and temp.ID == 0 and (temp.info not in ssids) :	
				ssids.add(temp.info)
				print len(ssids), pkt.addr3, temp.info
				break 

			temp = temp.payload 


sniff(iface = sys.argv[1], count = int( sys.argv[2]), prn = PacketHandler)


