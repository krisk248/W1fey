#!/usr/bin/python 

import sys
from scapy.all import * 

clientprobes = set()

def PacketHandler(pkt) :

	if pkt.haslayer(Dot11ProbeReq) :

		if len(pkt.info) > 0 : 
			testcase = pkt.addr2 + '---' + pkt.info 
			if testcase not in clientprobes :
				clientprobes.add(testcase) 
				print "New Probe Found:  " + pkt.addr2 + ' ' + pkt.info 


				print "\n------------Client Probes Table ---------------\n"
				counter = 1
				for probe in clientprobes :
					[client, ssid] = probe.split('---')
					print counter, client, ssid
					counter = counter + 1 
				
				print "\n-----------------------------------------------\n"


sniff(iface = sys.argv[1], count = int( sys.argv[2] ), prn = PacketHandler)


