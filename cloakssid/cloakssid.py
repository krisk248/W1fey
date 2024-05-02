#!/usr/bin/python

import sys
from scapy.all import *

mymac = 'aa:aa:aa:aa:aa:aa'

pkt = RadioTap() / Dot11( type = 0, subtype = 5, addr1 = mymac, addr2 = sys.argv[1], addr3 = sys.argv[1]) / Dot11ProbeResp() / Dot11Elt(ID=0, info = "Cloaked!") /  Dot11Elt(ID=1, info = "\x02\x04\x0b\x16") / Dot11Elt(ID=3, info = "\x08")

sendp(pkt, iface = "mon0", count = int( sys.argv[2] ), inter = .3)
