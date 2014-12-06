#!/usr/bin/env python 

""" 
A simple echo client 
""" 

import socket 

host = '10.5.104.211'
port = 50000 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.connect((host,port)) 
#s.send('<firewall-system-alert name="FW_China_sys_alert" logid="6089136626309529733"><type>SYSTEM</type><subtype>HA-STATE</subtype><time_generated>2014/12/04 21:27:57</time_generated><severity>critical</severity><opaque>HA device has changed states</opaque></firewall-system-alert>') 

s.send('<firewall-system-alert name="FW_Westcoast" ip-addr="10.5.104.53"><type>sasa</type><subtype>sasa</subtype><time_generated>sasa</time_generated><severity>sasa</severity><opaque>sasa</opaque></firewall-system-alert>')
#data = s.recv(size) 
s.close() 
#print 'Received:', data
