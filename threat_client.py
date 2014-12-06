#!/usr/bin/env python 

""" 
A simple echo client 
""" 

import socket 

host = '10.5.104.211'
port = 50000 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.connect((host,port)) 
s.send('<firewall-threat-alert name="FW_China" ip-addr="10.5.104.53" logid="6089136626309845878"><receive_time>2014/12/04 21:44:51</receive_time><subtype>attack</subtype><time_generated>2014/12/04 21:44:51</time_generated><src>192.168.30.1</src><dst>81.210.43.243</dst><rule>rule-1</rule><threat-name>Microsoft Internet Explorer CSS Strings Parsing Memory Corruption Vulnerability</threat-name><category>overflow</category><severity>critical</severity></firewall-threat-alert>') 

#data = s.recv(size) 
s.close() 
#print 'Received:', data
