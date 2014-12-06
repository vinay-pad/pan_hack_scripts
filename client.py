#!/usr/bin/env python 

""" 
A simple echo client 
""" 

import socket 

host = '10.5.104.120'
port = 50000 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.connect((host,port)) 
s.send('Hello, world') 
#data = s.recv(size) 
s.close() 
#print 'Received:', data
