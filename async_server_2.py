
import asyncore, socket
import sys
import simplejson as json
import httplib
import os
import elementtree.ElementTree as ET
from elementtree.ElementTree import Element, SubElement, ElementTree, tostring
import simplejson as json


class Server(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(('', port))
        self.listen(1)

    def handle_accept(self):
        # when we get a client connection start a dispatcher for that
        # client
        socket, address = self.accept()
        print 'Connection by', address
        EchoHandler(socket)

class EchoHandler(asyncore.dispatcher_with_send):
    # dispatcher_with_send extends the basic dispatcher to have an output
    # buffer that it writes whenever there's content
   	
    def __parse_threat(self, root):
	threat_alert_fwname = root.attrib["name"]
	threat_alert_fw_ipaddr = root.attrib["ip-addr"]
	threat_receive_time = root.find("receive_time").text
	threat_subtype =  root.find("subtype").text
	threat_time_generated = root.find("time_generated").text
	threat_source = root.find("src").text
	threat_dst = root.find("dst").text
	threat_rule = root.find("rule").text
	threat_name = root.find("threat-name").text
	threat_category = root.find("category").text
	threat_severity = root.find("severity").text

	print json.dumps({
        "threat_alert_fwname": threat_alert_fwname,
        "threat_alert_fw_ipaddr":threat_alert_fw_ipaddr,
        "threat_receive_time": threat_receive_time,
        "threat_subtype" : threat_subtype,
        "threat_time_generated" : threat_time_generated,
        "threat_source":threat_source,
        "threat_dst":threat_dst,
        "threat_rule":threat_rule,
        "threat_name":threat_name,
        "threat_category":threat_category,
        "threat_severity":threat_severity
         }, indent=2);

	connection = httplib.HTTPSConnection('api.parse.com', 443)
        connection.connect()
        connection.request('POST', '/1/functions/UPDATE_THREAT_ALERT_STATUS', json.dumps({
		"threat_alert_fwname": threat_alert_fwname,
        	"threat_alert_fw_ipaddr":threat_alert_fw_ipaddr,
        	"threat_receive_time": threat_receive_time,
        	"threat_subtype" : threat_subtype,
        	"threat_time_generated" : threat_time_generated,
        	"threat_source":threat_source,
        	"threat_dst":threat_dst,
        	"threat_rule":threat_rule,
        	"threat_name":threat_name,
        	"threat_category":threat_category,
        	"threat_severity":threat_severity
                }), {
                "X-Parse-Application-Id": "RnsDdfZemEz0bGQoqMQE4JyyfSLcdJmqTreY5QD9",
                "X-Parse-REST-API-Key": "RAIna9hI5q5OjxzQzbgq00rYrnOnrMAovCEfwiIb",
                "Content-Type": "application/json"
         })
	print 'Sent threat alert to Parse'

    def __parse_sys(self, root):
	sys_fwname = root.attrib["name"]
	sys_logtype = root.find("type").text
	sys_logsubtype =  root.find("subtype").text
	sys_logtime_generated = root.find("time_generated").text
	sys_logseverity = root.find("severity").text
	sys_log_opaque = root.find("opaque").text

	connection = httplib.HTTPSConnection('api.parse.com', 443)
        connection.connect()
        connection.request('POST', '/1/functions/UPDATE_SYS_ALERT_STATUS', json.dumps({
		"sys_fwname" : sys_fwname,
        	"sys_logtype" : sys_logtype,
        	"sys_logsubtype" :sys_logsubtype,
        	"sys_logtime_generated" : sys_logtime_generated,
        	"sys_logseverity" : sys_logseverity,
        	"sys_log_opaque" : sys_log_opaque 
                }), {
                "X-Parse-Application-Id": "RnsDdfZemEz0bGQoqMQE4JyyfSLcdJmqTreY5QD9",
                "X-Parse-REST-API-Key": "RAIna9hI5q5OjxzQzbgq00rYrnOnrMAovCEfwiIb",
                "Content-Type": "application/json"
         })
	print 'Sent system alert to Parse'
	
    def __parse_xml(self, xml_str):
	tree = ET.fromstring(xml_str)
	
	if tree.tag == 'firewall-threat-alert':
		self.__parse_threat(tree)		
	elif tree.tag == 'firewall-system-alert':
		self.__parse_sys(tree)
	
	
	

    def handle_read(self):
        self.out_buffer = self.recv(1024)
        if not self.out_buffer:
            self.close()
	else:
	    #Received data from device, aggregate the data and push it to parse
            str = self.out_buffer.strip('\n')
	    str = str.strip('\x00')
	    print repr(str)
	    self.__parse_xml(str)
	    #TODO: Parse the data to extract the correct details.
	    connection = httplib.HTTPSConnection('api.parse.com', 443)
	    connection.connect()
	    #connection.request('POST', '/1/functions/ADD_FW_DETAILS', json.dumps({
		#"FWName": "Test_firewall",
		#"Health": "Disconnected",
		#"Region": "Nevada"
     		#}), {
       		#"X-Parse-Application-Id": "RnsDdfZemEz0bGQoqMQE4JyyfSLcdJmqTreY5QD9",
       		#"X-Parse-REST-API-Key": "RAIna9hI5q5OjxzQzbgq00rYrnOnrMAovCEfwiIb",
       		#"Content-Type": "application/json"
     	    #})
	


s = Server('', 50000)
asyncore.loop()
