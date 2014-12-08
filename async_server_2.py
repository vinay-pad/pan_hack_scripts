
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
	
	req = "\"http://10.5.104.198/api/?type=config&action=set&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9NUZhL25kL29vMlRaaXp4WGFOQUI5UT09&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='block-threat']&element=<source><member>"+str(threat_source)+"</member></source><description>Policy to block threat</description><action>deny</action>\""
        os.system('wget -O vinay.com '+req)
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
	
    def __parse_info(self, root):
	#cpu entries
	ip = root.attrib['ip-addr']
	name = root.attrib['name']
	cpu_entries = root.find("cpu-usage").findall("entry")
	total_cpu = cpu_entries[0].find("value").text
	mgmtsrvr_cpu = cpu_entries[1].find("value").text
        logrcvr_cpu = cpu_entries[2].find("value").text

	#disk entries
	disk_entries = root.find("disk-usage").findall("entry")
	opt_pancfg_usage = disk_entries[0].find("usage").text
	opt_panrepo_usage = disk_entries[1].find("usage").text
	dev_shm_usage = disk_entries[2].find("usage").text
	opt_panlogs_usage = disk_entries[3].find("usage").text

	#memory usage
	mem_entries = root.find("memory-usage").findall("entry")
	total_mem = mem_entries[0].find("value").text
	mgmtsrvr_mem = mem_entries[1].find("value").text
	logrcvr_mem = mem_entries[2].find("value").text

	#lograte
	lograte = root.find("log-rate").text

	#throughput
	throughput = root.find("throughput").text

	#active sessions
	active_sess = root.find("active-sessions").text

	#ha_status
	ha_status = root.find("ha-status").text
	conn_status = root.find("conn_status").text
	
	connection = httplib.HTTPSConnection('api.parse.com', 443)
        connection.connect()
        connection.request('POST', '/1/functions/UPDATE_INFO_STATUS', json.dumps({
                "name":name,
                "total_cpu": total_cpu,
                "mgmtsrvr_cpu" : mgmtsrvr_cpu,
		"logrcvr_cpu" : logrcvr_cpu,
                "ip": ip,
                "opt_pancfg_usage" : opt_pancfg_usage,
                "opt_panrepo_usage" : opt_panrepo_usage,
                "dev_shm_usage" : dev_shm_usage,
                "opt_panlogs_usage" : opt_panlogs_usage,
                "total_mem": total_mem,
                "mgmtsrvr_mem" : mgmtsrvr_mem,
		"logrcvr_mem" : logrcvr_mem,
                "lograte" : lograte,
                "throughput" : throughput,
                "active_sess" : active_sess,
                "ha_status" : ha_status,
		"conn_status" : conn_status
                }), {
                "X-Parse-Application-Id": "RnsDdfZemEz0bGQoqMQE4JyyfSLcdJmqTreY5QD9",
                "X-Parse-REST-API-Key": "RAIna9hI5q5OjxzQzbgq00rYrnOnrMAovCEfwiIb",
                "Content-Type": "application/json"
         })
        print 'Sent info alert to Parse'

    def __parse_xml(self, xml_str):
	tree = ET.fromstring(xml_str)
	
	if tree.tag == 'firewall-threat-alert':
		self.__parse_threat(tree)		
	elif tree.tag == 'firewall-system-alert':
		self.__parse_sys(tree)
	elif tree.tag == 'firewall-sysinfo':
		self.__parse_info(tree)
	
	
	

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
