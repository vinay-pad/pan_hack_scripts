import elementtree.ElementTree as ET
from elementtree.ElementTree import Element, SubElement, ElementTree, tostring
import simplejson as json

tree = ET.parse("threat_alert.xml")
root = tree.getroot()

threat_alert_fwname = root.attrib["name"]
threat_alert_fw_ipaddr = root.attrib["ip-addr"]
threat_alert_logid = root.attrib["logid"]
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
	"threat_alert_logid" : threat_alert_logid,
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
