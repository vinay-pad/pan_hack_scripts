import elementtree.ElementTree as ET
from elementtree.ElementTree import Element, SubElement, ElementTree, tostring
import simplejson as json

tree = ET.parse("system_alert.xml")
root = tree.getroot()

sys_logid = root.attrib["logid"]
sys_logtype = root.find("type").text
sys_logsubtype =  root.find("subtype").text
sys_logtime_generated = root.find("time_generated").text
sys_logseverity = root.find("severity").text
sys_log_opaque = root.find("opaque").text 

print json.dumps({
	"sys_logid" : sys_logid,
	"sys_logtype" : sys_logtype,
	"sys_logsubtype" :sys_logsubtype,
	"sys_logtime_generated" : sys_logtime_generated,
	"sys_logseverity" : sys_logseverity,
	"sys_log_opaque" : sys_log_opaque }, indent=2);
