import elementtree.ElementTree as ET
from elementtree.ElementTree import Element, SubElement, ElementTree, tostring
import simplejson as json

tree = ET.parse("sample.xml")
root = tree.getroot()
cpu_entries = root.find("cpu").findall("entry")
total_cpu = cpu_entries[0].find("value").text
mgmtsrvr_cpu = cpu_entries[1].find("value").text

print total_cpu,mgmtsrvr_cpu

print json.dumps(
        {
                "name":"fw1",
                "total_cpu": total_cpu,
                "mgmtsrvr_cpu" : mgmtsrvr_cpu
        }
);
