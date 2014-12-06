import elementtree.ElementTree as ET
from elementtree.ElementTree import Element, SubElement, ElementTree, tostring
import simplejson as json

tree = ET.parse("firewall_sysinfo.xml")
root = tree.getroot()

#cpu entries
ip = root.attrib['ip-addr']
name = root.attrib['name']
cpu_entries = root.find("cpu-usage").findall("entry")
total_cpu = cpu_entries[0].find("value").text
mgmtsrvr_cpu = cpu_entries[1].find("value").text

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

#lograte
lograte = root.find("log-rate").text

#throughput
throughput = root.find("throughput").text

#active sessions
active_sess = root.find("active-sessions").text

#ha_status
ha_status = root.find("ha-status").text

print json.dumps(
        {
                "name":name,
                "total_cpu": total_cpu,
                "mgmtsrvr_cpu" : mgmtsrvr_cpu,
		"ip": ip,
		"opt_pancfg_usage" : opt_pancfg_usage,
		"opt_panrepo_usage" : opt_panrepo_usage,
		"dev_shm_usage" : dev_shm_usage,
		"opt_panlogs_usage" : opt_panlogs_usage,
		"total_mem": total_mem,
		"mgmtsrvr_mem" : mgmtsrvr_mem,
		"lograte" : lograte,
		"throughput" : throughput,
		"active_sess" : active_sess,
		"ha_status" : ha_status
        }, indent=2
);
