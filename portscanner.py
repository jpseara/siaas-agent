# Even though no original code is left, the original inspiration for this module was taken from Mohamed Ezzat's Python Vulnerability Scanner - https://mohamedaezzat.github.io/posts/vulnerabilityscanner/
# By João Pedro Seara

import siaas_aux
import os
import sys
import logging
import time
import json
import nmap3
import re
import concurrent.futures
import subprocess
import socket
import ipaddress
import pprint

logger = logging.getLogger(__name__)

NMAP_SYSINFO_TIMEOUT_SEC=600
NMAP_PORTSCAN_TIMEOUT_SEC=300
LOOP_INTERVAL_SEC=15

def vulnerabilities_per_port(target_ip, port, protocol, nmap_script="vulners", timeout=30):

    logger.info("Scanning vulnerabilities for " + target_ip + " at " + str(port) + "/" + protocol+" ...")
    
    vuln_list=[]
    vuln_dict={}

    ipv=siaas_aux.is_ipv4_or_ipv6(target_ip)
    if ipv==None:
       logger.error("Can't scan vulnerabilities for "+target_ip+" at " + str(port)+"/"+ protocol+"+ as it is not from a valid IP protocol.")
       return vuln_dict

    nmap = nmap3.Nmap()

    if protocol=="udp":
       prot_flag="U"
    else:
       prot_flag="T"

    try:
        # By default nmap will scan the top 1000 ports (~93% of TCP ports, ~49% of UDP ports)
        #results = nmap.nmap_version_detection(target_ip, args="-%s -p%s:%s --script %s -Pn --script-args mincvss+5.0 --host-timeout %s" % (ipv, prot_flag, port, nmap_script, timeout))
        results = nmap.nmap_version_detection(target_ip, args="-%s -p%s:%s --script %s -Pn --host-timeout %s" % (ipv, prot_flag, port, nmap_script, timeout))
        logger.debug("Nmap raw output for vulnerability scan in "+target_ip+" at "+str(port)+"/"+protocol+":\n"+pprint.pformat(results))
        
        for t in results["task_results"]:
            if "extrainfo" in t.keys():
                 if "timed out".casefold() in t["extrainfo"].casefold():
                      raise TimeoutError(str(timeout))

        host_results = results[target_ip]

        script_list=[]
        for c in host_results["ports"][0]["cpe"]:
            script_list.append(c["cpe"])

        for d in host_results["ports"][0]["scripts"]:
            for script_name in script_list:
                if script_name in d["data"].keys():
                    if "children" in d["data"][script_name].keys():
                        vuln_list = vuln_list + d["data"][script_name]["children"]

    except TimeoutError as e:
        logger.warning("Nmap timed out while scanning vulnerabilities for "+target_ip+" at "+str(port)+"/"+protocol+": "+str(e)+" sec. Maybe it needs to be increased?")
        return vuln_dict
    except LookupError as e:
        logger.warning("Nmap returned an empty reply while scanning vulnerabilities in "+target_ip+" at "+str(port)+"/"+protocol+". Possible timeout, or maybe the host or port are down?")
        return vuln_dict
    except Exception as e:
        logger.error("Nmap threw an invalid reply while scanning vulnerabilities in "+target_ip+" at "+str(port)+"/"+protocol+": "+str(e))
        return vuln_dict

    if len(vuln_list) == 0:
        logger.info("No vulnerabilities found for "+target_ip+" at "+str(port)+"/"+protocol)

    for vuln in vuln_list:
        try:
           logger.info("VULNERABILITY FOUND! In "+target_ip+" at "+str(port)+"/"+protocol+": "+str(vuln["id"]))
           vuln_dict[vuln["id"]]=vuln
           vuln_dict[vuln["id"]].pop("id",None)
        except:
           logger.error("Invalid vulnerability detected and ignored: "+str(vuln))
    
    return vuln_dict

def get_system_info(target_ip, timeout=30):

    logger.info("Scanning " + target_ip +" for system information ...")
    
    sysinfo_dict={}
    detected_ports={}

    ipv=siaas_aux.is_ipv4_or_ipv6(target_ip)
    if ipv==None:
       logger.error("Can't get system information for "+target_ip+" as it is not from a valid IP protocol.")
       return (sysinfo_dict, detected_ports)

    nmap = nmap3.Nmap()

    try:
        results = nmap.nmap_os_detection(target_ip, args="-%s -sV -Pn --host-timeout %s" % (ipv, timeout))
        logger.debug("Nmap raw output for system info scan in "+target_ip+":\n"+pprint.pformat(results))

        for t in results["task_results"]:
            if "extrainfo" in t.keys():
                if "timed out" in t["extrainfo"]:
                    raise TimeoutError(str(timeout))

        host_results = results[target_ip]

    except TimeoutError as e:
        logger.warning("Nmap timed out while grabbing system info for "+target_ip+": "+str(e)+" sec. Maybe it needs to be increased?")
        return (sysinfo_dict, detected_ports)
    except LookupError as e:
        logger.warning("Nmap returned an empty reply while grabbing system info for "+target_ip+". Possible timeout, or maybe the host is down?")
        return (sysinfo_dict, detected_ports)
    except Exception as e:
        logger.error("Nmap returned an unknown error while grabbing system info for "+target_ip+": "+str(e))
        return (sysinfo_dict, detected_ports)
   
    try:
        sysinfo_dict["mac_address"]=host_results["macaddress"]["addr"]
        sysinfo_dict["nic_vendor"]=host_results["macaddress"]["vendor"]
    except:
        pass
  
    try:
        sysinfo_dict["hostname"]=host_results["hostname"][0]["name"]
    except:
        pass

    try:
        sysinfo_dict["os_name"]=host_results["osmatch"][0]["name"]
        sysinfo_dict["os_family"]=host_results["osmatch"][0]["osclass"]["osfamily"]
        sysinfo_dict["os_vendor"]=host_results["osmatch"][0]["osclass"]["vendor"]
        sysinfo_dict["os_type"]=host_results["osmatch"][0]["osclass"]["type"]
        sysinfo_dict["os_gen"]=host_results["osmatch"][0]["osclass"]["osgen"]
    except:
        pass

    for p in host_results["ports"]:
       
        name=""
        prod_name=""
        hostname=""

        detected_ports[p["portid"]+"/"+p["protocol"]]={}
        detected_ports[p["portid"]+"/"+p["protocol"]]["state"]=p["state"]

        if "name" in p["service"].keys():
            if len(p["service"]["name"]) > 0:
                detected_ports[p["portid"]+"/"+p["protocol"]]["service"] = p["service"]["name"]
                name = p["service"]["name"]

        if "hostname" in p["service"].keys():
            if len(p["service"]["hostname"]) > 0:
                detected_ports[p["portid"]+"/"+p["protocol"]]["site"] = p["service"]["hostname"]

        if "product" in p["service"].keys():
            prod_name=p["service"]["product"]
            if "version" in p["service"].keys():
                prod_name+=" "+p["service"]["version"]
            if "extrainfo" in p["service"].keys():
                prod_name+=" ("+p["service"]["extrainfo"]+")"
            if len(p["service"]["product"]) > 0:
                detected_ports[p["portid"]+"/"+p["protocol"]]["product"]=prod_name

        logger.info("Service found in "+target_ip+" at "+p["portid"]+"/"+p["protocol"]+": "+name)

    return (sysinfo_dict, detected_ports)

def main(target_ip="127.0.0.1", nmap_script="vulners"):

    timeout=15
    target_info={}
    target_info["system_info"]={}
    target_info["detected_ports"]={}
    system_info_output=({},{})

    # Enable just one single target (testing purposes)
    #if target_ip != "192.168.122.51": return (target_ip, target_info)

    # Grab system information and detected ports
    system_info_output=get_system_info(target_ip, timeout=NMAP_SYSINFO_TIMEOUT_SEC)
    target_info["system_info"] = system_info_output[0]
    detected_ports = system_info_output[1]

    # Scan vulnerabilities for each detected port
    for port in detected_ports.keys():
        target_info["detected_ports"][port]={}
        target_info["detected_ports"][port]["vulnerabilities"]={}
        target_info["detected_ports"][port]=detected_ports[port]
        target_info["detected_ports"][port]["vulnerabilities"]=vulnerabilities_per_port(target_ip, port.split("/")[0], port.split("/")[1], nmap_script=nmap_script, timeout=NMAP_PORTSCAN_TIMEOUT_SEC)
    
    target_info["last_scan"]=siaas_aux.get_now_utc_str()

    return (target_ip, target_info)

def loop(siaas_uuid="00000000-0000-0000-0000-000000000000", nmap_script="vulners"):

    #try:
       #os.remove(os.path.join(sys.path[0],'tmp/portscanner.tmp'))
    #except OSError:
       #pass

    while True:
       
       portscanner_dict={}
       portscanner_dict[siaas_uuid]={}
       portscanner_dict[siaas_uuid]["portscanner"]={}
       scan_results_all={}

       logger.debug("Loop running ...")

       # Read hosts in the neighbourhood
       hosts = siaas_aux.read_from_local_file(os.path.join(sys.path[0],'tmp/neighbourhood.tmp'))

       if hosts == None or len(hosts) == 0:
           logger.warning("Couldn't read neighbourhood data. Either it's still being populated, or no neighbours exist at the moment. Trying again ...")
           time.sleep(5)
           continue

       with concurrent.futures.ThreadPoolExecutor() as executor:
           futures = []
           for ip in hosts[siaas_uuid]["neighbourhood"].keys():
              futures.append(executor.submit(main, target_ip=ip, nmap_script=nmap_script))
           for future in concurrent.futures.as_completed(futures):
              scan_results_all[future.result()[0]]=(future.result()[1])
      
       # Creating portscanner dict
       portscanner_dict[siaas_uuid]["portscanner"]=scan_results_all

       # Writing in local database
       siaas_aux.write_to_local_file(os.path.join(sys.path[0],'tmp/portscanner.tmp'), portscanner_dict)

       time.sleep(LOOP_INTERVAL_SEC)

if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    target_host = input('\nEnter target to scan for vulnerable open ports: ')

    if target_host=="":
        target_host="127.0.0.1"

    try:
       target_ip=socket.getaddrinfo(target_host, None)[0][4][0]
    except:
       print("Host "+target_host+" is invalid. It can't be pinged and neither can it be resolved. Exiting!")
       sys.exit(2)

    print('\n')

    main(target_ip)

    print('\nAll done. Bye!\n')
