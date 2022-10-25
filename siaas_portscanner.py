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

def parse_raw_output_from_nmap_scan(script_name="generic", raw_data=""):

   out_dict={}

   if type(script_name) is not str or type(raw_data) is not str:

      logger.error("Invalid input was provided. Not parsing nmap raw data.")
      return out_dict

   total_vulns=0
   
   if "vulners" in script_name or "vulscan" in script_name:

      logger.debug("Parsing raw data using vulners/vulscan parser ...")

      current_section=""
      for line in raw_data.splitlines():
         if len(line or '') > 0:
            clean_line=line.lstrip().rstrip()
            if clean_line.endswith(":"):
               current_section=clean_line.rstrip(":")
               out_dict[current_section]={}
            else:
               if current_section != "":
                  total_vulns+=1
                  out_dict[current_section][clean_line.split(maxsplit=1)[0].lstrip("[").rstrip("]")]=clean_line.split(maxsplit=1)[1].split("\t")

   else:

      logger.debug("Parsing raw nmap data using a generic parser ...")

      out_list=[]
      for line in raw_data.splitlines():
         if len(line or '') > 0:
            clean_line=line.lstrip().rstrip()
            try:
               out_list.append(clean_line.lstrip().rstrip().replace("\t", " | "))
               #total_vulns+=1 # not counting raw lines as vulnerabilities as there's lots of trash in there (fingerprints, banners, etc)
            except:
               logger.warning("Couldn't append line to list of vulnerabilities: "+str(clean_line))
      out_dict["raw_lines"]=out_list

   return (out_dict, total_vulns)

def vulnerabilities_per_port(target_ip, port, protocol, nmap_scripts_string=None, timeout=300):

    logger.info("Scanning vulnerabilities for " + target_ip +
                " at " + str(port) + "/" + protocol+" ...")

    vuln_dict = {}
    total_valid_scripts=set()
    total_vulns=0

    if type(nmap_scripts_string) is not str:
        logger.warning(
            "Nmap scripts string is undefined or invalid. Bypassing vulnerability scan.")
        return (vuln_dict, total_valid_scripts, total_vulns)

    if len(nmap_scripts_string or '') == 0:
        logger.warning(
            "Nmap scripts string is undefined or invalid. Bypassing vulnerability scan.")
        return (vuln_dict, total_valid_scripts, total_vulns)

    try:
        timeout = int(timeout)
    except:
        timeout = 300
        logger.warning(
            "Input timeout for port scanning is not configured or in an invalid format. Defaulting to \"300\".")

    ipv = siaas_aux.is_ipv4_or_ipv6(target_ip)
    if ipv == None:
        logger.error("Can't scan vulnerabilities for "+target_ip+" at " +
                     str(port)+"/" + protocol+"+ as it is not from a valid IP protocol.")
        return (vuln_dict, total_valid_scripts, total_vulns)

    nmap_scripts_list = nmap_scripts_string.split(",")
    for nmap_script_raw in nmap_scripts_list:

        nmap_script_uncommented = nmap_script_raw.split('#')[0]
        nmap_script = nmap_script_uncommented.split(
            '\t')[0].split('\n')[0].rstrip().lstrip()

        if len(nmap_script_uncommented) > 0 and len(nmap_script) == 0:
            logger.warning("Nmap script '" +
                           nmap_script_uncommented+"' is invalid. Skipped.")

        logger.debug("Now scanning using script '"+nmap_script +
                     "' for "+target_ip+" at " + str(port)+"/" + protocol+" ...")

        nmap = nmap3.Nmap()

        if protocol == "udp":
            prot_flag = "U"
        else:
            prot_flag = "T"

        try:

            #results = nmap.nmap_version_detection(target_ip, args="-%s -p%s:%s --script %s -Pn --script-args mincvss+5.0 --host-timeout %s" % (ipv, prot_flag, port, nmap_script, timeout))
            results = nmap.nmap_version_detection(
                target_ip, args="-%s -p%s:%s --script %s -Pn --host-timeout %s" % (ipv, prot_flag, port, nmap_script, timeout))
            logger.debug("Nmap raw output for vulnerability scan using script '"+nmap_script +
                         "' in "+target_ip+" at "+str(port)+"/"+protocol+":\n"+pprint.pformat(results))

            for t in results["task_results"]:
                if "extrainfo" in t.keys():
                    if "timed out".casefold() in t["extrainfo"].casefold():
                        raise TimeoutError(str(timeout))

            vuln_dict[nmap_script] = {}
            host_results = results[target_ip]
            script_vulns=0

            for d in host_results["ports"][0]["scripts"]:
                raw=""
                if "raw" in d.keys():
                   raw=d["raw"]
                sub_script="main"
                if "name" in d.keys():
                   sub_script=d["name"]
                vuln_dict[nmap_script][sub_script], n_vulns = parse_raw_output_from_nmap_scan(sub_script,raw)
                total_vulns+=n_vulns
                script_vulns+=n_vulns
                #vuln_dict[nmap_script]["raw"]=raw

            total_valid_scripts.add(nmap_script)

        except TimeoutError as e:
            logger.warning("Nmap timed out while scanning vulnerabilities using script '"+nmap_script+"' for " +
                           target_ip+" at "+str(port)+"/"+protocol+": "+str(e)+" sec. Maybe it needs to be increased?")
            return (vuln_dict, total_valid_scripts, total_vulns)
        except LookupError as e:
            logger.warning("Nmap returned an empty reply while scanning vulnerabilities using script '"+nmap_script +
                           "' in "+target_ip+" at "+str(port)+"/"+protocol+". Possible timeout, or maybe the host or port are down?")
            return (vuln_dict, total_valid_scripts, total_vulns)
        except Exception as e:
            logger.error("Nmap threw an invalid reply while scanning vulnerabilities using script '" +
                         nmap_script+"' in "+target_ip+" at "+str(port)+"/"+protocol+": "+str(e))
            return (vuln_dict, total_valid_scripts, total_vulns)

        if script_vulns == 0:
            logger.info("No vulnerabilities found using script '" +
                        nmap_script+"' for "+target_ip+" at "+str(port)+"/"+protocol)
        else:
            logger.info(str(script_vulns)+" VULNERABILITIES WERE FOUND! While using script '"+nmap_script +
                            "' in "+target_ip+" at "+str(port)+"/"+protocol+".")

    return (vuln_dict, total_valid_scripts, total_vulns)


def get_system_info(target_ip, specific_ports=None, timeout=30):

    logger.info("Scanning " + target_ip + " for system information ...")

    sysinfo_dict = {}
    detected_ports = {}

    try:
        timeout = int(timeout)
    except:
        timeout = 600
        logger.warning(
            "Input timeout for system information scanning is not configured or in an invalid format. Defaulting to \"600\".")

    ipv = siaas_aux.is_ipv4_or_ipv6(target_ip)
    if ipv == None:
        logger.error("Can't get system information for " +
                     target_ip+" as it is not from a valid IP protocol.")
        return (sysinfo_dict, detected_ports)

    nmap = nmap3.Nmap()

    try:
        if type(specific_ports) is int:
           specific_ports=str(specific_ports)

        if len(specific_ports or '') == 0:
           results = nmap.nmap_os_detection(
              target_ip, args="-%s -sV -Pn --host-timeout %s" % (ipv, timeout))
        else:
           logger.debug("Restricting port scan in "+target_ip+" to the configured port interval: "+specific_ports)
           results = nmap.nmap_os_detection(target_ip, args="-%s -sV -Pn -p%s --host-timeout %s" % (ipv, specific_ports, timeout))
        logger.debug("Nmap raw output for system info scan in " +
                     target_ip+":\n"+pprint.pformat(results))

        for t in results["task_results"]:
            if "extrainfo" in t.keys():
                if "timed out" in t["extrainfo"]:
                    raise TimeoutError(str(timeout))

        host_results = results[target_ip]

    except TimeoutError as e:
        logger.warning("Nmap timed out while grabbing system info for " +
                       target_ip+": "+str(e)+" sec. Maybe it needs to be increased?")
        return (sysinfo_dict, detected_ports)
    except LookupError as e:
        logger.warning("Nmap returned an empty reply while grabbing system info for " +
                       target_ip+". Possible timeout, or maybe the host is down?")
        return (sysinfo_dict, detected_ports)
    except Exception as e:
        logger.error(
            "Nmap returned an unknown error while grabbing system info for "+target_ip+": "+str(e))
        return (sysinfo_dict, detected_ports)

    try:
        sysinfo_dict["hostname"] = host_results["hostname"][0]["name"]
    except:
        pass

    try:
        sysinfo_dict["mac_address"] = host_results["macaddress"]["addr"]
        sysinfo_dict["nic_vendor"] = host_results["macaddress"]["vendor"]
    except:
        pass

    try:
        sysinfo_dict["os_name"] = host_results["osmatch"][0]["name"]
        sysinfo_dict["os_family"] = host_results["osmatch"][0]["osclass"]["osfamily"]
        sysinfo_dict["os_gen"] = host_results["osmatch"][0]["osclass"]["osgen"]
        sysinfo_dict["os_vendor"] = host_results["osmatch"][0]["osclass"]["vendor"]
        sysinfo_dict["os_type"] = host_results["osmatch"][0]["osclass"]["type"]
    except:
        pass

    for p in host_results["ports"]:

        name = ""
        prod_name = ""
        hostname = ""

        detected_ports[p["portid"]+"/"+p["protocol"]] = {}
        detected_ports[p["portid"]+"/"+p["protocol"]]["state"] = p["state"]

        if "name" in p["service"].keys():
            if len(p["service"]["name"]) > 0:
                detected_ports[p["portid"]+"/"+p["protocol"]
                               ]["service"] = p["service"]["name"]
                name = p["service"]["name"]

        if "hostname" in p["service"].keys():
            if len(p["service"]["hostname"]) > 0:
                detected_ports[p["portid"]+"/"+p["protocol"]
                               ]["site"] = p["service"]["hostname"]

        if "product" in p["service"].keys():
            prod_name = p["service"]["product"]
            if "version" in p["service"].keys():
                prod_name += " "+p["service"]["version"]
            if "extrainfo" in p["service"].keys():
                prod_name += " ("+p["service"]["extrainfo"]+")"
            if len(p["service"]["product"]) > 0:
                detected_ports[p["portid"]+"/" +
                               p["protocol"]]["product"] = prod_name

        logger.info("Service in "+target_ip+" at " +
                    p["portid"]+"/"+p["protocol"]+": "+name)

    if len(host_results["ports"]) == 0:
        logger.info("Found no ports/services reachable for host "+target_ip+".")

    return (sysinfo_dict, detected_ports)


def main(target_ip="127.0.0.1"):

    timeout = 15
    target_info = {}
    target_info["system_info"] = {}
    target_info["detected_ports"] = {}
    system_info_output = ({}, {})

    # Enable just one single target (testing purposes)
    # if target_ip != "192.168.122.51": return (target_ip, target_info)

    # Grab system information and detected ports
    system_info_output = get_system_info(
        target_ip, specific_ports=siaas_aux.get_config_from_configs_db(config_name="target_specific_ports"), timeout=siaas_aux.get_config_from_configs_db(config_name="nmap_sysinfo_timeout_sec"))
    target_info["system_info"] = system_info_output[0]
    detected_ports = system_info_output[1]

    # Report
    total_ports=len(detected_ports)
    total_valid_scripts=set()
    total_vulns=0

    # Scan vulnerabilities for each detected port
    for port in detected_ports.keys():
        target_info["detected_ports"][port] = {}
        target_info["detected_ports"][port]["vulnerabilities"] = {}
        target_info["detected_ports"][port] = detected_ports[port]
        target_info["detected_ports"][port]["vulnerabilities"], scripts_port, n_vulns_port = vulnerabilities_per_port(target_ip, port.split("/")[0], port.split(
            "/")[1], nmap_scripts_string=siaas_aux.get_config_from_configs_db(config_name="nmap_scripts"), timeout=siaas_aux.get_config_from_configs_db(config_name="nmap_portscan_timeout_sec"))
        total_valid_scripts.update(scripts_port)
        total_vulns+=n_vulns_port

    logger.info("Port scanning ended for %s: %s vulnerabilities were detected, across %s ports and using %s valid Nmap scripts. You might have duplicated outputs if you use multiple scripts." % (target_ip, total_vulns, total_ports, len(total_valid_scripts)))
    target_info["metadata"]={}
    target_info["metadata"]["num_ports"]=total_ports
    target_info["metadata"]["num_valid_scripts"]=len(total_valid_scripts)
    target_info["metadata"]["total_num_vulnerabilities"]=total_vulns
    target_info["last_check"] = siaas_aux.get_now_utc_str()

    return (target_ip, target_info)


def loop():

    # Initializing the portscanner local DB
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
    siaas_aux.write_to_local_file(os.path.join(
        sys.path[0], 'var/portscanner.db'), {})

    while True:

        portscanner_dict = {}
        scan_results_all = {}

        logger.debug("Loop running ...")

        disable_portscanner = siaas_aux.get_config_from_configs_db(
            config_name="disable_portscanner", convert_to_string=True)
        if len(disable_portscanner or '') > 0:
            if disable_portscanner.lower() == "true":
                logger.warning(
                    "Portscanner is disabled in the config. Not running. Will check again in a bit ...")
                time.sleep(60)
                continue

        hosts = siaas_aux.read_from_local_file(
            os.path.join(sys.path[0], 'var/neighborhood.db'))
        if len(hosts or '') == 0:
            logger.warning(
                "Couldn't read neighborhood data. Either it's still being populated, or no neighbors exist at the moment. Trying again ...")
            time.sleep(60)
            continue

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for ip in hosts.keys():
                futures.append(executor.submit(main, target_ip=ip))
            for future in concurrent.futures.as_completed(futures):
                scan_results_all[future.result()[0]] = (future.result()[1])

        # Creating portscanner dict
        portscanner_dict = scan_results_all

        # Writing in local database
        siaas_aux.write_to_local_file(os.path.join(
            sys.path[0], 'var/portscanner.db'), portscanner_dict)

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="portscanner_loop_interval_sec"))
            logger.debug("Sleeping for "+str(sleep_time) +
                         " seconds before next loop ...")
            time.sleep(sleep_time)
        except:
            logger.debug(
                "The interval loop time is not configured or is invalid. Sleeping now for 60 seconds by default ...")
            time.sleep(60)


if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    target_host = input('\nEnter target to scan for vulnerable open ports: ')

    if target_host == "":
        target_host = "127.0.0.1"

    try:
        target_ip = socket.getaddrinfo(target_host, None)[0][4][0]
    except:
        print("Host "+target_host +
              " is invalid. It can't be pinged and neither can it be resolved. Exiting!")
        sys.exit(2)

    print('\n')

    main(target_ip)

    print('\nAll done. Bye!\n')
