# This is a fork from Layer 2 network neighbourhood discovery tool by Benedikt Waldvogel - https://github.com/bwaldvogel/neighbourhood
# By João Pedro Seara

from __future__ import absolute_import, division, print_function
import siaas_aux
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import subprocess
import math
import errno
import os
import getopt
import sys
import time
import json
import dns.resolver
import ipaddress
import pprint

logger = logging.getLogger(__name__)

ARP_TIMEOUT_SEC=5
LOOP_INTERVAL_SEC=15

def get_arp_ndp_known_hosts():

    logger.info("Grabbing known hosts from local ARP/NDP tables ...")
   
    ip_mac_host={}

    try:
       cmd = subprocess.run(["ip", "neigh", "show"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       arp_output=cmd.stdout.decode('utf-8')
       if cmd.returncode != 0:
           raise Exception(cmd.stderr.decode('utf-8'))
       logger.debug("Raw 'ip neigh show' command output: "+str(arp_output.split('\n')))
    except Exception as e:
       logger.error("'ip' command failed: "+str(e))
       return ip_mac_host

    for arp in arp_output.split('\n'):

       status="up"

       try:
          fields = arp.strip().split()
          ip_arp=fields[0]
          mac=fields[4]
       except:
          continue

       ipv=siaas_aux.is_ipv4_or_ipv6(ip_arp)
       if ipv==None:
          logger.warning("The IP "+ip_arp+" found in the local ARP/NDP tables is not from a valid IP protocol. Skipped.")
          continue

       try:
          ip=socket.getaddrinfo(ip_arp, None)[0][4][0]
       except:
          logger.warning("The host "+ip_arp+" found in the local ARP/NDP tables can't be resolved. Skipped.")
          continue

       if(ipv=="6"):
          host_up = True if os.system("ping6 -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
       else:
          host_up = True if os.system("ping -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
       if not host_up:
          status="down"

       try:
          dns_name=socket.gethostbyaddr(ip)[0]
       except:
          dns_name=""

       dns_entry=ip
       ip_mac_host[ip]={}
       ip_mac_host[ip]["macaddress"]=mac
       if len(dns_name) > 0:
          ip_mac_host[ip]["domain_name"]=dns_name
          dns_entry=ip+" ("+dns_name+")"
       ip_mac_host[ip]["discovery_type"]="arp_ndp"
       ip_mac_host[ip]["ping_status"]=status
       ip_mac_host[ip]["ip_version"]=ipv

       ip_mac_host[ip]["last_check"]=siaas_aux.get_now_utc_str()

       logger.info("Host existing in the local ARP/NDP tables: "+dns_entry)

       if not host_up:
          logger.warning("The host "+ip+" found in the local ARP/NDP tables didn't respond to ping.")

    return ip_mac_host

def scan_and_print_neighbors(net, interface, timeout=5):
    
    logger.info("Arping %s in the neighbourhood of %s ..." % (net, interface))
    
    ip_mac_host={}
    
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
    except Exception as e:
        logger.error("Arping failed for interface "+interface+": "+str(e))
        return(ip_mac_host)

    for s, r in ans.res:

       status="up"

       ipv=siaas_aux.is_ipv4_or_ipv6(r.psrc)
       if ipv == None:
          logger.warning("The automatically found host "+r.psrc+" in the neighbourhood of "+interface+" is not from a valid IP protocol. Skipped.")
          continue

       try:
          ip=socket.getaddrinfo(r.psrc, None)[0][4][0]
       except:
          logger.warning("The automatically found host "+host+" in the neighbourhood of "+interface+" can't be resolved. Skipped.")
          continue

       host_up = True if os.system("ping -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
       if not host_up:
          status="down"

       try:
          dns_name=socket.gethostbyaddr(ip)[0]
       except:
          dns_name=""

       dns_entry=ip
       ip_mac_host[ip]={}
       ip_mac_host[ip]["macaddress"]=r.src
       if len(dns_name) > 0:
          ip_mac_host[ip]["domain_name"]=dns_name
          dns_entry=ip+" ("+dns_name+")"
       ip_mac_host[ip]["discovery_type"]="auto"
       ip_mac_host[ip]["ping_status"]=status
       ip_mac_host[ip]["ip_version"]=ipv

       ip_mac_host[ip]["last_check"]=siaas_aux.get_now_utc_str()

       logger.info("Host automatically found in the neighbourhood of "+interface+": "+dns_entry)

       if not host_up:
           logger.warning("The automatically found host "+ip+" didn't respond to ping.")

    return ip_mac_host

def add_manual_hosts(manual_hosts_file=os.path.join(sys.path[0],'conf/manual_hosts.txt')):
    
    logger.info("Starting host discovery for manually configured entries ...")

    ip_mac_host={}

    #try:
    #   with open(file, 'r') as file:
    #      content = file.read().splitlines()
    #except:
    #   logger.warning("No manual hosts file was found.")
    #   return(ip_mac_host)

    # Grab manual configured hosts
    manual_hosts = siaas_aux.read_from_local_file(manual_hosts_file)
    try:
       manual_host_list=manual_hosts.splitlines()
    except:
       logger.warning("No manual hosts file was found.")
       manual_host_list=[]

    for host_raw in manual_host_list:
      
       all_ips = {}
       host_uncommented=host_raw.split('#')[0]
       host=host_uncommented.split('\t')[0].split('\n')[0].split(' ')[0]

       if len(host_uncommented) > 0 and len(host) == 0:
           logger.warning("Manually configured host '"+host_uncommented+"' is invalid. Make sure there are no spaces or tabs at the beginning of the line. Skipped.") 
       
       else:

         try:
           socket.getaddrinfo("192.168.122.51", None)[0][4][0]
         except:
           logger.warning("Manually configured host '"+host+"' can't be resolved. Skipped.")
           continue

         all_ips=siaas_aux.get_all_ips_for_name(host)

         for ip in all_ips:

            status="up"

            ipv=siaas_aux.is_ipv4_or_ipv6(ip)
            if ipv==None:
               logger.warning("The IP "+ip+" for manually configured host '"+host+"' is not from a valid IP protocol. Skipped.")
               continue

            if(ipv=="6"):
                host_up = True if os.system("ping6 -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
            else:
                host_up = True if os.system("ping -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
            if not host_up:
              status="down"

            try:
              dns_name=socket.gethostbyaddr(ip)[0]
            except:
              dns_name=""

            dns_entry=ip
            ip_mac_host[ip]={}
            ip_mac_host[ip]["discovery_type"]="manual"
            if len(dns_name) > 0:
               ip_mac_host[ip]["domain_name"]=dns_name
               dns_entry=ip+" ("+dns_name+")"
            ip_mac_host[ip]["ping_status"]=status
            ip_mac_host[ip]["manual_entry_address"]=host
            ip_mac_host[ip]["ip_version"]=ipv

            ip_mac_host[ip]["last_check"]=siaas_aux.get_now_utc_str()

            logger.info("Found host for manually configured entry '"+host+"': "+dns_entry)

            if not host_up:
               logger.warning("The IP "+ip+" for manually configured host '"+host+"' didn't respond to ping.")

    return(ip_mac_host)

def main(interface_to_scan=None):

    auto_hosts={}
    manual_hosts={}
    arp_ndp_hosts={}
    all_hosts={}
    auto_scanned_interfaces=0

    # Grab known hosts by ARP/NDP
    arp_ndp_hosts = get_arp_ndp_known_hosts()

    # Grab automatically discovered hosts
    logger.info("Starting automatic neighbourhood discovery ...")
    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:

        if interface_to_scan and interface_to_scan != interface:
            continue

        # Skip loopback network and default GW
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # Skip docker interfaces
        if interface != interface_to_scan \
                and (interface.startswith('docker')
                     or interface.startswith('br-')
                     or interface.startswith('tun')):
            logger.warning("Skipped interface %s." % interface)
            continue

        net = siaas_aux.to_cidr_notation(network, netmask)
        mask=net.split('/')[1]

        if int(mask) > 16:
            auto_hosts=dict(list(auto_hosts.items())+list(scan_and_print_neighbors(net, interface, timeout=ARP_TIMEOUT_SEC).items()))
            auto_scanned_interfaces+=1
        else:
            logger.warning("Skipping network "+net+" as the subnet size is too big.")

    if auto_scanned_interfaces == 0:
        logger.warning("Automatic neighbourhood discovery found no interfaces with a valid network configuration to work on.")

    # Grab manual configured hosts
    manual_hosts=add_manual_hosts(os.path.join(sys.path[0],'conf/manual_hosts.txt'))

    # Merge all hosts (give priority to automatically found hosts in the neighbourhood, as they have more info)
    all_hosts = dict(list(manual_hosts.items())+list(auto_hosts.items())+list(arp_ndp_hosts.items()))

    return all_hosts

def loop(siaas_uuid="00000000-0000-0000-0000-000000000000", interface_to_scan=None):

   #try:
      #os.remove(os.path.join(sys.path[0],'tmp/neighbourhood.tmp'))
   #except OSError:
      #pass

   while True:

      neighbourhood_dict={}
      neighbourhood_dict[siaas_uuid]={}
      neighbourhood_dict[siaas_uuid]["neighbourhood"]={}

      logger.debug("Loop running ...")

      # Creating neighbourhood dict
      neighbourhood_dict[siaas_uuid]["neighbourhood"]=main(interface_to_scan)

      # Writing in local database
      siaas_aux.write_to_local_file(os.path.join(sys.path[0],'tmp/neighbourhood.tmp'), neighbourhood_dict)

      time.sleep(LOOP_INTERVAL_SEC)

if __name__ == "__main__":
    
    log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:', ['help', 'interface='])
    except Exception as e:
        print("Error: "+str(e))
        print("Usage: %s [-i <interface>]" % sys.argv[0])
        sys.exit(2)

    interface = None

    for o, a in opts:
        if o in ('-h', '--help'):
            print("Usage: %s [-i <interface>]" % sys.argv[0])
            sys.exit()
        elif o in ('-i', '--interface'):
            interface = a
        else:
            assert False, 'Unhandled option'
    
    print('\n')

    main(interface_to_scan=interface)

    print('\nAll done. Bye!\n')
