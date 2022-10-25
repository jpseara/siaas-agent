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


def get_arp_ndp_known_hosts():

    logger.info("Grabbing known hosts from local ARP/NDP tables ...")

    ip_mac_host = {}

    try:
        cmd = subprocess.run(["ip", "neigh", "show"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        arp_output = cmd.stdout.decode('utf-8')
        if cmd.returncode != 0:
            raise OSError(cmd.stderr.decode('utf-8'))
        logger.debug("Raw 'ip neigh show' command output: " +
                     str(arp_output.splitlines()))
    except Exception as e:
        logger.error("'ip' command failed: "+str(e))
        return ip_mac_host

    for arp in arp_output.splitlines():

        status = "up"

        try:
            fields = arp.strip().split()
            if "FAILED" in fields:
                raise ValueError("ARP/NDP entry in FAILED state.")
            ip_arp = fields[0]
            if ip_arp.startswith("127.") or ip_arp.lower().startswith("fe80::") or ip_arp == "::1":
                raise ValueError(
                    "Rejecting ARP/NDP entry which is a link local address.")
            interface = fields[2]
            if interface.lower() == "lo" or (not interface.lower().startswith("e") and not interface.lower().startswith("w") and not interface.lower().startswith("b")):
                raise ValueError(
                        "Rejecting ARP/NDP entry which is in an invalid interface: "+interface)
            mac = fields[4]
        except:
            continue

        ipv = siaas_aux.is_ipv4_or_ipv6(ip_arp)
        if ipv == None:
            logger.warning(
                "The IP "+ip_arp+" found in the local ARP/NDP tables for interface '"+interface+"' is not from a valid IP protocol. Skipped.")
            continue

        try:
            ip = socket.getaddrinfo(ip_arp, None)[0][4][0]
        except:
            logger.warning(
                "The host "+ip_arp+" found in the local ARP/NDP tables for interface '"+interface+"' can't be resolved. Skipped.")
            continue

        if(ipv == "6"):
            host_up = True if os.system(
                "ping6 -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
        else:
            host_up = True if os.system(
                "ping -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
        if not host_up:
            status = "down"

        try:
            dns_name = socket.gethostbyaddr(ip)[0]
        except:
            dns_name = ""

        dns_entry = ip
        ip_mac_host[ip] = {}
        ip_mac_host[ip]["interface"] = interface
        ip_mac_host[ip]["macaddress"] = mac
        if len(dns_name) > 0:
            ip_mac_host[ip]["domain_name"] = dns_name
            dns_entry = ip+" ("+dns_name+")"
        ip_mac_host[ip]["discovery_type"] = "arp_ndp"
        ip_mac_host[ip]["ping_status"] = status
        ip_mac_host[ip]["ip_version"] = ipv

        ip_mac_host[ip]["last_check"] = siaas_aux.get_now_utc_str()

        logger.info("Host existing in the local ARP/NDP tables for interface '"+interface+"': "+dns_entry)

        if not host_up:
            logger.warning(
                "The host "+ip+" found in the local ARP/NDP tables for interface '"+interface+"' didn't respond to ping.")

    return ip_mac_host


def scan_and_print_neighbors(net, interface, timeout=5):

    logger.info("Arping %s in the neighborhood of '%s' ..." % (net, interface))

    ip_mac_host = {}

    try:
        ans, unans = scapy.layers.l2.arping(
            net, iface=interface, timeout=timeout, verbose=False)
    except Exception as e:
        logger.error("Arping failed for interface '"+interface+"': "+str(e))
        return(ip_mac_host)

    for s, r in ans.res:

        status = "up"

        ipv = siaas_aux.is_ipv4_or_ipv6(r.psrc)
        if ipv == None:
            logger.warning("The automatically found host "+r.psrc+" in the neighborhood of " +
                           interface+" is not from a valid IP protocol. Skipped.")
            continue

        try:
            ip = socket.getaddrinfo(r.psrc, None)[0][4][0]
        except:
            logger.warning("The automatically found host "+host +
                           " in the neighborhood of '"+interface+"' can't be resolved. Skipped.")
            continue

        host_up = True if os.system(
            "ping -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
        if not host_up:
            status = "down"

        try:
            dns_name = socket.gethostbyaddr(ip)[0]
        except:
            dns_name = ""

        dns_entry = ip
        ip_mac_host[ip] = {}
        ip_mac_host[ip]["interface"] = interface
        ip_mac_host[ip]["macaddress"] = r.src
        if len(dns_name) > 0:
            ip_mac_host[ip]["domain_name"] = dns_name
            dns_entry = ip+" ("+dns_name+")"
        ip_mac_host[ip]["discovery_type"] = "auto"
        ip_mac_host[ip]["ping_status"] = status
        ip_mac_host[ip]["ip_version"] = ipv

        ip_mac_host[ip]["last_check"] = siaas_aux.get_now_utc_str()

        logger.info(
            "Host automatically found in the neighborhood of '"+interface+"': "+dns_entry)

        if not host_up:
            logger.warning("The automatically found host " +
                           ip+" didn't respond to ping.")

    return ip_mac_host


def add_manual_hosts(manual_hosts_string=""):

    logger.info("Starting host discovery for manually configured entries ...")

    ip_mac_host = {}

    if type(manual_hosts_string) is not str:
        logger.warning(
            "Manual hosts string is undefined or invalid. Not adding any manual host.")
        return ip_mac_host

    if len(manual_hosts_string or '') == 0:
        logger.warning(
            "Manual hosts string is undefined or invalid. Not adding any manual host.")
        return ip_mac_host

    manual_hosts_list = manual_hosts_string.split(",")

    for host_raw in manual_hosts_list:

        all_ips = {}
        host_uncommented = host_raw.split('#')[0]
        host = host_uncommented.split('\t')[0].split('\n')[0].rstrip().lstrip()

        if host.startswith("127.") or host.lower().startswith("fe80::") or host == "::1" or host.lower() == "localhost":
            logger.warning("Manually configured host '"+host+"' is invalid. No localhost hosts are allowed.")
            continue

        if len(host) > 0:

            try:
                socket.getaddrinfo(host, None)[0][4][0]
            except:
                logger.warning("Manually configured host '" +
                               host+"' can't be resolved. Skipped.")
                continue

            all_ips = siaas_aux.get_all_ips_for_name(host)

            for ip in all_ips:

                status = "up"

                ipv = siaas_aux.is_ipv4_or_ipv6(ip)
                if ipv == None:
                    logger.warning("The IP "+ip+" for manually configured host '" +
                                   host+"' is not from a valid IP protocol. Skipped.")
                    continue

                if(ipv == "6"):
                    host_up = True if os.system(
                        "ping6 -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
                else:
                    host_up = True if os.system(
                        "ping -c 1 " + ip + "> /dev/null 2>&1") == 0 else False
                if not host_up:
                    status = "down"

                try:
                    dns_name = socket.gethostbyaddr(ip)[0]
                except:
                    dns_name = ""

                dns_entry = ip
                ip_mac_host[ip] = {}
                ip_mac_host[ip]["manual_entry_address"] = host
                if len(dns_name) > 0:
                    ip_mac_host[ip]["domain_name"] = dns_name
                    dns_entry = ip+" ("+dns_name+")"
                ip_mac_host[ip]["discovery_type"] = "manual"
                ip_mac_host[ip]["ping_status"] = status
                ip_mac_host[ip]["ip_version"] = ipv

                ip_mac_host[ip]["last_check"] = siaas_aux.get_now_utc_str()

                logger.info(
                    "Found host for manually configured entry '"+host+"': "+dns_entry)

                if not host_up:
                    logger.warning(
                        "The IP "+ip+" for manually configured host '"+host+"' didn't respond to ping.")

    return(ip_mac_host)


def main(interface_to_scan=None, ignore_neighborhood=False):

    auto_hosts = {}
    manual_hosts = {}
    arp_ndp_hosts = {}
    all_hosts = {}
    auto_scanned_interfaces = 0

    if ignore_neighborhood:

        logger.warning(
            "Bypassing discovery of hosts in the neighborhood as per configuration. To change the behavior, set the configuration accordingly.")

    else:

        # Grab known hosts by ARP/NDP
        arp_ndp_hosts = get_arp_ndp_known_hosts()

        # Grab automatically discovered hosts
        logger.info("Starting automatic neighborhood discovery ...")
        for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:

            if interface_to_scan and interface_to_scan != interface:
                continue

            # Skip loopback network and default GW
            if network == 0 or interface.lower() == 'lo' or address == '127.0.0.1' or address == '0.0.0.0' or (not interface.lower().startswith("e") and not interface.lower().startswith("w") and not interface.lower().startswith("b")):
                continue

            # Skip invalid netmasks
            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            net = siaas_aux.to_cidr_notation(network, netmask)
            mask = net.split('/')[1]

            if int(mask) > 16:
                try:
                    arp_timeout = int(siaas_aux.get_config_from_configs_db(
                        config_name="neighborhood_arp_timeout_sec"))
                except:
                    arp_timeout = 5
                    logger.warning(
                        "Invalid or undefined timeout configuration for ARP timeout. Defaulting to \"5\".")
                auto_hosts = dict(list(auto_hosts.items(
                ))+list(scan_and_print_neighbors(net, interface, timeout=arp_timeout).items()))
                auto_scanned_interfaces += 1
            else:
                logger.warning("Skipping network "+net +
                               " as the subnet size is too big.")

        if auto_scanned_interfaces == 0:
            logger.warning(
                "Automatic neighborhood discovery found no interfaces with a valid network configuration to work on.")

    # Grab manual configured hosts
    manual_hosts = add_manual_hosts(
        siaas_aux.get_config_from_configs_db(config_name="manual_hosts"))

    # Merge all hosts (give priority to automatically found hosts in the neighborhood, as they have more info)
    all_hosts = dict(list(manual_hosts.items()) +
                     list(auto_hosts.items())+list(arp_ndp_hosts.items()))

    return all_hosts


def loop(interface_to_scan=None):

    # Initializing the neighborhood local DB
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
    siaas_aux.write_to_local_file(os.path.join(
        sys.path[0], 'var/neighborhood.db'), {})

    while True:

        neighborhood_dict = {}

        logger.debug("Loop running ...")

        ignore_neighborhood = siaas_aux.get_config_from_configs_db(
            config_name="ignore_neighborhood", convert_to_string=True)
        dont_neighborhood = False
        if len(ignore_neighborhood or '') > 0:
            if ignore_neighborhood.lower() == "true":
                dont_neighborhood = True

        # Creating neighborhood dict
        neighborhood_dict = main(
            interface_to_scan=interface_to_scan, ignore_neighborhood=dont_neighborhood)

        # Writing in local database
        siaas_aux.write_to_local_file(os.path.join(
            sys.path[0], 'var/neighborhood.db'), neighborhood_dict)

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="neighborhood_loop_interval_sec"))
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
