# Contains pieces of the post from Abdou Rockikz named "How to Get Hardware and System Information in Python" in PythonCode - https://www.thepythoncode.com/article/get-hardware-system-information-python
# By João Pedro Seara

import siaas_aux
import psutil
import platform
import cpuinfo
import socket
import re
import time
import sys
import os
import json
import ipaddress
import logging
import pprint
from datetime import datetime

logger = logging.getLogger(__name__)


def main(version="N/A"):

    logger.info("Grabbing agent information for this platform ...")

    agent = {}

    agent["version"] = version
    agent["uid"] = siaas_aux.get_or_create_unique_system_id()
    agent["last_check"] = siaas_aux.get_now_utc_str()
    agent["platform"] = {}

    # Boot Time
    try:
        boot_time_timestamp = psutil.boot_time()
        bt = datetime.utcfromtimestamp(
            boot_time_timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')
        agent["platform"]["last_boot"] = str(bt)
    except:
        logger.warning("Couldn't grab boot time information. Ignoring.")

    # Platform
    try:
        uname = platform.uname()
        agent["platform"]["system"] = {}
        agent["platform"]["system"]["os"] = uname.system
        agent["platform"]["system"]["node_name"] = uname.node
        agent["platform"]["system"]["kernel"] = uname.release
        agent["platform"]["system"]["flavor"] = uname.version
        agent["platform"]["system"]["arch"] = uname.machine
        agent["platform"]["system"]["processor"] = cpuinfo.get_cpu_info()[
            'brand_raw']
    except:
        logger.warning("Couldn't get platform information. Ignoring.")

    # CPU information
    try:
        agent["platform"]["cpu"] = {}
        agent["platform"]["cpu"]["physical_cores"] = psutil.cpu_count(
            logical=False)
        agent["platform"]["cpu"]["total_cores"] = psutil.cpu_count(
            logical=True)
        cpu_freq = psutil.cpu_freq()
        agent["platform"]["cpu"]["current_freq"] = f'{float(str(cpu_freq.current)):.2f}'+" MHz"
        agent["platform"]["cpu"]["percentage"] = str(psutil.cpu_percent())+" %"
    except:
        logger.warning("Couldn't get CPU information. Ignoring.")

    # Memory Information
    try:
        svmem = psutil.virtual_memory()
        agent["platform"]["memory"] = {}
        agent["platform"]["memory"]["total"] = siaas_aux.get_size(svmem.total)
        agent["platform"]["memory"]["available"] = siaas_aux.get_size(
            svmem.available)
        agent["platform"]["memory"]["used"] = siaas_aux.get_size(svmem.used)
        agent["platform"]["memory"]["percentage"] = str(svmem.percent)+" %"
        swap = psutil.swap_memory()
        agent["platform"]["memory"]["swap"] = {}
        agent["platform"]["memory"]["swap"]["total"] = siaas_aux.get_size(
            swap.total)
        agent["platform"]["memory"]["swap"]["free"] = siaas_aux.get_size(
            swap.free)
        agent["platform"]["memory"]["swap"]["used"] = siaas_aux.get_size(
            swap.used)
        agent["platform"]["memory"]["swap"]["present"] = siaas_aux.get_size(
            swap.total)
        agent["platform"]["memory"]["swap"] = {}
    except:
        logger.warning("Couldn't get memory information. Ignoring.")

    # IO and disk statistics
    try:
        # get all disk partitions
        partitions = psutil.disk_partitions()
        agent["platform"]["io"] = {}
        agent["platform"]["io"]["volumes"] = {}
        for partition in partitions:
            if partition.device.startswith("/dev/loop"):
                continue
            else:
                agent["platform"]["io"]["volumes"][partition.device] = {}
                agent["platform"]["io"]["volumes"][partition.device]["partition_mountpoint"] = partition.mountpoint
                agent["platform"]["io"]["volumes"][partition.device]["partition_fstype"] = partition.fstype
                agent["platform"]["io"]["volumes"][partition.device]["usage"] = {}
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    agent["platform"]["io"]["volumes"][partition.device]["usage"]["total"] = siaas_aux.get_size(
                        partition_usage.total)
                    agent["platform"]["io"]["volumes"][partition.device]["usage"]["used"] = siaas_aux.get_size(
                        partition_usage.used)
                    agent["platform"]["io"]["volumes"][partition.device]["usage"]["free"] = siaas_aux.get_size(
                        partition_usage.free)
                    agent["platform"]["io"]["volumes"][partition.device]["usage"]["percentage"] = str(
                        partition_usage.percent)+" %"
                except:
                    pass
        disk_io = psutil.disk_io_counters()
        agent["platform"]["io"]["total_read"] = siaas_aux.get_size(
            disk_io.read_bytes)
        agent["platform"]["io"]["total_write"] = siaas_aux.get_size(
            disk_io.write_bytes)
    except:
        logger.warning("Couldn't get IO statistics. Ignoring.")

    # Network and network interface statistics
    try:
        agent["platform"]["network"] = {}
        agent["platform"]["network"]["interfaces"] = {}
        if_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in if_addrs.items():
            if interface_name.startswith('docker') or interface_name.startswith('br-') or interface_name.startswith('tun') or interface_name == 'lo':
                continue
            list_addr_mask = []
            agent["platform"]["network"]["interfaces"][interface_name] = {}
            for address in interface_addresses:
                if str(address.family) == 'AddressFamily.AF_INET':
                    if interface_name not in address.address:
                        mask_prefix = ipaddress.IPv4Network(
                            "0.0.0.0/"+address.netmask).prefixlen
                        list_addr_mask.append(
                            address.address+"/"+str(mask_prefix))
                if str(address.family) == 'AddressFamily.AF_INET6':
                    if interface_name not in address.address:
                        mask_prefix = siaas_aux.get_ipv6_cidr(address.netmask)
                        list_addr_mask.append(
                            address.address+"/"+str(mask_prefix))
            if len(list_addr_mask) > 0:
                agent["platform"]["network"]["interfaces"][interface_name] = list_addr_mask
        net_io = psutil.net_io_counters()
        agent["platform"]["network"]["total_sent"] = siaas_aux.get_size(
            net_io.bytes_sent)
        agent["platform"]["network"]["total_received"] = siaas_aux.get_size(
            net_io.bytes_recv)
    except:
        logger.warning(
            "Couldnt get network information and statistics. Ignoring.")

    return agent


def loop(version=""):

    # Initializing the agent local DB
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
    siaas_aux.write_to_local_file(
        os.path.join(sys.path[0], 'var/agent.db'), {})

    while True:

        agent_dict = {}

        logger.debug("Loop running ...")

        agent_dict = main(version)

        # Writing in local database
        siaas_aux.write_to_local_file(os.path.join(
            sys.path[0], 'var/agent.db'), agent_dict)

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="agent_info_loop_interval_sec"))
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

    print('\n')
    output = main()
    print('\nOutput is:\n')
    pprint.pprint(output)

    print('\nAll done. Bye!\n')
