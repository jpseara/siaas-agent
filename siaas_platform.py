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

    logger.info("Grabbing hardware information for this platform ...")

    platform = {}

    platform["uid"] = siaas_aux.get_or_create_unique_system_id()
    platform["version"] = version
    platform["system_info"] = {}

    # Platform
    try:
        uname = platform.uname()
        platform["system_info"]["system"] = {}
        platform["system_info"]["system"]["os"] = uname.system
        platform["system_info"]["system"]["node_name"] = uname.node
        platform["system_info"]["system"]["kernel"] = uname.release
        platform["system_info"]["system"]["flavor"] = uname.version
        platform["system_info"]["system"]["arch"] = uname.machine
        platform["system_info"]["system"]["processor"] = cpuinfo.get_cpu_info()[
            'brand_raw']
    except:
        logger.warning("Couldn't get platform information. Ignoring.")

    # CPU information
    try:
        platform["system_info"]["cpu"] = {}
        platform["system_info"]["cpu"]["percentage"] = str(psutil.cpu_percent())+" %"
        platform["system_info"]["cpu"]["physical_cores"] = psutil.cpu_count(
            logical=False)
        platform["system_info"]["cpu"]["total_cores"] = psutil.cpu_count(
            logical=True)
        cpu_freq = psutil.cpu_freq()
        platform["system_info"]["cpu"]["current_freq"] = f'{float(str(cpu_freq.current)):.2f}'+" MHz"
    except:
        logger.warning("Couldn't get CPU information. Ignoring.")

    # Memory Information
    try:
        svmem = psutil.virtual_memory()
        platform["system_info"]["memory"] = {}
        platform["system_info"]["memory"]["percentage"] = str(svmem.percent)+" %"
        platform["system_info"]["memory"]["total"] = siaas_aux.get_size(svmem.total)
        platform["system_info"]["memory"]["used"] = siaas_aux.get_size(svmem.used)
        platform["system_info"]["memory"]["available"] = siaas_aux.get_size(svmem.available)
        swap = psutil.swap_memory()
        platform["system_info"]["memory"]["swap"] = {}
        platform["system_info"]["memory"]["swap"]["percentage"] = str(swap.percent)+" %"
        platform["system_info"]["memory"]["swap"]["total"] = siaas_aux.get_size(
            swap.total)
        platform["system_info"]["memory"]["swap"]["used"] = siaas_aux.get_size(
            swap.used)
        platform["system_info"]["memory"]["swap"]["free"] = siaas_aux.get_size(
            swap.free)
    except:
        logger.warning("Couldn't get memory information. Ignoring.")

    # IO and disk statistics
    try:
        # get all disk partitions
        partitions = psutil.disk_partitions()
        platform["system_info"]["io"] = {}
        platform["system_info"]["io"]["volumes"] = {}
        for partition in partitions:
            if partition.device.startswith("/dev/loop") or "/snap" in partition.mountpoint:
                continue
            else:
                platform["system_info"]["io"]["volumes"][partition.device] = {}
                platform["system_info"]["io"]["volumes"][partition.device]["partition_mountpoint"] = partition.mountpoint
                platform["system_info"]["io"]["volumes"][partition.device]["partition_fstype"] = partition.fstype
                platform["system_info"]["io"]["volumes"][partition.device]["usage"] = {}
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    platform["system_info"]["io"]["volumes"][partition.device]["usage"]["percentage"] = str(
                        partition_usage.percent)+" %"
                    platform["system_info"]["io"]["volumes"][partition.device]["usage"]["total"] = siaas_aux.get_size(
                        partition_usage.total)
                    platform["system_info"]["io"]["volumes"][partition.device]["usage"]["used"] = siaas_aux.get_size(
                        partition_usage.used)
                    platform["system_info"]["io"]["volumes"][partition.device]["usage"]["free"] = siaas_aux.get_size(
                        partition_usage.free)
                except:
                    pass
        disk_io = psutil.disk_io_counters()
        platform["system_info"]["io"]["total_read"] = siaas_aux.get_size(
            disk_io.read_bytes)
        platform["system_info"]["io"]["total_written"] = siaas_aux.get_size(
            disk_io.write_bytes)
    except:
        logger.warning("Couldn't get IO statistics. Ignoring.")

    # Network and network interface statistics
    try:
        platform["system_info"]["network"] = {}
        platform["system_info"]["network"]["interfaces"] = {}
        if_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in if_addrs.items():
            if interface_name.startswith('docker') or interface_name.startswith('br-') or interface_name.startswith('tun') or interface_name == 'lo':
                continue
            list_addr_mask = []
            platform["system_info"]["network"]["interfaces"][interface_name] = []
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
                platform["system_info"]["network"]["interfaces"][interface_name] = list_addr_mask
        net_io = psutil.net_io_counters()
        platform["system_info"]["network"]["total_received"] = siaas_aux.get_size(
            net_io.bytes_recv)
        platform["system_info"]["network"]["total_sent"] = siaas_aux.get_size(
            net_io.bytes_sent)
    except:
        logger.warning(
            "Couldnt get network information and statistics. Ignoring.")

    # Boot Time
    try:
        boot_time_timestamp = psutil.boot_time()
        bt = datetime.utcfromtimestamp(
            boot_time_timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')
        platform["system_info"]["last_boot"] = str(bt)
    except:
        logger.warning("Couldn't grab boot time information. Ignoring.")

    platform["last_check"] = siaas_aux.get_now_utc_str()

    return platform


def loop(version=""):

    # Initializing the platform local DB
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
    siaas_aux.write_to_local_file(
        os.path.join(sys.path[0], 'var/platform.db'), {})

    while True:

        platform_dict = {}

        logger.debug("Loop running ...")

        platform_dict = main(version)

        # Writing in local database
        siaas_aux.write_to_local_file(os.path.join(
            sys.path[0], 'var/platform.db'), platform_dict)

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="platform_loop_interval_sec"))
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