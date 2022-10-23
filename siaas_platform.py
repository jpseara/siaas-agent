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

    platform["version"] = version
    platform["uid"] = siaas_aux.get_or_create_unique_system_id()
    platform["last_check"] = siaas_aux.get_now_utc_str()
    platform["platform"] = {}

    # Boot Time
    try:
        boot_time_timestamp = psutil.boot_time()
        bt = datetime.utcfromtimestamp(
            boot_time_timestamp).strftime('%Y-%m-%dT%H:%M:%SZ')
        platform["platform"]["last_boot"] = str(bt)
    except:
        logger.warning("Couldn't grab boot time information. Ignoring.")

    # Platform
    try:
        uname = platform.uname()
        platform["platform"]["system"] = {}
        platform["platform"]["system"]["os"] = uname.system
        platform["platform"]["system"]["node_name"] = uname.node
        platform["platform"]["system"]["kernel"] = uname.release
        platform["platform"]["system"]["flavor"] = uname.version
        platform["platform"]["system"]["arch"] = uname.machine
        platform["platform"]["system"]["processor"] = cpuinfo.get_cpu_info()[
            'brand_raw']
    except:
        logger.warning("Couldn't get platform information. Ignoring.")

    # CPU information
    try:
        platform["platform"]["cpu"] = {}
        platform["platform"]["cpu"]["physical_cores"] = psutil.cpu_count(
            logical=False)
        platform["platform"]["cpu"]["total_cores"] = psutil.cpu_count(
            logical=True)
        cpu_freq = psutil.cpu_freq()
        platform["platform"]["cpu"]["current_freq"] = f'{float(str(cpu_freq.current)):.2f}'+" MHz"
        platform["platform"]["cpu"]["percentage"] = str(psutil.cpu_percent())+" %"
    except:
        logger.warning("Couldn't get CPU information. Ignoring.")

    # Memory Information
    try:
        svmem = psutil.virtual_memory()
        platform["platform"]["memory"] = {}
        platform["platform"]["memory"]["total"] = siaas_aux.get_size(svmem.total)
        platform["platform"]["memory"]["available"] = siaas_aux.get_size(
            svmem.available)
        platform["platform"]["memory"]["used"] = siaas_aux.get_size(svmem.used)
        platform["platform"]["memory"]["percentage"] = str(svmem.percent)+" %"
        swap = psutil.swap_memory()
        platform["platform"]["memory"]["swap"] = {}
        platform["platform"]["memory"]["swap"]["total"] = siaas_aux.get_size(
            swap.total)
        platform["platform"]["memory"]["swap"]["free"] = siaas_aux.get_size(
            swap.free)
        platform["platform"]["memory"]["swap"]["used"] = siaas_aux.get_size(
            swap.used)
        platform["platform"]["memory"]["swap"]["present"] = siaas_aux.get_size(
            swap.total)
    except:
        logger.warning("Couldn't get memory information. Ignoring.")

    # IO and disk statistics
    try:
        # get all disk partitions
        partitions = psutil.disk_partitions()
        platform["platform"]["io"] = {}
        platform["platform"]["io"]["volumes"] = {}
        for partition in partitions:
            if partition.device.startswith("/dev/loop") or "/snap" in partition.mountpoint:
                continue
            else:
                platform["platform"]["io"]["volumes"][partition.device] = {}
                platform["platform"]["io"]["volumes"][partition.device]["partition_mountpoint"] = partition.mountpoint
                platform["platform"]["io"]["volumes"][partition.device]["partition_fstype"] = partition.fstype
                platform["platform"]["io"]["volumes"][partition.device]["usage"] = {}
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    platform["platform"]["io"]["volumes"][partition.device]["usage"]["total"] = siaas_aux.get_size(
                        partition_usage.total)
                    platform["platform"]["io"]["volumes"][partition.device]["usage"]["used"] = siaas_aux.get_size(
                        partition_usage.used)
                    platform["platform"]["io"]["volumes"][partition.device]["usage"]["free"] = siaas_aux.get_size(
                        partition_usage.free)
                    platform["platform"]["io"]["volumes"][partition.device]["usage"]["percentage"] = str(
                        partition_usage.percent)+" %"
                except:
                    pass
        disk_io = psutil.disk_io_counters()
        platform["platform"]["io"]["total_read"] = siaas_aux.get_size(
            disk_io.read_bytes)
        platform["platform"]["io"]["total_written"] = siaas_aux.get_size(
            disk_io.write_bytes)
    except:
        logger.warning("Couldn't get IO statistics. Ignoring.")

    # Network and network interface statistics
    try:
        platform["platform"]["network"] = {}
        platform["platform"]["network"]["interfaces"] = {}
        if_addrs = psutil.net_if_addrs()
        for interface_name, interface_addresses in if_addrs.items():
            if interface_name.startswith('docker') or interface_name.startswith('br-') or interface_name.startswith('tun') or interface_name == 'lo':
                continue
            list_addr_mask = []
            platform["platform"]["network"]["interfaces"][interface_name] = []
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
                platform["platform"]["network"]["interfaces"][interface_name] = list_addr_mask
        net_io = psutil.net_io_counters()
        platform["platform"]["network"]["total_sent"] = siaas_aux.get_size(
            net_io.bytes_sent)
        platform["platform"]["network"]["total_received"] = siaas_aux.get_size(
            net_io.bytes_recv)
    except:
        logger.warning(
            "Couldnt get network information and statistics. Ignoring.")

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
