import ipaddress
import scapy.config
import scapy.layers.l2
import scapy.route
import math
import dns.resolver
import pprint
import logging
import uuid
import os
import sys
import json
from copy import copy
from datetime import datetime
from pymongo import MongoClient
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)


def merge_module_dicts(module_list=[]):
    """
    Grabs all DB files from the module list and concatenate them
    Returns an empty dict if it fails 
    """
    merged_dict = {}
    for module in module_list:
        try:
            next_dict_to_merge = {}
            next_dict_to_merge[module] = {}
            next_dict_to_merge[module] = read_from_local_file(
                os.path.join(sys.path[0], 'var/'+str(module)+'.db'))
            merged_dict = dict(
                list(merged_dict.items())+list(next_dict_to_merge.items()))
        except:
            logger.warning("Couldn't merge upstream dict: " +
                           str(next_dict_to_merge))
    return merged_dict


def merge_configs_from_upstream(local_dict=os.path.join(sys.path[0], 'var/config_orig.db'), output=os.path.join(sys.path[0], 'var/config.db'), upstream_dict={}):
    """
    Merges the configs downloaded from the server to the current configs DB
    """
    merged_config_dict = {}
    try:
        current_config_dict = get_config_from_configs_db(local_dict=local_dict)
        merged_config_dict = dict(
            list(current_config_dict.items())+list(upstream_dict.items()))
    except:
        logger.error(
            "Could not merge configurations from remote server with the local configs.")
    return write_to_local_file(output, merged_config_dict)


def get_config_from_configs_db(local_dict=os.path.join(sys.path[0], 'var/config.db'), config_name=None):
    """
    Reads a configuration value from the configs db
    If the intput is "None" it returns an entire dict with all the values. Returns an empty dict if there are no configs
    If the input is a specific config key, it returns the value for that config key. Returns None if the config key does not exist
    """
    if config_name == None:

        logger.debug("Getting configuration dictionary from local DB ...")
        config_dict = read_from_local_file(
            local_dict)
        if len(config_dict or '') > 0:
            return config_dict

        logger.error("Couldn't get configuration dictionary from local DB.")
        return {}

    else:

        logger.debug("Getting configuration value '" +
                     config_name+"' from local DB ...")
        config_dict = read_from_local_file(
            local_dict)
        if len(config_dict or '') > 0:
            if config_name in config_dict.keys():
                return config_dict[config_name]

        logger.debug("Couldn't get configuration named '" +
                     config_name+"' from local DB. Maybe it doesn't exist.")
        return None


def write_config_db_from_conf_file(conf_file=os.path.join(sys.path[0], 'conf/siaas_agent.cnf'), output=os.path.join(sys.path[0], 'var/config.db')):
    """
    Writes the configuration DB (dict) from the config file. If the file is empty or does not exist, returns False
    It will strip all characters after '#', and then strip the spaces from the beginning or end of the resulting string. If the resulting string is empty, it will ignore it
    Then, it will grab the string before the first "=" as the config key, and after it as the actual value
    The config key is then converted to lowercase, spaces removed from beginning or end, and all " and ' are removed.
    The actual value is just stripped of spaces from the beginning and the end
    Writes the resulting dict in the DB file of config.db. This means it will return True if things go fine, or False if it fails
    """

    logger.debug("Writing configuration local DB, from local file: "+conf_file)

    config_dict = {}

    local_conf_file = read_from_local_file(conf_file)
    if len(local_conf_file or '') == 0:
        return False

    for line in local_conf_file.splitlines():
        try:
            line_uncommented = line.split('#')[0].rstrip().lstrip()
            if len(line_uncommented) == 0:
                continue
            config_name = line_uncommented.split("=", 1)[0].lower(
            ).rstrip().lstrip().replace("\"", "").replace("\'", "")
            config_value = line_uncommented.split("=", 1)[1].rstrip().lstrip()
            config_dict[config_name] = config_value
        except:
            logger.warning("Invalid line from local config file: "+str(line))
            continue

    return write_to_local_file(output, config_dict)


def read_mongodb_collection(collection, siaas_uid="00000000-0000-0000-0000-000000000000"):
    """
    Reads data from the Mongo DB collection
    If the UID is "nil" it will return all records. Else, it will return records only for the inputted UID
    Returns a list of records. Returns None if data can't be read
    """
    logger.info("Reading data from the remote DB server ...")
    try:

        if(siaas_uid == "00000000-0000-0000-0000-000000000000"):
            # cursor = collection.find() # show all raw
            cursor = collection.find().sort('_id', -1).limit(5)  # show only most recent raw
            # cursor = collection.find({},{'_id': False}).sort('_id', -1).limit(5) # show only most recent, hide object id, direction and timestamp
        else:
            # cursor = collection.find({"payload": {'$exists': True}}).sort('_id', -1) # show most recent first
            cursor = collection.find({"payload": {'$exists': True}}).sort(
                '_id', -1).limit(5)  # show only the 5 most recent
            # cursor = collection.find({"payload": {'$exists': True}, "origin":"agent_"+siaas_uid},{'_id': False}).sort('_id', -1).limit(5) # same, but only for the UID of this agent
            # cursor = collection.find({"payload.agent.platform.system.os": "Linux" },{'_id': False}).sort('_id', -1).limit(5) # show only most recent for agents running on Linux

        results = list(cursor)
        for doc in results:
            logger.debug("Record read: "+str(doc))
        return results
    except Exception as e:
        logger.error("Can't read data from remote DB server: "+str(e))
        return None


def read_published_data_for_agents_mongodb(collection, siaas_uid="00000000-0000-0000-0000-000000000000", scope="agent_configs"):
    """
    Reads data from the Mongo DB collection, specifically published by the server, for agents
    Returns a config dict. Returns an empty dict if anything failed
    """
    my_configs = {}
    broadcasted_configs = {}
    final_results = {}
    logger.info("Reading data from the remote DB server ...")
    try:
        cursor = collection.find({"payload": {'$exists': True}, "destiny": "agent_"+siaas_uid, "scope": scope}, {'_id': False,
                                                                                                                  'timestamp': False, 'origin': False, 'destiny': False, 'scope': False}).sort('_id', -1).limit(1)  # show most recent first
        results1 = list(cursor)
        for doc in results1:
            my_configs = doc["payload"]
        cursor = collection.find({"payload": {'$exists': True}, "destiny": "agent_"+"ffffffff-ffff-ffff-ffff-ffffffffffff", "scope": scope}, {
                                 '_id': False, 'timestamp': False, 'origin': False, 'destiny': False, 'scope': False}).sort('_id', -1).limit(1)  # show most recent first
        results2 = list(cursor)
        for doc in results2:
            broadcasted_configs = doc["payload"]
        final_results = dict(
            list(broadcasted_configs.items())+list(my_configs.items()))
        logger.debug("Records read from the server: "+str(final_results))
    except Exception as e:
        logger.error("Can't read data from remote DB server: "+str(e))
    return final_results


def insert_in_mongodb_collection(collection, data_to_insert):
    """
    Inserts data (usually a dict) into a said collection
    Returns True if all was OK. Returns False if the insertion failed
    """
    logger.info("Inserting data in the remote DB server ...")
    try:
        logger.debug("All data that will now be written to the database:\n" +
                     pprint.pformat(data_to_insert))
        collection.insert_one(copy(data_to_insert))
        logger.info("Data successfully uploaded to the remote DB server.")
        return True
    except Exception as e:
        logger.error("Can't upload data to remote DB server: "+str(e))
        return False


def connect_mongodb_collection(mongo_user="siaas", mongo_password="siaas", mongo_host="127.0.0.1:27017", mongo_db="siaas", mongo_collection="siaas"):
    """
    Set up a MongoDB collection connection based on the inputs
    Returns the collection obj if succeeded. Returns None if it failed
    """
    logger.info("Connecting to remote DB server at "+str(mongo_host)+" ...")
    try:
        uri = "mongodb://%s:%s@%s/%s" % (quote_plus(mongo_user),
                                         quote_plus(mongo_password), mongo_host, mongo_db)
        client = MongoClient(uri)
        db = client[mongo_db]
        collection = db[mongo_collection]
        logger.info(
            "Correctly configured the remote DB server connection to collection '"+mongo_collection+"'.")
        return collection
    except Exception as e:
        logger.error("Can't connect to remote DB server: "+str(e))
        return None


def write_to_local_file(file_to_write, data_to_insert):
    """
    Writes data (usually a dict) to a local file, after converting it to a JSON format
    Returns True if all went OK
    Returns False if it failed
    """
    logger.info("Inserting data to local file "+file_to_write+" ...")
    try:
        os.makedirs(os.path.dirname(os.path.join(
            sys.path[0], file_to_write)), exist_ok=True)
        logger.debug("All data that will now be written to the file:\n" +
                     pprint.pformat(data_to_insert))
        with open(file_to_write, 'w') as file:
            file.write(json.dumps(data_to_insert))
            logger.info("Local file write ended successfully.")
            return True
    except Exception as e:
        logger.error(
            "There was an error while writing to the local file "+file_to_write+": "+str(e))
        return False


def read_from_local_file(file_to_read):
    """
    Reads data from local file and returns it
    It will return None if it failed
    """
    logger.info("Reading from local file "+file_to_read+" ...")
    try:
        with open(file_to_read, 'r') as file:
            content = file.read()
            try:
                content = eval(content)
            except:
                pass
            return content
    except Exception as e:
        logger.error("There was an error reading from local file " +
                     file_to_read+": "+str(e))
        return None


def get_or_create_unique_system_id():
    """
    Reads the local UID file and returns it
    If this file does not exist or has no data, continues to generate an UID. If it has an invalid UID, it will return a nil UID
    Proceeds to try to generate an UID from local system data
    If this fails, generates a random one
    If all fails, returns a nil UID
    """
    logger.debug(
        "Searching for an existing UID and creating a new one if it doesn't exist ...")
    try:
        with open(os.path.join(sys.path[0], 'var/uid'), 'r') as file:
            content = file.read()
            if len(content or '') == 0:
                raise IOError(
                    "Nothing valid could be read from local UID file.")
            if content.split('\n')[0] == "ffffffff-ffff-ffff-ffff-ffffffffffff":
                logger.warning(
                    "Invalid ID, reserved for broadcast. Returning a nil UID.")
                return "00000000-0000-0000-0000-000000000000"
            logger.debug("Reusing existing UID: "+str(content))
            return content.split('\n')[0]
    except:
        pass
    logger.debug(
        "Existing UID not found. Creating a new one from system info ...")
    new_uid = ""
    try:
        with open("/sys/class/dmi/id/board_serial", 'r') as file:
            content = file.read()
            new_uid = content.split('\n')[0]
    except:
        pass
    if len(new_uid) == 0:
        try:
            with open("/sys/class/dmi/id/product_uuid", 'r') as file:
                content = file.read()
                new_uid = content.split('\n')[0]
        except:
            pass
    if len(new_uid) == 0:
        try:
            with open("/var/lib/dbus/machine-id", 'r') as file:
                content = file.read()
                new_uid = content.split('\n')[0]
        except:
            pass
    if len(new_uid) == 0:
        logger.warning(
            "Couldn't create a new UID from the system info. Creating a new one on-the-fly ...")
        try:
            new_uid = str(uuid.UUID(int=uuid.getnode()))
        except:
            logger.error(
                "There was an error while generating a new UID. Returning a nil UID.")
            return "00000000-0000-0000-0000-000000000000"
    try:
        os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)
        with open(os.path.join(sys.path[0], 'var/uid'), 'w') as file:
            file.write(new_uid)
            logger.debug("Wrote new UID to a local file: "+new_uid)
    except Exception as e:
        logger.error("There was an error while writing to the local UID file: " +
                     str(e)+". Returning a nil UID.")
        return "00000000-0000-0000-0000-000000000000"
    return new_uid


def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f} {unit}{suffix}"
        bytes /= factor


def get_now_utc_str():
    """
    Returns an ISO date string
    """
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def get_now_utc_obj():
    """
    Returns an ISO date obj
    """
    return datetime.strptime(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'), '%Y-%m-%dT%H:%M:%SZ')


def is_ipv4_or_ipv6(ip):
    """
    Returns "6" if input IP is IPv6
    Returns "4" if input IP is IPv4
    Else returns None
    """
    try:
        ipaddress.IPv4Network(ip)
        return "4"
    except:
        pass
    try:
        ipaddress.IPv6Network(ip)
        return "6"
    except:
        return None


def get_ipv6_cidr(mask):
    """
    Returns the IPv6 short netmask from a long netmask input
    Returns None if inputted mask is not proper
    """
    bitCount = [0, 0x8000, 0xc000, 0xe000, 0xf000, 0xf800, 0xfc00, 0xfe00,
                0xff00, 0xff80, 0xffc0, 0xffe0, 0xfff0, 0xfff8, 0xfffc, 0xfffe, 0xffff]
    count = 0
    try:
        for w in mask.split(':'):
            if not w or int(w, 16) == 0:
                break
            count += bitCount.index(int(w, 16))
    except:
        return None
        logger.warning("Bad IPv6 netmask: "+mask)
    return count


def get_all_ips_for_name(host):
    """
    Checks all registered DNS IPs for a said host and returns them in a set
    If the input is already an IP address, returns it
    Returns an empty set if no IPs are found 
    """
    ips = set()

    # Check if the host is already an IP and return it
    try:
        ipaddress.IPv4Network(host)
        ips.add(host)
        return ips
    except:
        pass
    try:
        ipaddress.IPv6Network(host)
        ips.add(host)
        return ips
    except:
        pass

    # IPv4 name resolution
    try:
        result = dns.resolver.resolve(host, "A")
        for ipval in result:
            ips.add(ipval.to_text())
    except:
        pass

    # IPv6 name resolution
    try:
        result6 = dns.resolver.resolve(host, "AAAA")
        for ipval in result6:
            ips.add(ipval.to_text())
    except:
        pass

    return ips


def long2net(arg):
    """
    Converts an hexadecimal IPv4 netmask to a 0-32 integer
    """
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("Illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_cidr_notation(bytes_network, bytes_netmask):
    """
    Converts a network and network mask inputs in bytes to a network/short_mask IPv4 CIDR notation
    """
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)

    return net


if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    # print(str(write_config_db_from_conf_file()))
    print(str(get_config_from_configs_db()))
