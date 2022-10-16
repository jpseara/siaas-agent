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

def merge_module_dicts_under_uuid(siaas_uuid="00000000-0000-0000-0000-000000000000", module_list=[]):
    merged_dict={}
    merged_dict[siaas_uuid]={}
    for module in module_list:
       try:
         next_dict_to_merge={}
         next_dict_to_merge[module]={}
         next_dict_to_merge[module]=read_from_local_file(os.path.join(sys.path[0],'var/'+str(module)+'.db'))
         merged_dict[siaas_uuid]=dict(list(merged_dict[siaas_uuid].items())+list(next_dict_to_merge.items()))
       except:
            logger.warning("Couldn't merge dict: "+str(next_dict_to_merge))
    return merged_dict

def get_config_from_configs_db(config_name=None):

    if config_name==None:
    
       logger.debug("Getting configuration dictionary from local DB ...")
       config_dict=read_from_local_file(os.path.join(sys.path[0],'var/config.db'))
       if len(config_dict or '') > 0:
           return config_dict

       logger.error("Couldn't get configuration dictionary from local DB.")
       return {}

    else:
       
       logger.debug("Getting configuration value '"+config_name+"' from local DB ...")
       config_dict=read_from_local_file(os.path.join(sys.path[0],'var/config.db'))
       if len(config_dict or '') > 0:
           if config_name in config_dict.keys():
               return config_dict[config_name]
       
       logger.warning("Couldn't get configuration named '"+config_name+"' from local DB. Maybe it doesn't exist.")
       return None

def write_config_db_from_conf_file(conf_file=os.path.join(sys.path[0],'conf/siaas_agent.cnf')):

    logger.debug("Writing configuration local DB, from local file: "+conf_file)

    config_dict={}

    local_conf_file = read_from_local_file(conf_file)
    if len(local_conf_file or '') == 0:
          return False

    for line in local_conf_file.splitlines():
       try:
          line_uncommented=line.split('#')[0].rstrip().lstrip()
          if len(line_uncommented)==0:
             continue
          config_name=line_uncommented.split("=",1)[0].lower().rstrip().lstrip().replace("\"","").replace("\'","")
          config_value=line_uncommented.split("=",1)[1].rstrip().lstrip()
          config_dict[config_name]=config_value
       except:
          logger.warning("Invalid line from local config file: "+str(line))
          continue

    return write_to_local_file(os.path.join(sys.path[0],'var/config.db'), config_dict)

def read_mongodb_collection(collection, siaas_uuid="00000000-0000-0000-0000-000000000000"):
   logger.info("Reading data from the remote DB server ...")
   try:

      if(siaas_uuid=="00000000-0000-0000-0000-000000000000"):
          #cursor = collection.find() # show all raw
          cursor = collection.find().sort("_id", -1).limit(5) # show only most recent raw
          #cursor = collection.find({},{'_id': False, 'direction': False, 'timestamp': False}).sort("_id", -1).limit(5) # show only most recent, hide object id, direction and timestamp
      else:
          #cursor = collection.find({siaas_uuid: {'$exists': True}}) # show all
          #cursor = collection.find({siaas_uuid: {'$exists': True}},{'_id': False, 'direction': False, 'timestamp': False}) # show all, hide object id, direction and timestamp
          cursor = collection.find({siaas_uuid: {'$exists': True}}).sort("_id", -1).limit(5) # show only most recent
          #cursor = collection.find({siaas_uuid+"."+"portscanner": {'$exists': True}},{'_id': False, 'direction': False, 'timestamp': False}).sort("_id", -1).limit(5) # show only most recent that has the subkey 'portscanner', hide object id, direction and timestamp
          #cursor = collection.find({siaas_uuid+"."+"agent"+"."+"platform"+"."+"system"+"."+"os": "Linux" },{'_id': False, 'direction': False, 'timestamp': False}).sort("_id", -1).limit(5) # show only most recent for agents running on Linux, hide object id, direction and timestamp
          #cursor = collection.find({siaas_uuid: {'$exists': True}},{'_id': False, 'direction': False, 'timestamp': False}).sort("_id", -1).limit(5) # show only most recent, hide object id, direction and timestamp

      results=list(cursor)
      for doc in results:
          logger.debug("Record read: "+str(doc))
      return results
   except Exception as e:
      logger.error("Can't read data from remote DB server: "+str(e))
      return None

def insert_in_mongodb_collection(collection, data_to_insert):
   logger.info("Inserting data in the remote DB server ...")
   try:
      logger.debug("All data that will now be written to the database:\n" + pprint.pformat(data_to_insert))
      collection.insert_one(copy(data_to_insert))
      logger.info("Data successfully uploaded to the remote DB server.")
      return True
   except Exception as e:
      logger.error("Can't upload data to remote DB server: "+str(e))
      return False

def connect_mongodb_collection(mongo_user="siaas", mongo_password="siaas", mongo_host="127.0.0.1:27017", mongo_db="siaas", mongo_collection="agents"):
   logger.info("Connecting to remote DB server at "+str(mongo_host)+" ...")
   try:
      uri = "mongodb://%s:%s@%s/%s" % (quote_plus(mongo_user), quote_plus(mongo_password), mongo_host, mongo_db)
      client = MongoClient(uri)
      db = client[mongo_db]
      collection = db[mongo_collection]
      logger.info("Correctly configured the remote DB server connection to collection '"+mongo_collection+"'.")
      return collection
   except Exception as e:
      logger.error("Can't connect to remote DB server: "+str(e))
      return None

def write_to_local_file(file_to_write, data_to_insert):
    logger.info("Inserting data to local file "+file_to_write+" ...")
    try:
       logger.debug("All data that will now be written to the file:\n" + pprint.pformat(data_to_insert))
       with open(file_to_write, 'w') as file:
          file.write(json.dumps(data_to_insert))
          logger.info("Local file write ended successfully.")
          return True
    except Exception as e:
       logger.error("There was an error while writing to the local file "+file_to_write+": "+str(e))
       return False

def read_from_local_file(file_to_read):
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
       logger.error("There was an error reading from local file "+file_to_read+": "+str(e))
       return None

def get_or_create_unique_system_id():
   logger.debug("Searching for an existing UUID and creating a new one if it doesn't exist ...")
   try:
      with open(os.path.join(sys.path[0],'var/uuid'), 'r') as file:
          content = file.read()
          if len(content or '') == 0:
              raise
          if content.split('\n')[0] == "ffffffff-ffff-ffff-ffff-ffffffffffff":
              logger.warning("Invalid ID, reserved for broadcast. Returning a nil UUID.")
              return "00000000-0000-0000-0000-000000000000"
          logger.debug("Reusing existing UUID: "+str(content))
          return content.split('\n')[0]
   except:
      pass
   new_uuid=""
   try:
      with open("/sys/class/dmi/id/board_serial", 'r') as file:
          content = file.read()
          new_uuid=content.split('\n')[0]
   except:
      pass
   if len(new_uuid) == 0:
      try:
          with open("/sys/class/dmi/id/product_uuid", 'r') as file:
             content = file.read()
             new_uuid=content.split('\n')[0]
      except:
          pass
   if len(new_uuid) == 0:
      try:
          with open("/var/lib/dbus/machine-id", 'r') as file:
              content = file.read()
              new_uuid=content.split('\n')[0]
      except:
          pass
   if len(new_uuid) == 0:
       try:
          new_uuid=str(uuid.UUID(int=uuid.getnode()))
       except:
          logger.error("There was an error while generating a new UUID. Returning a nil UUID.")
          return "00000000-0000-0000-0000-000000000000"
   try:
      with open(os.path.join(sys.path[0],'var/uuid'), 'w') as file:
          file.write(new_uuid)
          logger.debug("Wrote new UUID to a local file: "+new_uuid)
   except Exception as e:
      logger.error("There was an error while writing to the local UUID file: "+str(e)+". Returning a nil UUID.")
      return "00000000-0000-0000-0000-000000000000"
   return new_uuid

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
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

def get_now_utc_obj():
    return  datetime.strptime(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),'%Y-%m-%dT%H:%M:%SZ')

def is_ipv4_or_ipv6(ip):

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

   bitCount = [0, 0x8000, 0xc000, 0xe000, 0xf000, 0xf800, 0xfc00, 0xfe00, 0xff00, 0xff80, 0xffc0, 0xffe0, 0xfff0, 0xfff8, 0xfffc, 0xfffe, 0xffff]
   count = 0
   try:
      for w in mask.split(':'):
         if not w or int(w, 16) == 0:
            break
         count += bitCount.index(int(w, 16))
   except:
       raise SyntaxError("Bad IPv6 netmask: "+mask)
   return count

def get_all_ips_for_name(host):

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

    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("Illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

def to_cidr_notation(bytes_network, bytes_netmask):

    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)

    return net

if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    #print(str(write_config_db_from_conf_file()))
    print(str(get_config_from_configs_db()))
