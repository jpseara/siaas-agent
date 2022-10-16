import siaas_aux
import logging
import os
import sys
import pprint
import time
from datetime import datetime
from copy import copy

logger = logging.getLogger(__name__)

def upload_agent_data(siaas_uuid="00000000-0000-0000-0000-000000000000", db_collection=None, last_uploaded_dict={}):
   
   if db_collection == None:
      logger.error("No valid DB collection object received. Bypassed remote DB data upload.")
      return last_uploaded_dict

   current_dict={}
   current_dict[siaas_uuid]={}

   # Grab agent data
   agent = siaas_aux.read_from_local_file(os.path.join(sys.path[0],'var/agent.db'))
   if len(agent or '') ==0:
      agent={}

   # Grab neighbourhood data
   neighbourhood = siaas_aux.read_from_local_file(os.path.join(sys.path[0],'var/neighbourhood.db'))
   if len(neighbourhood or '') ==0:
      neighbourhood={}

   # Grab portscanner data
   portscanner = siaas_aux.read_from_local_file(os.path.join(sys.path[0],'var/portscanner.db'))
   if len(portscanner or '') ==0:
      portscanner={}

   current_dict[siaas_uuid]["agent"]=agent
   current_dict[siaas_uuid]["neighbourhood"]=neighbourhood
   current_dict[siaas_uuid]["portscanner"]=portscanner

   if (str(current_dict) == str(last_uploaded_dict)) or len(current_dict)==0:
      logger.info("No changes were detected in local databases, so there's nothing to upload to the remote DB server. Will check again later ...")
      return last_uploaded_dict

   # Creating a new dict with a date object so we can easily filter it and order entries in MongoDB
   complete_dict=dict(current_dict)
   complete_dict["timestamp"] = siaas_aux.get_now_utc_obj()

   ret_db=False
   if db_collection != None:
      ret_db=siaas_aux.insert_in_mongodb_collection(db_collection, complete_dict)
      if ret_db:
          return current_dict
   
   return last_uploaded_dict

   #siaas_aux.read_mongodb_collection(db_collection, siaas_uuid)

def loop(siaas_uuid="00000000-0000-0000-0000-000000000000"):

   db_collection=None
   last_uploaded_dict={}
   last_downloaded_dict={}

   # Some default values for some well known variables that can't be changed during runtime
   MONGO_USER = "siaas"
   MONGO_PWD = "siaas"
   MONGO_HOST = "127.0.0.1"
   MONGO_PORT = "27017"
   MONGO_DB = "siaas"
   MONGO_COLLECTION = "agents"
   
   # Generate global variables from the configuration file
   config_dict=siaas_aux.get_config_from_configs_db()
   for config_name in config_dict.keys():
       if config_name.upper() == "MONGO_USER": MONGO_USER = config_dict[config_name]
       if config_name.upper() == "MONGO_PWD": MONGO_PWD = config_dict[config_name]
       if config_name.upper() == "MONGO_HOST": MONGO_HOST = config_dict[config_name]
       if config_name.upper() == "MONGO_PORT": MONGO_PORT = config_dict[config_name]
       if config_name.upper() == "MONGO_DB": MONGO_DB = config_dict[config_name]
       if config_name.upper() == "MONGO_COLLECTION": MONGO_COLLECTION = config_dict[config_name]
   
   while True:

     logger.debug("Loop running ...")

     if db_collection == None:
        # Create connection to MongoDB if it doesn't exist
        if len(MONGO_PORT or '') > 0:
            mongo_host_port = MONGO_HOST+":"+MONGO_PORT
        else:
            mongo_host_port = MONGO_HOST
        db_collection=siaas_aux.connect_mongodb_collection(MONGO_USER, MONGO_PWD, mongo_host_port, MONGO_DB, MONGO_COLLECTION)

     if db_collection != None:
        # Upload agent data
        last_uploaded_dict=upload_agent_data(siaas_uuid, db_collection, last_uploaded_dict)
        # Download agent data
        #last_downloaded_dict=download_agent_data(siaas_uuid, db_collection, last_downloaded_dict)

        # Sleep before next loop
        try:
           sleep_time=int(siaas_aux.get_config_from_configs_db("data_uploader_loop_interval_sec"))
           logger.debug("Sleeping for "+str(sleep_time)+" seconds before next loop ...")
           time.sleep(sleep_time)
        except:
           logger.debug("The interval loop time is not configured or is invalid. Sleeping now for 60 seconds by default ...")
           time.sleep(60)

if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    print('\nThis script is being directly run, so it will just read data from the DB!\n')

    siaas_uuid=siaas_aux.get_or_create_unique_system_id()
    siaas_uuid="00000000-0000-0000-0000-000000000000" # hack to show all

    try:
       collection=siaas_aux.connect_mongodb_collection()
       cursor=siaas_aux.read_mongodb_collection(collection,siaas_uuid)
    except:
       print("Can't connect to DB!")
       sys.exit(1)
    
    if cursor != None:
       for doc in cursor:
          #print('\n'+str(pprint.pformat(doc)))
          print('\n'+str(doc))
    
    print('\nAll done. Bye!\n')
