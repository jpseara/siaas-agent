import siaas_aux
import logging
import os
import sys
import pprint
import time
from datetime import datetime
from copy import copy

logger = logging.getLogger(__name__)

LOOP_INTERVAL_SEC=300

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
      agent[siaas_uuid]={}
      agent[siaas_uuid]["agent"]={}

   # Grab neighbourhood data
   neighbourhood = siaas_aux.read_from_local_file(os.path.join(sys.path[0],'var/neighbourhood.db'))
   if len(neighbourhood or '') ==0:
      neighbourhood={}
      neighbourhood[siaas_uuid]={}
      neighbourhood[siaas_uuid]["neighbourhood"]={}

   # Grab portscanner data
   portscanner = siaas_aux.read_from_local_file(os.path.join(sys.path[0],'var/portscanner.db'))
   if len(portscanner or '') ==0:
      portscanner={}
      portscanner[siaas_uuid]={}
      portscanner[siaas_uuid]["portscanner"]={}

   current_dict[siaas_uuid]["agent"]=agent[siaas_uuid]["agent"]
   current_dict[siaas_uuid]["neighbourhood"]=neighbourhood[siaas_uuid]["neighbourhood"]
   current_dict[siaas_uuid]["portscanner"]=portscanner[siaas_uuid]["portscanner"]

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

def loop(siaas_uuid="00000000-0000-0000-0000-000000000000", mongo_user="siaas", mongo_password="siaas", mongo_host="127.0.0.1", mongo_db="siaas", mongo_collection="agents"):

   db_collection=None
   last_uploaded_dict={}
   last_downloaded_dict={}

   while True:

     logger.debug("Loop running ...")

     if db_collection == None:
        # Create connection to MongoDB if it doesn't exist
        db_collection=siaas_aux.connect_mongodb_collection(mongo_user, mongo_password, mongo_host, mongo_db, mongo_collection)

     if db_collection != None:
        # Upload agent data
        last_uploaded_dict=upload_agent_data(siaas_uuid, db_collection, last_uploaded_dict)
        # Download agent data
        #last_downloaded_dict=download_agent_data(siaas_uuid, db_collection, last_downloaded_dict)

     time.sleep(LOOP_INTERVAL_SEC)

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
