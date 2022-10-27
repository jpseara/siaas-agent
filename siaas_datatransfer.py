import siaas_aux
import logging
import os
import sys
import pprint
import time
from datetime import datetime
from copy import copy

logger = logging.getLogger(__name__)


def download_agent_data(db_collection=None):

    if db_collection == None:
        logger.error(
            "No valid DB collection object received. Bypassed remote DB data upload.")
        return False

    siaas_uid = siaas_aux.get_or_create_unique_system_id()
    downloaded_configs = siaas_aux.read_published_data_for_agents_mongodb(db_collection, siaas_uid, scope="agent_configs", convert_to_string=False)
    siaas_aux.merge_configs_from_upstream(upstream_dict=downloaded_configs)

    return True


def upload_agent_data(api_base_uri, last_uploaded_dict={}):

    siaas_uid = siaas_aux.get_or_create_unique_system_id()

    all_modules = "platform,neighborhood,portscanner,config"
    current_dict = siaas_aux.merge_module_dicts(all_modules)

    #if (str(current_dict) == str(last_uploaded_dict)) or len(current_dict) == 0:
    #    logger.info(
    #        "No changes were detected in local databases, so there's nothing to upload to the remote DB server. Will check again later ...")
    #    return last_uploaded_dict

    if not siaas_aux.post_request_to_server(api_base_uri+"/siaas-server/agents/data/"+siaas_uid, dict(current_dict)):
        logger.error("Error while uploading agent data to the server.")
        return last_uploaded_dict

    return current_dict


def loop():

    db_collection = None
    last_uploaded_dict = {}
    last_downloaded_dict = {}

    # Generate global variables from the configuration file
    config_dict = siaas_aux.get_config_from_configs_db(convert_to_string=True)
    MONGO_USER=None
    MONGO_PWD=None
    MONGO_HOST=None
    MONGO_PORT=None
    MONGO_DB=None
    MONGO_COLLECTION=None
    for config_name in config_dict.keys():
        if config_name.upper() == "MONGO_USER":
            MONGO_USER = config_dict[config_name]
        if config_name.upper() == "MONGO_PWD":
            MONGO_PWD = config_dict[config_name]
        if config_name.upper() == "MONGO_HOST":
            MONGO_HOST = config_dict[config_name]
        if config_name.upper() == "MONGO_PORT":
            MONGO_PORT = config_dict[config_name]
        if config_name.upper() == "MONGO_DB":
            MONGO_DB = config_dict[config_name]
        if config_name.upper() == "MONGO_COLLECTION":
            MONGO_COLLECTION = config_dict[config_name]

    run = True
    offline_mode = siaas_aux.get_config_from_configs_db(config_name="offline_mode", convert_to_string=True)
    if len(offline_mode or '') > 0:
        if offline_mode.lower() == "true":
            logger.warning(
                "Offline mode is on! No data will be transferred. If you want to change this behavior, change the configuration and restart the application.")
            run = False

    while run:

        logger.debug("Loop running ...")

        if db_collection == None:
            # Create connection to MongoDB if it doesn't exist
            if len(MONGO_PORT or '') > 0:
                mongo_host_port = MONGO_HOST+":"+MONGO_PORT
            else:
                mongo_host_port = MONGO_HOST
            db_collection = siaas_aux.connect_mongodb_collection(
                MONGO_USER, MONGO_PWD, mongo_host_port, MONGO_DB, MONGO_COLLECTION)

        if db_collection != None:

            api_base_uri = siaas_aux.get_config_from_configs_db(
                config_name="api_uri", convert_to_string=True)

            # Upload agent data
            silent_mode = siaas_aux.get_config_from_configs_db(
                config_name="silent_mode", convert_to_string=True)
            dont_upload = False
            if len(silent_mode or '') > 0:
                if silent_mode.lower() == "true":
                    dont_upload = True
                    logger.warning(
                        "Silent mode is on! This means no data is sent to the server. Will check again later ...")
            if dont_upload != True:
                last_uploaded_dict = upload_agent_data(api_base_uri,
                    last_uploaded_dict)

            # Download agent data
            download_agent_data(db_collection)
        else:
            logger.error(
                "The DB connection is not OK. Sleeping for some seconds and retrying ...")
            time.sleep(60)
            # continue

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="datatransfer_loop_interval_sec"))
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

    print('\nThis script is being directly run, so it will just read data from the DB!\n')

    siaas_uid = siaas_aux.get_or_create_unique_system_id()
    #siaas_uid = "00000000-0000-0000-0000-000000000000" # hack to show data from all agents

    MONGO_USER = "siaas"
    MONGO_PWD = "siaas"
    MONGO_HOST = "127.0.0.1"
    MONGO_PORT = "27017"
    MONGO_DB = "siaas"
    MONGO_COLLECTION = "siaas"

    try:
        collection = siaas_aux.connect_mongodb_collection(
            MONGO_USER, MONGO_PWD, MONGO_HOST+":"+MONGO_PORT, MONGO_DB, MONGO_COLLECTION)
    except:
        print("Can't connect to DB!")
        sys.exit(1)

    results=siaas_aux.read_mongodb_collection(collection, siaas_uid)

    if results != None:
        for doc in results:
            # print('\n'+str(pprint.pformat(doc)))
            print('\n'+str(doc))

    print('\nAll done. Bye!\n')
