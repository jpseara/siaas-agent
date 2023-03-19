# Intelligent System for Automation of Security Audits (SIAAS)
# Agent - Data Transfer module
# By João Pedro Seara, 2023

import siaas_aux
import logging
import os
import sys
import pprint
import time
from datetime import datetime

logger = logging.getLogger(__name__)


def download_agent_configs(api_base_uri, ignore_ssl=False, ca_bundle=None, api_user=None, api_pwd=None):
    """
    Downloads agent configs and merges with local configs
    Returns True if all OK; False if anything failed
    """
    logger.info("Downloading agent configs from the server ...")

    siaas_uid = siaas_aux.get_or_create_unique_system_id()

    downloaded_configs_raw = siaas_aux.get_request_to_server(
        api_base_uri+"/siaas-server/agents/configs/"+siaas_uid+"?merge_broadcast=1", ignore_ssl=ignore_ssl, ca_bundle=ca_bundle, api_user=api_user, api_pwd=api_pwd)

    try:
        downloaded_configs = downloaded_configs_raw["output"][siaas_uid]

    except:
        downloaded_configs = {}

    if siaas_aux.merge_configs_from_upstream(upstream_dict=downloaded_configs):
        logger.info("Agent configs download finished and merged locally.")
        return True

    else:
        logger.error("There was an error downloading agent configs.")
        return False


def upload_agent_data(api_base_uri, last_uploaded_dict={}, ignore_ssl=False, ca_bundle=None, api_user=None, api_pwd=None):
    """
    Uploads agent configs, after connecting to the server's API
    Returns True if all OK; False if anything failed
    """
    logger.info("Uploading agent data to the server ...")

    siaas_uid = siaas_aux.get_or_create_unique_system_id()

    all_modules = "platform,neighborhood,portscanner,config"
    current_dict = siaas_aux.merge_module_dicts(all_modules)

    # if (str(current_dict) == str(last_uploaded_dict)) or len(current_dict) == 0:
    #    logger.info(
    #        "No changes were detected in local databases, so there's nothing to upload to the remote DB server. Will check again later ...")
    #    return last_uploaded_dict

    logger.info("Agent data upload to the server finished.")

    if not siaas_aux.post_request_to_server(api_base_uri+"/siaas-server/agents/data/"+siaas_uid, dict(current_dict), ignore_ssl=ignore_ssl, ca_bundle=ca_bundle, api_user=api_user, api_pwd=api_pwd):
        return last_uploaded_dict

    return current_dict


def loop():
    """
    Data Transfer module loop (calls the download and upload functions)
    """
    last_uploaded_dict = {}
    last_downloaded_dict = {}

    # Generate global variables from the configuration file
    config_dict = siaas_aux.get_config_from_configs_db(convert_to_string=True)
    API_URI = None
    API_USER = None
    API_PWD = None
    API_SSL_IGNORE_VERIFY = None
    API_SSL_CA_BUNDLE = None
    for config_name in config_dict.keys():
        if config_name.upper() == "API_URI":
            API_URI = config_dict[config_name]
        if config_name.upper() == "API_USER":
            API_USER = config_dict[config_name]
        if config_name.upper() == "API_PWD":
            API_PWD = config_dict[config_name]
        if config_name.upper() == "API_SSL_IGNORE_VERIFY":
            API_SSL_IGNORE_VERIFY = config_dict[config_name]
        if config_name.upper() == "API_SSL_CA_BUNDLE":
            API_SSL_CA_BUNDLE = config_dict[config_name]

    ssl_ignore_verify = siaas_aux.validate_bool_string(API_SSL_IGNORE_VERIFY)

    ssl_ca_bundle = None
    if len(API_SSL_CA_BUNDLE or '') > 0:
        ssl_ca_bundle = os.path.join(sys.path[0], API_SSL_CA_BUNDLE)

    api_user = None
    api_pwd = None
    if len(API_USER or '') > 0 and len(API_PWD or '') > 0:
        api_user = API_USER
        api_pwd = API_PWD

    valid_api = True
    if len(API_URI or '') == 0:
        logger.error(
            "The API URI is empty. No communications with the server will take place.")
        valid_api = False

    offline_mode = siaas_aux.get_config_from_configs_db(
        config_name="offline_mode", convert_to_string=True)
    no_comms = siaas_aux.validate_bool_string(offline_mode)
    if no_comms:
        logger.warning(
            "Offline mode is on! No data will be transferred to or from the server. If you want to change this behavior, change the local configuration file and restart the application.")

    while valid_api and not no_comms:

        logger.debug("Loop running ...")

        # Upload agent data
        silent_mode = siaas_aux.get_config_from_configs_db(
            config_name="silent_mode", convert_to_string=True)
        if siaas_aux.validate_bool_string(silent_mode):
            logger.warning(
                "Silent mode is on! This means no data is being sent to the server.")
        else:
            last_uploaded_dict = upload_agent_data(API_URI,
                                                   last_uploaded_dict, ssl_ignore_verify, ssl_ca_bundle, api_user, api_pwd)

        # Download agent configs
        download_agent_configs(API_URI, ssl_ignore_verify,
                               ssl_ca_bundle, api_user, api_pwd)

        # Sleep before next loop
        try:
            sleep_time = int(siaas_aux.get_config_from_configs_db(
                config_name="datatransfer_loop_interval_sec"))
            logger.debug("Sleeping for "+str(sleep_time) +
                         " seconds before next loop ...")
            time.sleep(sleep_time)
        except:
            logger.debug(
                "The interval loop time is not configured or is invalid. Sleeping now for 5 minutes by default ...")
            time.sleep(300)


if __name__ == "__main__":

    log_level = logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-5s %(filename)s [%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=log_level)

    if os.geteuid() != 0:
        print("You need to be root to run this script!", file=sys.stderr)
        sys.exit(1)

    print('\nThis script is being directly run, so it will just read data from the DB!\n')

    siaas_uid = siaas_aux.get_or_create_unique_system_id()
    # siaas_uid = "00000000-0000-0000-0000-000000000000" # hack to show data from all agents

    api_base_uri = "https://siaas/api"

    pprint.pprint(siaas_aux.get_request_to_server(
        api_base_uri+"/siaas-server/agents/configs/"+siaas_uid+"?merge_broadcast=1", ignore_ssl=True, api_user="siaas", api_pwd="siaas"), sort_dicts=False)

    print('\nAll done. Bye!\n')
