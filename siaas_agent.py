# SIAAS - Sistema Inteligente para Automação de Auditorias de Segurança
# By João Pedro Seara

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
import uuid
from flask import Flask, jsonify, render_template
from multiprocessing import Process, Value, Manager, Lock
from waitress import serve

app = Flask(__name__)
logger = logging.getLogger(__name__)
log_file = "log/siaas-agent.log"
os.makedirs(os.path.dirname(log_file), exist_ok=True)
logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=10240000, backupCount=5)],
                    format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)

import siaas_aux
import routes
import agent
import neighbourhood
import portscanner
import data_transfer

SIAAS_VERSION = "0.0.1"

if __name__ == "__main__":

    print('\n')

    # No Windows can do ; - )
    if os.name != "posix":
        print("\nThis program can only be run in Linux or Raspberry Pi. Exiting!\n")
        sys.exit(1)

    # Create local directories
    os.makedirs(os.path.join(sys.path[0], 'conf'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'log'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'tmp'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)

    # Initializing local databases
    siaas_aux.write_to_local_file(
        os.path.join(sys.path[0], 'var/config.db'), {})

    # Some default values for some well known variables that can't be changed during runtime (these will be overwritten if there's a config file key for them)
    AGENT_ID = None
    LOG_LEVEL = "info"

    # Read local configuration file and insert in local database
    if not siaas_aux.write_config_db_from_conf_file():
        logger.critical(
            "Can't find or use local configuration file. Aborting !")
        print("\nCan't find or use local configuration file. Aborting !\n")
        sys.exit(2)

    # Generate global variables from the configuration file
    config_dict = siaas_aux.get_config_from_configs_db()
    for config_name in config_dict.keys():
        if config_name.upper() == "AGENT_ID":
            AGENT_ID = config_dict[config_name]
        if config_name.upper() == "LOG_LEVEL":
            LOG_LEVEL = config_dict[config_name]

    # Redefine logging level according to user config
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    try:
        logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=10240000, backupCount=5)],
                            format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=eval("logging."+LOG_LEVEL.upper()))
    except:
        logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=10240000, backupCount=5)],
                            format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

    # Grabbing a unique system ID before proceeding
    if len(AGENT_ID or '') != 0:
        if AGENT_ID == "ffffffff-ffff-ffff-ffff-ffffffffffff" or AGENT_ID == "00000000-0000-0000-0000-000000000000":
            logger.warning("The hard configured ID '"+AGENT_ID +
                           "' is reserved for internal use. Aborting !")
            print("\nThe hard configured ID '"+AGENT_ID +
                  "' is reserved for internal use. Aborting !\n")
            sys.exit(3)
        logger.debug("Using hard configured ID: "+str(AGENT_ID))
    else:
        AGENT_ID = siaas_aux.get_or_create_unique_system_id()
        if AGENT_ID == "00000000-0000-0000-0000-000000000000":
            logger.critical(
                "Can't proceed without an unique system ID. Aborting !")
            print("\nCan't proceed without an unique system ID. Aborting !\n")
            sys.exit(3)

    print("\nSIAAS Agent v"+SIAAS_VERSION +
          " starting ["+AGENT_ID+"]\n\nLogging to: "+os.path.join(sys.path[0], log_file)+"\n")
    logger.info("SIAAS Agent v"+SIAAS_VERSION+" starting ["+AGENT_ID+"]")

    # Main logic
    agent = Process(target=agent.loop, args=(SIAAS_VERSION,))
    #neighbourhood = Process(target=neighbourhood.loop, args=("enp1s0",))
    neighbourhood = Process(target=neighbourhood.loop, args=())
    portscanner = Process(target=portscanner.loop, args=())
    data_transfer = Process(target=data_transfer.loop, args=())
    agent.start()
    neighbourhood.start()
    portscanner.start()
    data_transfer.start()
    app.run(debug=True, use_reloader=False, host="0.0.0.0")
    #serve(app, host="0.0.0.0", port=5000)
    agent.join()
    neighbourhood.join()
    portscanner.join()
    data_transfer.join()
