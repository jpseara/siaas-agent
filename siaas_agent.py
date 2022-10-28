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

SIAAS_VERSION = "0.0.1"
#LOG_DIR = "log"
LOG_DIR = "/var/log/siaas"


if __name__ == "__main__":

    import siaas_aux
    import siaas_datatransfer
    import siaas_neighborhood
    import siaas_platform
    import siaas_portscanner
    import siaas_routes

    print('\n')

    # No Windows can do ; - )
    if os.name != "posix":
        logger.critical(
            "\nThis program can only be run in Linux or Raspberry Pi. Exiting!\n")
        sys.exit(1)

    # Needs to be root
    if os.geteuid() != 0:
        logger.critical(
            "\nThis script must be run as root or using sudo!\n", file=sys.stderr)
        sys.exit(2)

    # Create local directories
    os.makedirs(os.path.join(sys.path[0], 'conf'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'tmp'), exist_ok=True)
    os.makedirs(os.path.join(sys.path[0], 'var'), exist_ok=True)

    # Initializing local databases for configurations
    siaas_aux.write_to_local_file(
        os.path.join(sys.path[0], 'var/config.db'), {})
    siaas_aux.write_to_local_file(os.path.join(
        sys.path[0], 'var/config_orig.db'), {})

    # Read local configuration file and insert in local database
    siaas_aux.write_config_db_from_conf_file()
    siaas_aux.write_config_db_from_conf_file(
        output=os.path.join(sys.path[0], 'var/config_orig.db'))

    # Define logging level according to user config
    os.makedirs(os.path.join(sys.path[0], LOG_DIR), exist_ok=True)
    log_file = os.path.join(os.path.join(sys.path[0], LOG_DIR), "siaas-agent.log")
    log_level = siaas_aux.get_config_from_configs_db(config_name="log_level")
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    try:
        logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=10240000, backupCount=5)],
                            format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=eval("logging."+log_level.upper()))
    except:
        logging.basicConfig(handlers=[RotatingFileHandler(os.path.join(sys.path[0], log_file), maxBytes=10240000, backupCount=5)],
                            format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

    # Grabbing a unique system ID before proceeding
    agent_uid = siaas_aux.get_or_create_unique_system_id()
    if agent_uid == "00000000-0000-0000-0000-000000000000":
        logger.critical(
            "\nCan't proceed without an unique system ID. Aborting !\n")
        sys.exit(3)

    print("\nSIAAS Agent v"+SIAAS_VERSION +
          " starting ["+agent_uid+"]\n\nLogging to: "+os.path.join(sys.path[0], log_file)+"\n")
    logger.info("SIAAS Agent v"+SIAAS_VERSION+" starting ["+agent_uid+"]")

    # Main logic
    platform = Process(target=siaas_platform.loop, args=(SIAAS_VERSION,))
    #neighborhood = Process(target=siaas_neighborhood.loop, args=("enp1s0",))
    neighborhood = Process(target=siaas_neighborhood.loop, args=())
    portscanner = Process(target=siaas_portscanner.loop, args=())
    datatransfer = Process(target=siaas_datatransfer.loop, args=())
    platform.start()
    neighborhood.start()
    portscanner.start()
    datatransfer.start()
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port="5001")
    #serve(app, host="0.0.0.0", port="5001")
    platform.join()
    neighborhood.join()
    portscanner.join()
    datatransfer.join()
