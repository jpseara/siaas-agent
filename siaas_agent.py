# SIAAS - Sistema Inteligente para Automação de Auditorias de Segurança
# By João Pedro Seara

import siaas_aux
import os
import sys
import logging
import uuid
from flask import Flask, jsonify, render_template
from multiprocessing import Process, Value, Manager, Lock
from waitress import serve

app = Flask(__name__)
logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

import siaas_aux
import routes
import agent
import neighbourhood
import portscanner
import data_uploader

SIAAS_VERSION="0.0.1"

if __name__ == "__main__":
   
   print('\n')

   # Initializing local databases
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'var/agent.db'), {})
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'var/config.db'), {})
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'var/neighbourhood.db'), {})
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'var/portscanner.db'), {})

   # Some default values for some well known variables that can't be changed during runtime
   AGENT_ID = None
   LOG_LEVEL = "info"

   # Read local configuration file and insert in local database
   if not siaas_aux.write_config_db_from_conf_file():
       logger.critical("Can't find or use local configuration file. Aborting !")
       sys.exit(1)
 
   # Generate global variables from the configuration file
   config_dict=siaas_aux.get_config_from_configs_db()
   for config_name in config_dict.keys():
       if config_name.upper() == "AGENT_ID": AGENT_ID = config_dict[config_name]
       if config_name.upper() == "LOG_LEVEL": LOG_LEVEL = config_dict[config_name]

   # Redefine logging level according to user config
   for handler in logging.root.handlers[:]:
      logging.root.removeHandler(handler)
   try:
      logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=eval("logging."+LOG_LEVEL.upper()))
   except:
      logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

   # Grabbing a unique system ID before proceeding
   if len(AGENT_ID or '') != 0:
      logger.debug("Using hard configured ID: "+str(AGENT_ID))
   else:
      AGENT_ID=siaas_aux.get_or_create_unique_system_id()
      if AGENT_ID=="00000000-0000-0000-0000-000000000000":
         logger.critical("Can't proceed without an unique system ID. Aborting !")
         sys.exit(2)

   logger.info("SIAAS Agent v"+SIAAS_VERSION+" starting ["+AGENT_ID+"]")

   # Main logic
   agent = Process(target=agent.loop, args=(SIAAS_VERSION,))
   #neighbourhood = Process(target=neighbourhood.loop, args=("enp1s0",))
   neighbourhood = Process(target=neighbourhood.loop, args=())
   portscanner = Process(target=portscanner.loop, args=())
   data_uploader = Process(target=data_uploader.loop, args=(AGENT_ID,))
   agent.start()
   neighbourhood.start()
   portscanner.start()
   data_uploader.start()
   app.run(debug=True, use_reloader=False, host="0.0.0.0")
   #serve(app, host="0.0.0.0", port=5000)
   agent.join()
   neighbourhood.join()
   portscanner.join()
   data_uploader.join()
