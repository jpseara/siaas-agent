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

import routes
import agent
import neighbourhood
import portscanner
import data_uploader

SIAAS_VERSION="0.0.1"
AGENT_ID="" # this should be kept empty except for testing purposes
NMAP_SCRIPT = "vulners"
MONGO_USER = "siaas"
MONGO_PWD = "siaas"
MONGO_HOST = "127.0.0.1:27017"
MONGO_DB = "siaas"
MONGO_COLLECTION = "agents"
#NMAP_SCRIPT = os.path.join(sys.path[0],"tmp/nmap-vulners")

LOG_LEVEL = logging.INFO
logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)-5s %(filename)s [%(processName)s|%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=LOG_LEVEL)

if __name__ == "__main__":

   print('\n')

   # Grabbing a unique system ID before proceeding
   if len(AGENT_ID) > 0:
       logger.debug("Using hard configured ID: "+str(AGENT_ID))
   else:
      AGENT_ID=siaas_aux.get_or_create_unique_system_id()
      if AGENT_ID=="00000000-0000-0000-0000-000000000000":
         logger.fatal("Can't proceed without an unique system ID. Exiting.")
         sys.exit(1)

   logger.info("SIAAS Agent v"+SIAAS_VERSION+" starting ["+AGENT_ID+"]")

   # Initializing local databases
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'tmp/agent.tmp'), {})
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'tmp/neighbourhood.tmp'), {})
   siaas_aux.write_to_local_file(os.path.join(sys.path[0],'tmp/portscanner.tmp'), {})

   # Main logic
   agent = Process(target=agent.loop, args=(AGENT_ID,SIAAS_VERSION,))
   #neighbourhood = Process(target=neighbourhood.loop, args=(AGENT_ID,"enp1s0",))
   neighbourhood = Process(target=neighbourhood.loop, args=(AGENT_ID,))
   portscanner = Process(target=portscanner.loop, args=(AGENT_ID,NMAP_SCRIPT,))
   data_uploader = Process(target=data_uploader.loop, args=(AGENT_ID,MONGO_USER,MONGO_PWD,MONGO_HOST,MONGO_DB,MONGO_COLLECTION,))
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
