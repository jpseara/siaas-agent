#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

#rm -rf tmp/nmap-vulners && git clone https://github.com/vulnersCom/nmap-vulners.git tmp/nmap-vulners

source ./venv/bin/activate
python3 -u ./siaas_agent.py
