#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

mkdir -p conf
mkdir -p tmp
mkdir -p var

#git clone https://github.com/vulnersCom/nmap-vulners.git tmp/nmap-vulners

source ./venv/bin/activate
python3 ./siaas_agent.py
