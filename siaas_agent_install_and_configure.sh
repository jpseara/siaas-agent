#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

apt-get update
apt-get install -y python3 python3-pip python3-venv git nmap

ln -fs ${SCRIPT_DIR}/siaas_agent_run.sh /usr/local/bin/
ln -fs ${SCRIPT_DIR}/siaas_agent_kill.sh /usr/local/bin/
