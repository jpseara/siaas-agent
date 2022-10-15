#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}
mkdir -p tmp
mkdir -p conf

apt-get update
apt-get install -y python3 python3-pip python3-venv git nmap

python3 -m venv ./venv
source ./venv/bin/activate
pip3 install wheel==0.37.1
pip3 install -r ./requirements.txt
pip3 install -e git+https://github.com/jpseara/python3-nmap.git#egg=python3-nmap # forked nmap version

ln -fs ${SCRIPT_DIR}/siaas_agent_run.sh /usr/local/bin/
ln -fs ${SCRIPT_DIR}/siaas_agent_kill.sh /usr/local/bin/
