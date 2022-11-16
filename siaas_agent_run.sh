#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}
rm -f ./var/uid

if ! source ./venv/bin/activate 2> /dev/null
then
	python3 -m venv ./venv
	source ./venv/bin/activate
	pip3 install wheel==0.37.1
	pip3 install -r ./requirements.txt
	pip3 install -e git+https://github.com/jpseara/python3-nmap.git#egg=python3-nmap # forked nmap version
fi

./siaas_agent_refresh_nmap_scripts_repos.sh

source ./venv/bin/activate
python3 -u ./siaas_agent.py
