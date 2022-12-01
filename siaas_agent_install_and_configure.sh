#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

apt-get update
apt-get install -y python3 python3-pip python3-venv git nmap dmidecode

# SERVICE CONFIGURATION
mkdir -p ssl
cp -n conf/siaas_agent.cnf.orig conf/siaas_agent.cnf
ln -fs ${SCRIPT_DIR}/siaas_agent_run.sh /usr/local/bin/
ln -fs ${SCRIPT_DIR}/siaas_agent_kill.sh /usr/local/bin/
ln -fs ${SCRIPT_DIR}/log /var/log/siaas-agent
sudo cat << EOF | sudo tee /etc/systemd/system/siaas-agent.service
[Unit]
Description=SIAAS Agent
[Service]
ExecStart=/usr/local/bin/siaas_agent_run.sh
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable siaas-agent

echo -e "\nSIAAS Agent will be started on boot.\n\nTo start (or restart) manually right now: sudo systemctl [start/restart] siaas-agent\n"
