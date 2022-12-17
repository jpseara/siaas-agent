#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

# CRONTAB
rm -f /etc/cron.daily/siaas-agent

# SERVICE CONFIGURATION
systemctl stop siaas-agent
rm -f /usr/local/bin/siaas_agent_run.sh
rm -f /usr/local/bin/siaas_agent_kill.sh
rm -f /var/log/siaas-agent
rm -f /etc/systemd/system/siaas-agent.service
systemctl daemon-reload

echo -e "\nSIAAS Agent service and configurations were removed from the system.\n"
