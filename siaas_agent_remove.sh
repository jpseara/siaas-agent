#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

systemctl stop siaas-agent

# CRONTAB
rm -f /etc/cron.daily/siaas-agent

# SERVICE CONFIGURATION
rm -f /var/log/siaas-agent
rm -f /etc/systemd/system/siaas-agent.service
systemctl daemon-reload

echo -e "\nSIAAS Agent service and configurations were removed from the system.\n"
