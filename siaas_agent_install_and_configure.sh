#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

cd ${SCRIPT_DIR}

# INSTALL PACKAGES
apt-get update
apt-get install -y python3 python3-pip python3-venv git nmap dmidecode ca-certificates || exit 1

# CRONTAB
cat << EOF | tee /etc/cron.daily/siaas-agent
#!/bin/bash
echo "Starting SIAAS Agent cronjob: "\$(date) > /tmp/siaas_agent_last_cronjob
${SCRIPT_DIR}/siaas_agent_refresh_nmap_scripts_repos.sh | tee -a /tmp/siaas_agent_last_cronjob
echo "Ending SIAAS Agent cronjob: "\$(date) >> /tmp/siaas_agent_last_cronjob
EOF
chmod 755 /etc/cron.daily/siaas-agent

# SERVICE CONFIGURATION
mkdir -p ssl
cp -n conf/siaas_agent.cnf.orig conf/siaas_agent.cnf
ln -fsT ${SCRIPT_DIR}/log /var/log/siaas-agent
cat << EOF | tee /etc/systemd/system/siaas-agent.service
[Unit]
Description=SIAAS Agent
# if SIAAS Server is installed (AIO setup), let it start first
After=siaas-server.service

[Service]
ExecStart=${SCRIPT_DIR}/siaas_agent_run.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable siaas-agent

# INITIALIZE
#sudo rm -rf ${SCRIPT_DIR}/venv
${SCRIPT_DIR}/siaas_agent_venv_setup.sh
${SCRIPT_DIR}/siaas_agent_refresh_nmap_scripts_repos.sh

echo -e "\nSIAAS Agent will be started on boot.\n\nTo start (or restart) manually right now: sudo systemctl [start/restart] siaas-agent\n"
