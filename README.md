# siaas-agent

_Intelligent System for Automation of Security Audits (SIAAS) - Agent_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD), 2022-2024

__

**Instructions (tested on Ubuntu 20.04 "Focal", Ubuntu 22.04 "Jammy", Debian 11 "Bullseye", and Raspberry Pi OS 11 "Bullseye")**

 - Install and configure: `sudo ./siaas_agent_install_and_configure.sh`

 - Start: `sudo systemctl start siaas-agent` or `sudo ./siaas_agent_run.sh`

 - Stop: `sudo systemctl stop siaas-agent` or `sudo ./siaas_agent_kill.sh`

 - Logs: `tail -100f /var/log/siaas-agent/siaas-agent.log` or `tail -100f ./log/siaas-agent.log`

 - Generate a project archive (it is recommended to stop all processes before): `sudo ./siaas_agent_archive.sh`

 - Remove: `sudo ./siaas_agent_remove.sh`
