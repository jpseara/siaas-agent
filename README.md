# siaas-agent

_Intelligent System for Automation of Security Audits (SIAAS) - Agent Module_

In the context of the MSc in Telecommunications and Computer Engineering, at ISCTE - Instituto Universitário de Lisboa.

By João Pedro Seara, supervised by teacher Carlos Serrão (PhD).

__

**Instructions (tested on Ubuntu 20.04 "Focal" and Raspberry Pi OS 11 "Bullseye")**

 - Set up system and Pyhon packages (Ubuntu 20.04 "Focal"): `sudo ./siaas_agent_install_and_configure.sh`

 - How to run: `sudo siaas_agent_run.sh`

 - How to stop: `sudo siaas_agent_kill.sh`

 - RECOMMENDED WAY TO START/STOP SERVICES: `sudo systemctl [start/stop/restart] siaas-agent`

 - Logs: `tail -100f /var/log/siaas/siaas-agent.log`

 - How to generate a project archive (it is recommended to stop all processes before): `sudo siaas_agent_archive.sh`
