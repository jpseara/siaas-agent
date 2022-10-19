#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "`readlink -f ${BASH_SOURCE[0]}`" )" &> /dev/null && pwd )

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or using sudo!"
  exit 1
fi

cd ${SCRIPT_DIR}

NMAP_SCRIPTS_DIR=${SCRIPT_DIR}/tmp

git -C ${NMAP_SCRIPTS_DIR}/nmap-vulners pull 2> /dev/null || (rm -rf ${NMAP_SCRIPTS_DIR}/nmap-vulners && git clone https://github.com/vulnersCom/nmap-vulners.git ${NMAP_SCRIPTS_DIR}/nmap-vulners && ln -fs ${NMAP_SCRIPTS_DIR}/nmap-vulners /usr/share/nmap/scripts/)

git -C ${NMAP_SCRIPTS_DIR}/vulscan pull 2> /dev/null || (rm -rf ${NMAP_SCRIPTS_DIR}/vulscan && git clone https://github.com/scipag/vulscan.git ${NMAP_SCRIPTS_DIR}/vulscan && cd ${NMAP_SCRIPTS_DIR}/vulscan/utilities/updater/ && chmod +x updateFiles.sh && ./updateFiles.sh && cd - && ln -fs ${NMAP_SCRIPTS_DIR}/vulscan /usr/share/nmap/scripts/)
