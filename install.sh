#!/bin/bash

echo "[+] Installing pynessus ..."
sudo python setup.py install

echo "[+] Configuring pynessys ..."
echo -n "Nessus server hostname (scanner.hacme.org): "
read NESSUS_SERVER
echo -n "Nessus server port (8080): "
read NESSUS_PORT
echo -n "Username: "
read USERNAME
echo -n "Password: "
read -s PASSWORD

mkdir -p ~/.config/pynessus
echo """
# Defaults

[core]
server = $NESSUS_SERVER
port = $NESSUS_PORT
user = $USERNAME
password = $PASSWORD
logfile = /tmp/pynessus.log
report_path = /home/$USER/tools/pynessus/reports
loglevel = info
limit = 3
sleepmax = 600
sleepmin = 300""" > ~/.config/pynessus/default.conf

echo ""
echo "[+] All done!"
