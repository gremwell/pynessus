#!/bin/bash

echo "[+] Installing pynessus ..."
sudo python setup.py install

echo "[+] Configuring pynessys ..."
echo -n "Nessus server hostname: "
read NESSUS_SERVER
echo -n "Nessus server port: "
read NESSUS_PORT
echo -n "Username: "
read USERNAME
echo -n "Password: "
read -s PASSWORD

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
sleepmin = 300""" > ~/.pynessus.conf

if [[ "$SHELL" == "/bin/zsh" ]]; then
	echo "alias nessus_scan='skanner.py -c ~/.pynessus.conf'" >> ~/.zshrc
else	
	echo "alias nessus_scan='skanner.py -c ~/.pynessus.conf'" >> ~/.bashrc
fi

echo ""
echo "[+] All done!"
