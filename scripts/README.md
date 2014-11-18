# Example scripts

## demo.py

This is a simple demo of the pynessus module capabilities, it will connect to a Nessus server and output all informations.

```shell
$ python demo.py nessus.local user password
[+] Successfully logged in, getting informations ...
###   SCANS  ###
	d7808a8d-95dd-861f-e79b-1f6cd162dc9b5faff40e31bee8d5 - Hacme Scan
	1438f9a1-c228-83d1-d345-29b4b6f85b27edbba8fc879a142c - Hacme Scan 2
### POLICIES ###
	1 - Internal Network Scan
	2 - External Network Scan
### SCHEDULES ###
###   USERS ###
	bob
	alice
	eve
###   TAGS  ###
	My Scans
	Trash
[+] Successfully logged out.
```

## nmap.py

This script is used to launch scans that will use a nmap xml file as input so we do not need to run the Nessus scanner
again. You'll need to have Nmap XML plugin installed on your Nesssus server instance to be able to use it.

```shell
$ python nmapscan.py -c gremwell.conf -n Test -p "Import Nmap XML_" -x localhost.xm
```

The log file will provide details about the ongoing process

```
2014-11-18 13:26:39.216345    DEBUG Logger initiated; Logfile: /home/quentin/tools/pynessus/nessus.log, Loglevel: 10
2014-11-18 13:26:39.216472    DEBUG PARSED scans: [{'policy': 'Import Nmap XML_', 'name': 'Test', 'nmap_xml_file': 'localhost.xml'}]
2014-11-18 13:26:39.216530     INFO Nessus scanner started.
2014-11-18 13:26:40.373138     INFO Connected to Nessus server; authenticated to server 'nessus.local' as user 'quentin'
2014-11-18 13:26:41.040365     INFO Starting with a single scan
2014-11-18 13:26:41.189136     INFO localhost.xml has been uploaded.
2014-11-18 13:26:43.404651     INFO Scan successfully started; Owner: 'quentin', Name: 'Test'
2014-11-18 13:30:48.067551     INFO Report for scan Test saved at /home/quentin/tools/pynessus/reports/d7808a8d-95dd-861f-e79b-1f6cd162dc9b5faff40e31bee8d5.nessus.v2
2014-11-18 13:30:48.067795     INFO All done; closing
```

## cgiscan.py

This script is used to launch CGI scans with Nessus against a list of specified URLs.

```shell
$ python cgiscan.py -c gremwell.conf -n "My CGI scan" -i hosts.txt
```

The log file will provide details about the ongoing process

```
```

## loadreports.py

This script will simply download all available reports from the Nessus server in the format of your choice.

```shell
$ python loadreports.py -c gremwell.conf -f nessus.v2
[+] Successfully logged in.
[+] 9 reports will be downloaded.
[+] Downloading report 87346a9b-f366-00e9-2edd-451693f592f6566c523bdb634060
[+] 87346a9b-f366-00e9-2edd-451693f592f6566c523bdb634060 report downloaded to 87346a9b-f366-00e9-2edd-451693f592f6566c523bdb634060.nessus.v2
[+] Downloading report 29616c31-858e-3c3d-fcd4-92413a72c29c6b935fb58c7dfb32
[+] 29616c31-858e-3c3d-fcd4-92413a72c29c6b935fb58c7dfb32 report downloaded to 29616c31-858e-3c3d-fcd4-92413a72c29c6b935fb58c7dfb32.nessus.v2
[+] Downloading report 7b0d272b-b81e-5f81-f8d8-044c9a17c7015c36d10528f069e7
[+] 7b0d272b-b81e-5f81-f8d8-044c9a17c7015c36d10528f069e7 report downloaded to 7b0d272b-b81e-5f81-f8d8-044c9a17c7015c36d10528f069e7.nessus.v2
[+] Downloading report 7cd871ef-f2b5-9c68-9160-97a83b7848087b07db1cee5d02b9
[+] 7cd871ef-f2b5-9c68-9160-97a83b7848087b07db1cee5d02b9 report downloaded to 7cd871ef-f2b5-9c68-9160-97a83b7848087b07db1cee5d02b9.nessus.v2
[+] Downloading report d8faf8e2-79dc-ae42-5336-faabee88d101d7323a71cecdbbde
[+] d8faf8e2-79dc-ae42-5336-faabee88d101d7323a71cecdbbde report downloaded to d8faf8e2-79dc-ae42-5336-faabee88d101d7323a71cecdbbde.nessus.v2
[+] Downloading report 5b2e896c-f7da-fa14-877d-c3403cdbc570f1c9e7ef303cfcb7
[+] 5b2e896c-f7da-fa14-877d-c3403cdbc570f1c9e7ef303cfcb7 report downloaded to 5b2e896c-f7da-fa14-877d-c3403cdbc570f1c9e7ef303cfcb7.nessus.v2
[+] Downloading report 1438f9a1-c228-83d1-d345-29b4b6f85b27edbba8fc879a142c
[+] 1438f9a1-c228-83d1-d345-29b4b6f85b27edbba8fc879a142c report downloaded to 1438f9a1-c228-83d1-d345-29b4b6f85b27edbba8fc879a142c.nessus.v2
[+] Downloading report d7808a8d-95dd-861f-e79b-1f6cd162dc9b5faff40e31bee8d5
[+] d7808a8d-95dd-861f-e79b-1f6cd162dc9b5faff40e31bee8d5 report downloaded to d7808a8d-95dd-861f-e79b-1f6cd162dc9b5faff40e31bee8d5.nessus.v2
[+] Downloading report 83d9d99b-f22f-f38f-1a4b-d0ef191a8612a251b6a85e3079ad
[+] 83d9d99b-f22f-f38f-1a4b-d0ef191a8612a251b6a85e3079ad report downloaded to 83d9d99b-f22f-f38f-1a4b-d0ef191a8612a251b6a85e3079ad.nessus.v2
[+] Successfully logged out.
```

