Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T14:01:31Z
**Timeframe:** 2025-10-07T13:20:01Z to 2025-10-07T14:00:01Z
**Files Used:**
- agg_log_20251007T132001Z.json
- agg_log_20251007T134001Z.json
- agg_log_20251007T140001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 18,065 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and SIP (Sentrypeer). A significant portion of the attacks originated from IP address 23.94.26.58. Multiple CVEs were targeted, with a focus on older vulnerabilities. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 7300
*   Sentrypeer: 3432
*   Honeytrap: 2704
*   Suricata: 1727
*   Mailoney: 869
*   Ciscoasa: 420
*   H0neytr4p: 426
*   Miniprint: 82
*   Tanner: 79
*   Heralding: 104
*   Adbhoney: 42
*   ConPot: 23
*   Dicompot: 12
*   Ipphoney: 10
*   ElasticPot: 8
*   Dionaea: 8
*   ssh-rsa: 6
*   Redishoneypot: 6
*   Honeyaml: 7

***Top Attacking IPs***

*   23.94.26.58: 2579
*   176.65.141.117: 820
*   114.217.32.132: 1154
*   172.237.112.229: 418
*   185.255.126.223: 569
*   94.183.188.216: 217
*   161.35.71.172: 342
*   147.45.50.147: 342
*   45.140.17.52: 387
*   162.214.126.1: 287
*   43.161.245.90: 332
*   190.119.63.98: 193
*   192.42.116.179: 170
*   95.163.176.177: 154
*   38.100.203.79: 125
*   103.76.120.90: 125
*   118.193.61.170: 119
*   45.84.107.182: 115
*   185.220.101.32: 113
*   172.86.95.98: 227

***Top Targeted Ports/Protocols***

*   5060: 3432
*   22: 990
*   25: 869
*   443: 421
*   6000: 206
*   8333: 184
*   TCP/1080: 117
*   socks5/1080: 104
*   9100: 82
*   80: 59
*   5903: 95
*   2222: 54
*   8090: 45
*   6443: 35
*   8081: 35
*   4891: 34
*   8888: 34
*   9000: 32
*   9999: 32
*   8088: 31

***Most Common CVEs***

*   CVE-2021-44228: 28
*   CVE-1999-0265: 32
*   CVE-2002-0013 CVE-2002-0012: 23
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 17
*   CVE-2006-2369: 1
*   CVE-2019-11500 CVE-2019-11500: 1
*   CVE-2024-4577 CVE-2002-0953: 2
*   CVE-2024-4577 CVE-2024-4577: 2
*   CVE-2023-26801 CVE-2023-26801: 1
*   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
*   CVE-2021-42013 CVE-2021-42013: 1
*   CVE-2021-35394 CVE-2021-35394: 1

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 39
*   `lockr -ia .ssh`: 39
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 38
*   `cat /proc/cpuinfo | grep name | wc -l`: 39
*   `Enter new UNIX password: `: 39
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 39
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 39
*   `ls -lh $(which ls)`: 38
*   `which ls`: 38
*   `crontab -l`: 38
*   `w`: 39
*   `uname -m`: 39
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 39
*   `top`: 39
*   `uname`: 38
*   `uname -a`: 38
*   `whoami`: 39
*   `lscpu | grep Model`: 39
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 38

***Signatures Triggered***

*   ET DROP Dshield Block Listed Source group 1: 541
*   ET SCAN NMAP -sS window 1024: 149
*   ET INFO Reserved Internal IP Traffic: 56
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 15
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 7
*   ET CINS Active Threat Intelligence Poor Reputation IP group 68: 13
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 272
*   ET SCAN Suspicious inbound to MSSQL port 1433: 6
*   ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228): 5
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 5
*   GPL ICMP redirect host: 28
*   ET SCAN Suspicious inbound to Oracle SQL port 1521: 13
*   ET INFO CURL User Agent: 20
*   ET CINS Active Threat Intelligence Poor Reputation IP group 2: 6
*   GPL INFO SOCKS Proxy attempt: 115
*   GPL SNMP request udp: 18
*   GPL SNMP public access udp: 17
*   ET CINS Active Threat Intelligence Poor Reputation IP group 66: 12

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 37
*   sysadmin/sysadmin@1: 21
*   manager/manager!: 4
*   vpn/vpn12345: 4
*   mcserver/P@ssw0rd1: 3
*   sysadmin/sysadmin: 3
*   newuser/newuser321: 2
*   tempuser/tempuser123: 2
*   nginx/123123: 2
*   ubuntu/3245gs5662d34: 2
*   git/gitpass: 2
*   amir/123456789: 2
*   amir/3245gs5662d34: 2
*   kafka/kafka.123: 2
*   erpnext/erpnext!: 2
*   support/support.123: 2
*   nginx/nginx@123: 2
*   user2/123: 2
*   ubuntu/Ubuntu123: 2
*   elasticsearch/elasticsearch!: 2

***Files Uploaded/Downloaded***

*   sh: 98
*   wget.sh;: 16
*   w.sh;: 4
*   c.sh;: 4
*   cmd.txt: 1
*   boatnet.mpsl;: 1

***HTTP User-Agents***

*   No HTTP user agents were recorded in this period.

***SSH Clients and Servers***

*   No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations***

*   No attacker AS organizations were identified in the logs.

**Key Observations and Anomalies**

*   The high number of attacks from a single IP (23.94.26.58) suggests a targeted or persistent attacker.
*   The commands attempted indicate a focus on system reconnaissance and establishing a foothold via SSH authorized_keys.
*   The wide range of CVEs targeted, including very old ones, suggests automated scanning tools looking for any vulnerable system.
*   The presence of `boatnet.mpsl` in downloaded files indicates attempts to install botnet clients.

This concludes the Honeypot Attack Summary Report.
