Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T15:01:27Z
**Timeframe:** 2025-10-04T14:20:01Z to 2025-10-04T15:00:01Z
**Files Used:**
- agg_log_20251004T142001Z.json
- agg_log_20251004T144001Z.json
- agg_log_20251004T150001Z.json

**Executive Summary:**
This report summarizes honeypot activity over a period of approximately 40 minutes, based on three aggregated log files. A total of 10,614 attacks were recorded. The most targeted services were Cowrie (SSH), Dionaea (SMB), and Ciscoasa (Firewall). The majority of attacks originated from IP address 159.223.50.114. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to gain access via SSH using common and default credentials.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 4469
- Dionaea: 2413
- Ciscoasa: 1486
- Mailoney: 844
- Suricata: 773
- Sentrypeer: 203
- Honeytrap: 134
- Miniprint: 107
- H0neytr4p: 64
- Tanner: 25
- ConPot: 26
- Adbhoney: 19
- Redishoneypot: 19
- Dicompot: 14
- Honeyaml: 11
- Ipphoney: 4
- ElasticPot: 3

**Top Attacking IPs:**
- 159.223.50.114: 1253
- 15.235.131.242: 1168
- 111.255.69.129: 1168
- 176.65.141.117: 820
- 85.208.253.217: 438
- 194.5.192.95: 428
- 83.168.107.46: 387
- 157.10.52.50: 364
- 45.120.216.232: 256
- 103.171.85.186: 256
- 89.126.208.24: 188
- 47.239.219.128: 126
- 46.105.87.113: 121
- 45.186.251.70: 115
- 101.44.35.141: 113
- 103.115.24.11: 103
- 45.234.176.18: 97
- 65.254.93.52: 80
- 185.243.5.68: 68
- 3.134.148.59: 64

**Top Targeted Ports/Protocols:**
- 445: 2364
- 25: 844
- 22: 651
- 5060: 203
- 9100: 107
- 443: 64
- 23: 63
- TCP/5432: 52
- 80: 29
- TCP/80: 25
- TCP/22: 24
- 6379: 19
- TCP/1433: 12

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2005-4050

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- uname -a
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- uname -s -v -n -r -m
- tftp; wget; /bin/busybox JUHWN

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- 2010939

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/nPSpP4PBW0
- testing/1qaz2wsx
- root/1008
- partner/partner
- traefik/traefik123
- root/LeitboGi0ro

**Files Uploaded/Downloaded:**
- w.sh
- c.sh
- wget.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients and Servers:**
- No SSH clients or servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

**Key Observations and Anomalies:**
- A significant amount of activity was seen from a small number of IP addresses, suggesting targeted attacks or botnet activity.
- The most common commands attempted by attackers involve reconnaissance of the system, such as checking CPU and memory information, and attempts to add SSH keys for persistence.
- A number of attacks involved attempts to download and execute shell scripts, as well as ELF executables for various architectures (ARM, x86, MIPS).
- The CVEs detected are relatively old, suggesting that attackers are scanning for unpatched systems.
- The high number of attacks on port 445 (SMB) indicates widespread scanning for vulnerabilities like EternalBlue.

This concludes the Honeypot Attack Summary Report.
