Honeypot Attack Summary Report

Report Generation Time: 2025-10-01T12:01:34Z
Timeframe: 2025-10-01T11:20:01Z to 2025-10-01T12:00:01Z
Files Used:
- agg_log_20251001T112001Z.json
- agg_log_20251001T114002Z.json
- agg_log_20251001T120001Z.json

Executive Summary:
This report summarizes honeypot activity over the last hour, based on three log files. A total of 14,989 events were recorded. The most targeted honeypot was Cowrie, and the most frequent attacker IP was 202.47.39.39. The most targeted port was 445/TCP, commonly used for SMB. Several CVEs were targeted, with a focus on remote code execution vulnerabilities. Attackers attempted a variety of commands, including reconnaissance and attempts to download and execute malicious scripts.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 5815
- Dionaea: 3568
- Suricata: 2565
- Honeytrap: 1415
- Ciscoasa: 1412
- Adbhoney: 43
- Redishoneypot: 49
- H0neytr4p: 31
- Sentrypeer: 35
- Tanner: 20
- Mailoney: 14
- ElasticPot: 6
- Dicompot: 6
- ConPot: 7
- ssh-rsa: 2
- Honeyaml: 1

Top Attacking IPs:
- 202.47.39.39: 3133
- 129.212.186.229: 2164
- 181.124.146.45: 1339
- 89.111.163.67: 1238
- 185.156.73.167: 363
- 185.156.73.166: 362
- 92.63.197.55: 355
- 92.63.197.59: 327
- 81.215.207.182: 375
- 88.210.63.16: 309
- 160.251.196.99: 262
- 187.33.59.116: 178
- 64.227.184.250: 120
- 67.217.243.120: 119
- 103.183.74.214: 116
- 103.157.25.60: 116
- 49.204.74.149: 111
- 223.197.186.7: 98
- 137.184.202.107: 86
- 14.63.196.175: 78

Top Targeted Ports/Protocols:
- 445: 3530
- 22: 984
- 3388: 84
- 8333: 141
- 5060: 34
- 6379: 49
- 23: 99
- 80: 17
- 443: 29
- 1433: 17
- 5431: 17
- 8092: 24
- 9200: 6
- 25: 9
- 135: 6

Most Common CVEs:
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2009-2765
- CVE-2016-6563
- CVE-2016-20016
- CVE-2001-0414

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...
- uname -s -v -n -r -m
- free -m | grep Mem | ...
- ls -lh $(which ls)
- cd /data/local/tmp/; rm *; busybox wget ...
- Enter new UNIX password:

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- GPL TELNET Bad Login
- ET SCAN Potential SSH Scan

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/3245gs5662d34
- root/zhbjETuyMffoL8F
- agent/agent
- work/workwork
- itsupport/itsupport123
- user/user
- root/12345
- ubuntu/ubuntu

Files Uploaded/Downloaded:
- Mozi.m
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- wget.sh
- w.sh
- c.sh

HTTP User-Agents:
- (No data in logs)

SSH Clients:
- (No data in logs)

SSH Servers:
- (No data in logs)

Top Attacker AS Organizations:
- (No data in logs)

Key Observations and Anomalies:
- A significant amount of scanning activity was observed on port 445, likely related to SMB vulnerabilities.
- The DoublePulsar backdoor was detected, indicating attempts to compromise systems with sophisticated malware.
- Attackers frequently attempted to add their own SSH keys to the authorized_keys file for persistent access.
- Multiple download attempts of ELF executables for various architectures (ARM, MIPS, x86) were observed, suggesting automated attacks targeting a wide range of IoT devices.
- The commands and filenames suggest the use of the "urbotnetisass" botnet.
- The CVEs targeted are a mix of old and new vulnerabilities, indicating that attackers are still exploiting legacy systems.