Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T21:01:30Z
**Timeframe:** 2025-10-25T20:20:01Z to 2025-10-25T21:00:01Z
**Files Used:**
- agg_log_20251025T202001Z.json
- agg_log_20251025T204001Z.json
- agg_log_20251025T210001Z.json

### Executive Summary

This report summarizes 18,916 events captured by the honeypot network over a period of approximately 40 minutes. The majority of attacks were registered on the Honeytrap, Cowrie, and Dionaea honeypots. The most prominent attack vector was scanning and exploitation attempts against SMB (port 445) and SSH (port 22) services. A significant number of brute-force login attempts were observed, along with the execution of various shell commands aimed at reconnaissance and establishing persistence. Several vulnerabilities were targeted, including CVE-2022-27255.

### Detailed Analysis

**Attacks by Honeypot**
- Honeytrap: 5021
- Cowrie: 4746
- Dionaea: 3251
- Suricata: 3242
- Ciscoasa: 1834
- Sentrypeer: 468
- Mailoney: 113
- Tanner: 83
- Adbhoney: 24
- ConPot: 39
- Redishoneypot: 43
- Dicompot: 18
- ElasticPot: 8
- H0neytr4p: 10
- Heralding: 7
- Honeyaml: 3
- ssh-rsa: 4
- Ipphoney: 2

**Top Attacking IPs**
- 80.94.95.238: 2984
- 223.197.230.43: 3160
- 77.90.185.47: 688
- 103.123.53.88: 446
- 23.94.26.58: 417
- 143.198.201.181: 329
- 107.170.36.5: 254
- 212.233.136.201: 252
- 103.172.237.182: 234
- 150.95.157.171: 209
- 128.1.131.163: 208
- 102.88.137.80: 204
- 121.229.13.210: 210
- 94.181.229.254: 219
- 113.164.66.10: 173
- 200.225.246.102: 154
- 167.250.224.25: 155
- 118.193.61.170: 109
- 196.251.85.163: 97
- 58.98.200.129: 99

**Top Targeted Ports/Protocols**
- 445: 3209
- 22: 775
- 5060: 468
- 8333: 247
- UDP/5060: 209
- 5903: 132
- 5901: 116
- 25: 113
- 80: 97
- TCP/80: 47
- 5904: 78
- 5905: 78
- TCP/22: 69
- 5907: 51
- 5909: 52
- 5908: 48
- 23: 33
- 6379: 34

**Most Common CVEs**
- CVE-2022-27255
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-2010-0569
- CVE-1999-0183
- CVE-1999-0517
- CVE-2001-0414
- CVE-2002-1149
- CVE-2006-2369

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
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
- Enter new UNIX password:
- uname -s -v -n -r -m

**Signatures Triggered**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Sipsak SIP scan
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- GPL SCAN PING NMAP
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET DROP Spamhaus DROP Listed Traffic Inbound group 14

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 15
- root/fego253463: 4
- mariadb/mariadb: 4
- root/3245gs5662d34: 4
- root/fendant123: 4
- root/fernando: 4
- root/Ferrari360Modena!: 4
- root/fGgjk387voipvc: 4
- root/fGgjk387voipvd: 4
- root/india@2025: 3
- root/fendibober: 3
- admin/140681: 3
- admin/14061994: 3
- admin/140589: 3
- admin/1405: 3
- admin/14041980: 3
- root/fghjkl: 3

**Files Uploaded/Downloaded**
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisas
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

**HTTP User-Agents**
- N/A

**SSH Clients**
- N/A

**SSH Servers**
- N/A

**Top Attacker AS Organizations**
- N/A

### Key Observations and Anomalies
- The overwhelming majority of attacks originate from a small number of IP addresses, with `80.94.95.238` and `223.197.230.43` being particularly active.
- A recurring pattern of commands involves enumeration of system hardware (`/proc/cpuinfo`, `lscpu`), checking system load (`w`, `top`), and attempting to install a persistent SSH key in `.ssh/authorized_keys`.
- Attackers frequently attempt to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) and binaries for various architectures (ARM, x86, MIPS), indicating automated and widespread infection campaigns.
- The targeting of CVE-2022-27255 (Realtek eCos RSDK/MSDK vulnerability) is a notable recent threat vector.
- The lack of diverse HTTP User-Agents, SSH clients, or AS Organization data suggests that these fields are not being consistently logged or that the attacks are coming from sources that do not populate this information.
