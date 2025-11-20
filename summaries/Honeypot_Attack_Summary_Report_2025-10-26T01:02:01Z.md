Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T01:01:41Z
**Timeframe:** 2025-10-26T00:20:01Z to 2025-10-26T01:00:01Z
**Files Used:**
- agg_log_20251026T002001Z.json
- agg_log_20251026T004001Z.json
- agg_log_20251026T010001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 15,530 attacks were recorded. The most active honeypots were Honeytrap, Suricata, and Cowrie. The majority of attacks originated from the IP address 80.94.95.238. Port 445 (SMB) was the most targeted port, and several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. A variety of commands were attempted by attackers, primarily focusing on system enumeration and establishing persistence.

**Detailed Analysis**

**Attacks by Honeypot:**
- Honeytrap: 4796
- Suricata: 3945
- Cowrie: 2467
- Dionaea: 2019
- Ciscoasa: 1869
- Sentrypeer: 177
- Mailoney: 115
- Tanner: 59
- H0neytr4p: 30
- ElasticPot: 17
- Heralding: 13
- Redishoneypot: 9
- ConPot: 5
- Adbhoney: 4
- Dicompot: 3
- Wordpot: 1
- Honeyaml: 1

**Top Attacking IPs:**
- 80.94.95.238: 2881
- 103.7.81.84: 1968
- 109.205.211.9: 1487
- 72.167.220.12: 1249
- 104.248.84.184: 330
- 107.170.36.5: 236
- 77.83.207.203: 126
- 167.250.224.25: 120
- 68.183.149.135: 110
- 130.83.245.115: 94

**Top Targeted Ports/Protocols:**
- 445: 1973
- 22: 468
- 8333: 250
- 5060: 177
- 25: 115
- 5903: 115
- 5901: 100
- 5904: 79
- 5905: 70
- 80: 46

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2005-4050: 1
- CVE-1999-0183: 1

**Commands Attempted by Attackers:**
- uname -a
- uname -s -v -n -r -m
- cat /proc/uptime 2 > /dev/null | cut -d. -f1
- chmod +x clean.sh; sh clean.sh; rm -rf clean.sh; chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys; echo "ssh-rsa ..." > ~/.ssh/authorized_keys; chattr +ai ~/.ssh/authorized_keys; uname -a; echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- export PATH=...; uname=...; arch=...; uptime=...; cpus=...; cpu_model=...; gpu_info=...; cat_help=...; ls_help=...; last_output=...; echo ...
- uname -s -v -n -m 2 > /dev/null
- uname -m 2 > /dev/null
- cat /proc/cpuinfo | grep name | wc -l
- echo -e "..."|passwd|bash
- Enter new UNIX password:
- Enter new UNIX password: 
- echo "..."|passwd
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

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2173
- 2023753: 2173
- ET HUNTING RDP Authentication Bypass Attempt: 433
- ET DROP Dshield Block Listed Source group 1: 418
- 2402000: 418
- ET SCAN NMAP -sS window 1024: 171
- 2009582: 171
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 25

**Users / Login Attempts:**
- root/Forkidskz46954695whitepbxc0nv3rg14A.LangeTc2990eeec0nv3rg14jnfZCqUrWAn5Onelove
- root/fortewdfjklcg99
- admin/13111978
- admin/13091976
- admin/13081976
- admin/130789
- admin/13061995
- root/root123
- root/fostatil11
- root/fp758x
- root/fpstirnd
- root/Fr33Adm!n
- postgres/postgres
- postgres/123
- root/P@ssw0rd
- root/p@ssw0rd
- root/Passw0rd
- admin/admin123
- erp/erp123
- root/zhaowei123

**Files Uploaded/Downloaded:**
- )

**HTTP User-Agents:**
- None

**SSH Clients:**
- None

**SSH Servers:**
- None

**Top Attacker AS Organizations:**
- None

**Key Observations and Anomalies**

- The high number of attacks on port 445 (SMB) suggests widespread scanning for vulnerabilities like EternalBlue.
- The variety of credentials used in login attempts indicates brute-force attacks are ongoing.
- The commands executed by attackers show a clear pattern of reconnaissance and attempts to establish persistent access through SSH keys.
- The presence of commands related to password changes and system cleanup suggests more sophisticated attackers attempting to cover their tracks.
- The "ET SCAN MS Terminal Server Traffic on Non-standard Port" signature was the most frequently triggered, indicating a high volume of RDP scanning activity.
- The file named ")" being uploaded is anomalous and may indicate a malformed script or an attempt to exploit a vulnerability in the file upload handling.

This concludes the Honeypot Attack Summary Report.
