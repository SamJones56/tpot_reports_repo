## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T22:01:38Z
**Timeframe:** 2025-10-08T21:20:01Z to 2025-10-08T22:00:01Z
**Files Used:**
- agg_log_20251008T212001Z.json
- agg_log_20251008T214001Z.json
- agg_log_20251008T220001Z.json

### Executive Summary

This report summarizes 14,954 attacks recorded across three log files. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from the IP address 79.134.202.162. The most targeted port was TCP/445, commonly associated with SMB. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access. The most triggered signature was related to the DoublePulsar backdoor.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 7495
* Honeytrap: 2736
* Suricata: 2591
* Ciscoasa: 1627
* Mailoney: 169
* Sentrypeer: 123
* Dionaea: 69
* Tanner: 39
* H0neytr4p: 34
* Honeyaml: 26
* Redishoneypot: 19
* ConPot: 13
* Adbhoney: 5
* ElasticPot: 4
* Dicompot: 3
* Ipphoney: 1

**Top Attacking IPs:**
* 79.134.202.162
* 5.167.79.4
* 103.177.248.157
* 119.29.90.180
* 103.145.145.74
* 95.85.114.218
* 209.141.52.88
* 51.89.150.103
* 91.108.227.22
* 101.250.60.4
* 121.52.154.238
* 210.79.190.22
* 201.249.205.94

**Top Targeted Ports/Protocols:**
* TCP/445
* 22
* 5903
* 8333
* 25
* 5060
* 5901
* TCP/22

**Most Common CVEs:**
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2019-11500
* CVE-2023-26801
* CVE-2021-3449

**Commands Attempted by Attackers:**
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* Enter new UNIX password:
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* ls -lh $(which ls)
* which ls
* crontab -l
* w
* uname -m
* whoami
* top
* uname
* uname -a

**Signatures Triggered:**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
* 2024766
* ET DROP Dshield Block Listed Source group 1
* 2402000
* ET SCAN NMAP -sS window 1024
* 2009582
* ET INFO Reserved Internal IP Traffic
* 2002752
* ET SCAN Potential SSH Scan
* 2001219
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* 2023753

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* support/support2
* blank/blank88
* ubuntu/3245gs5662d34
* vpn/vpn123321
* support/123567
* userbot/userbot
* jenkins/3245gs5662d34

**Files Uploaded/Downloaded:**
* parm;
* parm5;
* parm6;
* parm7;
* psh4;
* parc;
* pmips;
* pmipsel;
* psparc;
* px86_64;
* pi686;
* pi586;
* w.sh;
* c.sh;

**HTTP User-Agents:**
* No user agents were logged in this period.

**SSH Clients and Servers:**
* No specific SSH clients or servers were logged in this period.

**Top Attacker AS Organizations:**
* No AS organization data was available in the logs.

### Key Observations and Anomalies

* The high number of attacks on TCP/445, along with the DoublePulsar signature, suggests continued automated exploitation attempts related to the EternalBlue vulnerability.
* The commands attempted by attackers indicate a clear pattern of reconnaissance to understand the system architecture (CPU, memory, etc.) followed by attempts to establish persistence by adding an SSH key to `authorized_keys`.
* One of the "interesting" commands includes a `wget` command to download and execute shell scripts (`w.sh`, `c.sh`) from a remote server (141.98.10.66), indicating a multi-stage attack.
* There is a significant amount of credential stuffing and brute-force attempts with common and default usernames and passwords.
* The lack of HTTP User-Agents, SSH client/server info, and AS organization data might indicate that these fields were not consistently logged or that the attacks did not involve protocols where this information would be present.
