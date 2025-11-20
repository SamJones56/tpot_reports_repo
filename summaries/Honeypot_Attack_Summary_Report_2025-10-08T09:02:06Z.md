# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T09:01:38Z
**Timeframe:** 2025-10-08T08:20:02Z to 2025-10-08T09:00:01Z
**Files Used:**
- `agg_log_20251008T082002Z.json`
- `agg_log_20251008T084002Z.json`
- `agg_log_20251008T090001Z.json`

## Executive Summary

This report summarizes 18,434 events recorded across the honeypot infrastructure over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Dionaea and Suricata. The most frequent attacks targeted SMB (port 445) and SSH (port 22) services. A large number of events are associated with the DoublePulsar backdoor. Attackers were observed attempting to enumerate system information and install unauthorized SSH keys.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7,984
- **Dionaea:** 2,817
- **Suricata:** 2,773
- **Honeytrap:** 2,617
- **Ciscoasa:** 1,571
- **Heralding:** 301
- **Sentrypeer:** 179
- **Mailoney:** 64
- **H0neytr4p:** 45
- **Tanner:** 28
- **Redishoneypot:** 17
- **ConPot:** 12
- **Miniprint:** 10
- **ElasticPot:** 8
- **Adbhoney:** 4
- **Honeyaml:** 4

### Top Attacking IPs
- 81.16.14.2: 1,477
- 182.176.117.154: 1,098
- 5.141.26.114: 1,126
- 129.212.187.23: 656
- 202.163.71.222: 411
- 185.156.174.178: 301
- 114.204.9.108: 331
- 46.32.178.186: 510
- 103.172.205.68: 287
- 200.44.190.194: 332

### Top Targeted Ports/Protocols
- 445: 2,741
- TCP/445: 1,522
- 22: 1,092
- 5060: 179
- vnc/5900: 301
- 8333: 86
- 5903: 94
- 25: 64
- 5901: 77
- 6667: 63

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0517

### Commands Attempted by Attackers
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `top`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- GPL INFO SOCKS Proxy attempt
- 2100615
- ET INFO Reserved Internal IP Traffic
- 2002752

### Users / Login Attempts (Top 10)
- 345gs5662d34/345gs5662d34
- sysadmin/sysadmin@1
- sysadmin/3245gs5662d34
- support/support13
- root/Root11
- root/951951
- tempuser/3245gs5662d34
- oracle/oracle
- vncuser/P@ssw0rd
- deployer/deployer

### Files Uploaded/Downloaded
- No file upload or download activity was observed during the reporting period.

### HTTP User-Agents
- No HTTP user-agent data was recorded.

### SSH Clients and Servers
- No specific SSH client or server software versions were identified in the logs.

### Top Attacker AS Organizations
- No attacker AS organization data was available in the logs.

## Key Observations and Anomalies
- The overwhelming number of events related to the DoublePulsar backdoor suggests a targeted campaign or automated scanning for this vulnerability.
- Attackers consistently attempt to add their own SSH key to the `authorized_keys` file, indicating a clear objective of gaining persistent access.
- The commands executed are primarily for reconnaissance, aiming to understand the system architecture and available resources.
- The IP address `81.16.14.2` was responsible for a large volume of attacks in a short period, focusing on SMB services.
