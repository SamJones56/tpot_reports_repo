## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T00:01:55Z
**Timeframe:** 2025-10-06T23:20:01Z to 2025-10-07T00:00:01Z
**Files Used:**
- agg_log_20251006T232001Z.json
- agg_log_20251006T234001Z.json
- agg_log_20251007T000001Z.json

### Executive Summary

This report summarizes 11,624 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most targeted services were SSH (port 22) and SMTP (port 25). A significant number of attacks originated from the IP address 4.144.169.44. The most common commands attempted by attackers involved modifying the SSH authorized_keys file to gain persistent access. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4075
- Honeytrap: 3057
- Suricata: 1782
- Ciscoasa: 1162
- Mailoney: 845
- Sentrypeer: 455
- H0neytr4p: 69
- Dionaea: 53
- ConPot: 45
- Adbhoney: 30
- Redishoneypot: 18
- Tanner: 13
- Honeyaml: 10
- Heralding: 3
- Ipphoney: 3
- ElasticPot: 2
- ssh-rsa: 2

**Top Attacking IPs:**
- 4.144.169.44
- 176.65.141.117
- 80.94.95.238
- 172.86.95.98
- 107.173.61.177
- 51.158.108.240
- 157.230.85.50
- 118.26.36.241
- 37.193.112.180
- 128.199.24.112

**Top Targeted Ports/Protocols:**
- 25
- 22
- 5060
- 8333
- 443
- 5903
- TCP/80
- TCP/1521
- 1025
- 5909

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -m`
- `w`
- `whoami`
- `uname -a`
- `top`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344

**Users / Login Attempts (user/password):**
- 345gs5662d34/345gs5662d34
- admin/10031972
- admin/100190
- admin/100185
- admin/10000
- admin/0o9i8u
- root/admin@123
- root/adminHW
- devops/devops!
- devops/3245gs5662d34

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- No user agent data was recorded in the logs.

**SSH Clients:**
- No SSH client data was recorded in the logs.

**SSH Servers:**
- No SSH server data was recorded in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organization data was recorded in the logs.

### Key Observations and Anomalies

- A large number of commands executed by attackers are reconnaissance commands to understand the system's architecture (`uname -a`, `lscpu`, `cat /proc/cpuinfo`).
- The most common attack pattern is to gain access via SSH and then attempt to add a new SSH key to the `authorized_keys` file for persistent access.
- The attackers are using automated scripts that try a series of commands, including downloading and executing shell scripts (`wget.sh`, `w.sh`, `c.sh`).
- There is a significant amount of scanning activity, as indicated by the "ET SCAN" signatures.
- The lack of data for User-Agents, SSH clients/servers, and AS organizations might indicate a gap in the logging capabilities of some honeypots.
