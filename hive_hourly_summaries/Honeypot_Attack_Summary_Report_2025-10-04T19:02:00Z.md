
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T19:01:41Z
**Timeframe:** 2025-10-04T18:20:01Z to 2025-10-04T19:00:01Z
**Files Used:**
- agg_log_20251004T182001Z.json
- agg_log_20251004T184001Z.json
- agg_log_20251004T190001Z.json

## Executive Summary

This report summarizes 8,105 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie, Ciscoasa, Suricata, Dionaea, and Mailoney honeypots. A significant amount of activity involved reconnaissance and brute-force attempts against SSH (port 22), SMB (port 445), and SMTP (port 25). Attackers were observed attempting to install SSH keys and execute system enumeration commands. Multiple CVEs were targeted, and a high number of security signatures were triggered, primarily related to blocklisted IPs and port scanning.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 3,252
- **Ciscoasa:** 1,562
- **Suricata:** 1,008
- **Dionaea:** 927
- **Mailoney:** 857
- **Honeytrap:** 219
- **Sentrypeer:** 80
- **Adbhoney:** 56
- **H0neytr4p:** 44
- **Tanner:** 36
- **ConPot:** 20
- **Honeyaml:** 19
- **Redishoneypot:** 15
- **ElasticPot:** 4
- **Heralding:** 3
- **Medpot:** 2
- **Ipphoney:** 1

### Top Attacking IPs
- 15.235.131.242
- 176.65.141.117
- 51.178.43.161
- 185.216.117.150
- 178.128.124.111
- 150.5.129.10
- 165.154.205.128
- 191.242.105.131
- 87.251.77.103
- 27.254.137.144

### Top Targeted Ports/Protocols
- 445
- 25
- 22
- 5060
- 23
- TCP/80
- 443
- 80
- TCP/1433
- TCP/1080

### Most Common CVEs
- CVE-2002-0012
- CVE-2002-0013
- CVE-2003-0825
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2009-2765
- CVE-2014-6271
- CVE-2015-2051
- CVE-2019-10891
- CVE-2019-11500
- CVE-2019-16920
- CVE-2021-3449
- CVE-2021-42013
- CVE-2022-37056
- CVE-2023-26801
- CVE-2023-31983
- CVE-2023-47565
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-12856
- CVE-2024-12885
- CVE-2024-33112
- CVE-2024-3721

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- lockr -ia .ssh
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- uname -a
- whoami
- rm -rf /data/local/tmp/*

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET SCAN Suspicious inbound to PostgreSQL port 5432

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- novinhost/novinhost.org
- root/3245gs5662d34
- alves/alves
- root/2glehe5t24th1issZs
- debian/Debian@2025
- csgo/csgo
- user01/user01123
- frappe/admin123

### Files Uploaded/Downloaded
- wget.sh;
- 129.212.146.61
- rondo.dgx.sh||busybox
- rondo.dgx.sh||curl
- rondo.dgx.sh)|sh&
- w.sh;
- c.sh;
- apply.cgi
- rondo.tkg.sh|sh&echo
- rondo.qre.sh||busybox

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were recorded in this period.

### Top Attacker AS Organizations
- No AS organizations were recorded in this period.

## Key Observations and Anomalies

- **High Volume of Mail Scans:** The Mailoney honeypot recorded a significant spike in activity, primarily from the IP `176.65.141.117`, indicating a targeted scan or attack campaign against SMTP services.
- **SMB Exploitation Attempts:** The Dionaea honeypot captured a large number of connections on port 445, with IP `15.235.131.242` being the most prominent source. This suggests attempts to exploit SMB vulnerabilities, possibly related to services like WannaCry/EternalBlue.
- **Repetitive Reconnaissance Commands:** Attackers consistently executed a standard set of commands (`uname -a`, `whoami`, `cat /proc/cpuinfo`, etc.) across multiple sessions. A recurring pattern involved attempts to clear existing SSH configurations and install a new authorized key, indicating automated scripts designed for mass infection.
- **Script Downloads:** Multiple attackers attempted to download and execute shell scripts (e.g., `w.sh`, `c.sh`, `wget.sh`, `rondo.*.sh`) from external servers. This is a common tactic for deploying malware or botnet clients.
