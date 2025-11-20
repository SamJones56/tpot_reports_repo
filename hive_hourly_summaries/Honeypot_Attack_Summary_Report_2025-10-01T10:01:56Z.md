
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T10:01:29Z
**Timeframe:** 2025-10-01T09:20:01Z to 2025-10-01T10:00:01Z
**Files Used:**
- agg_log_20251001T092001Z.json
- agg_log_20251001T094001Z.json
- agg_log_20251001T100001Z.json

## Executive Summary

This report summarizes 11,420 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. Top attacking IPs originate from various geolocations, with a significant number of attacks targeting ports 445, 22 and 25. Several CVEs were exploited, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Analysis of attacker commands reveals a focus on system reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 3694
- Honeytrap: 2318
- Suricata: 1622
- Mailoney: 1289
- Dionaea: 865
- Ciscoasa: 947
- Redishoneypot: 56
- H0neytr4p: 46
- Tanner: 25
- Honeyaml: 27
- ConPot: 22
- Adbhoney: 10
- ElasticPot: 4
- Dicompot: 4
- Sentrypeer: 5
- Wordpot: 2
- Ipphoney: 3

### Top Attacking IPs
- 101.201.32.249: 1240
- 87.106.35.227: 973
- 86.54.42.238: 821
- 136.158.39.93: 845
- 92.242.166.161: 414
- 88.210.63.16: 449
- 185.156.73.166: 374
- 185.156.73.167: 362
- 92.63.197.55: 351
- 92.63.197.59: 332
- 101.36.107.103: 231
- 23.91.96.123: 232
- 115.91.91.182: 241
- 161.35.152.121: 101
- 196.251.84.92: 141
- 114.67.89.99: 124

### Top Targeted Ports/Protocols
- 25: 1289
- 22: 645
- 445: 845
- 8333: 114
- 6379: 56
- 443: 70
- 80: 50
- TCP/3388: 18
- UDP/161: 45
- 10001: 14
- 8090: 25
- 23: 30
- 31337: 12

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0517
- CVE-2005-4050
- CVE-1999-0183

### Commands Attempted by Attackers
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
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
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- echo "root:taY20v2QSxqf"|chpasswd|bash
- start
- config terminal
- system
- linuxshell
- shell
- echo -ne \\x45\\x4c\\x46
- uname -s -v -n -r -m

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- GPL INFO SOCKS Proxy attempt
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 66
- GPL SNMP request udp
- GPL SNMP public access udp
- ET SCAN Potential SSH Scan
- ET INFO CURL User Agent

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- seekcy/Joysuch@Locate2024
- tmp/tmp@123
- user1/123456789
- root/123@Password
- devops/qwerty123
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- habib/habib
- root/nPSpP4PBW0
- admin/q1w2e3r4t5y6
- root/abc123
- admin/1234

### Files Uploaded/Downloaded
- s:Envelope>
- i;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
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
- i

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- A significant number of commands are geared towards establishing persistent SSH access by adding a public key to `authorized_keys`.
- The file downloads of `arm.urbotnetisass` and related files indicate a malware campaign targeting various CPU architectures.
- The high volume of scans for MS Terminal Server on non-standard ports suggests widespread scanning for vulnerable RDP services.
- The presence of commands like `config terminal` suggests some attacks are targeting network devices.
- The CVEs detected are relatively old, indicating that attackers are still targeting legacy systems and unpatched vulnerabilities.
- There were no HTTP User-Agents, SSH clients, or server software identified in the logs provided.
- Similarly, no AS organization data was available in the logs.
