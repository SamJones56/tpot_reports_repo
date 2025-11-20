# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T22:01:25Z
**Timeframe:** 2025-10-03T21:20:01Z to 2025-10-03T22:00:01Z
**Files:** agg_log_20251003T212001Z.json, agg_log_20251003T214001Z.json, agg_log_20251003T220001Z.json

## Executive Summary

This report summarizes 10540 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by the Mailoney and Ciscoasa honeypots. The most targeted services were SSH (port 22) and SMTP (port 25). A variety of CVEs were observed, with the most frequent being related to older vulnerabilities. Attackers attempted a range of commands, primarily focused on reconnaissance and establishing further access.

## Detailed Analysis

### Attacks by honeypot
- Cowrie: 4677
- Mailoney: 1694
- Ciscoasa: 1817
- Suricata: 1353
- Sentrypeer: 296
- Honeytrap: 229
- Dionaea: 182
- Heralding: 49
- ElasticPot: 45
- Adbhoney: 37
- ssh-rsa: 30
- H0neytr4p: 33
- ConPot: 22
- Redishoneypot: 21
- Tanner: 29
- Miniprint: 10
- Honeyaml: 16

### Top attacking IPs
- 176.65.141.117: 1640
- 47.97.202.123: 1244
- 77.239.96.92: 469
- 103.174.215.18: 351
- 106.75.131.128: 202
- 193.32.162.157: 185
- 81.192.46.45: 222
- 139.59.119.25: 189
- 185.156.73.166: 226
- 80.238.234.114: 227
- 103.252.73.219: 133
- 46.105.87.113: 180
- 103.241.43.23: 100
- 80.97.160.168: 130
- 64.188.92.102: 134
- 106.12.35.31: 124
- 155.4.244.169: 73
- 206.189.152.59: 68
- 10.208.0.3: 49

### Top targeted ports/protocols
- 25: 1694
- 22: 813
- 5060: 296
- vnc/5900: 49
- 3306: 71
- 445: 84
- TCP/445: 32
- 9200: 44
- TCP/22: 22
- 23: 32
- 80: 33
- 443: 33
- 6379: 21
- 1025: 19
- TCP/80: 32
- UDP/53: 18

### Most common CVEs
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3

### Commands attempted by attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 16
- `lockr -ia .ssh`: 16
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 16
- `cat /proc/cpuinfo | grep name | wc -l`: 10
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 10
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 10
- `ls -lh $(which ls)`: 10
- `which ls`: 10
- `crontab -l`: 10
- `w`: 10
- `uname -m`: 10
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 10
- `top`: 10
- `uname`: 10
- `uname -a`: 10
- `whoami`: 10
- `lscpu | grep Model`: 10
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 10
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 5
- `Enter new UNIX password: `: 4

### Signatures triggered
- ET DROP Dshield Block Listed Source group 1: 357
- 2402000: 357
- ET SCAN NMAP -sS window 1024: 188
- 2009582: 188
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61
- ET INFO VNC Authentication Failure: 48
- 2002920: 48
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 28
- 2024766: 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 30
- 2403350: 30
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 28
- 2403348: 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 28
- 2403343: 28

### Users / login attempts
- a2billinguser/: 68
- root/: 32
- 345gs5662d34/345gs5662d34: 14
- root/nPSpP4PBW0: 9
- test/zhbjETuyMffoL8F: 4
- root/LeitboGi0ro: 4
- admin/kjashd123sadhj123d1SS: 3
- test/3245gs5662d34: 3
- root/3245gs5662d34: 4
- root/2glehe5t24th1issZs: 4

### Files uploaded/downloaded
- `arm.urbotnetisass;`: 2
- `arm.urbotnetisass`: 2
- `arm5.urbotnetisass;`: 2
- `arm5.urbotnetisass`: 2
- `arm6.urbotnetisass;`: 2
- `arm6.urbotnetisass`: 2
- `arm7.urbotnetisass;`: 2
- `arm7.urbotnetisass`: 2
- `x86_32.urbotnetisass;`: 2
- `x86_32.urbotnetisass`: 2
- `mips.urbotnetisass;`: 2
- `mips.urbotnetisass`: 2
- `mipsel.urbotnetisass;`: 2
- `mipsel.urbotnetisass`: 2
- `wget.sh;`: 4
- `w.sh;`: 1
- `c.sh;`: 1
- `11`: 2
- `fonts.gstatic.com`: 2
- `css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext`: 2
- `ie8.css?ver=1.0`: 2
- `html5.js?ver=3.7.3`: 2
- `soap-envelope`: 1
- `addressing`: 1
- `discovery`: 1
- `env:Envelope>`: 1

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH clients and servers
- No SSH clients or servers were logged in this timeframe.

### Top attacker AS organizations
- No AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- A significant amount of reconnaissance and automated attacks were observed, as indicated by the high number of events from Cowrie and the variety of commands attempted.
- The most common commands are related to system information gathering, which is typical of automated scripts looking for vulnerable systems.
- The presence of commands related to downloading and executing scripts (e.g., `wget`, `curl`) indicates that attackers are attempting to deploy malware on the honeypot.
- The variety of usernames and passwords attempted suggests that attackers are using common credential lists to gain access.
- The triggered Suricata signatures indicate that attackers are using well-known scanning and exploitation techniques.
- The lack of HTTP User-Agents, SSH clients, and AS organizations in the logs is unusual and may warrant further investigation.
