# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T00:01:37Z

**Timeframe:** 2025-10-16T23:20:01Z to 2025-10-17T00:00:01Z

**Files Used:**
- agg_log_20251016T232001Z.json
- agg_log_20251016T234002Z.json
- agg_log_20251017T000001Z.json

## Executive Summary

This report summarizes 15,948 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Dionaea and Honeytrap. The most prominent attacker IP was 171.102.83.142, and the most targeted port was 445/TCP. A variety of CVEs were observed, with the most frequent being CVE-2002-0013 and CVE-2002-0012. Attackers attempted a range of commands, primarily focused on reconnaissance and establishing persistent access. The Suricata IDS detected a high volume of traffic from sources on the Dshield blocklist.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 5076
- Dionaea: 2814
- Honeytrap: 3202
- Sentrypeer: 1552
- Suricata: 1452
- Ciscoasa: 1643
- Mailoney: 107
- Tanner: 24
- Redishoneypot: 18
- ConPot: 13
- H0neytr4p: 16
- Honeyaml: 11
- Adbhoney: 7
- ElasticPot: 5
- ssh-rsa: 4
- Heralding: 3
- Ipphoney: 1

### Top Attacking IPs

- 171.102.83.142: 2746
- 196.251.88.103: 993
- 172.86.95.115: 527
- 172.86.95.98: 507
- 41.111.178.165: 329
- 185.243.5.158: 342
- 14.116.156.100: 334
- 185.40.30.168: 306
- 107.170.36.5: 251
- 125.21.53.232: 183

### Top Targeted Ports/Protocols

- 445: 2750
- 5060: 1552
- 22: 774
- 5903: 227
- 8333: 144
- 25: 112
- 5901: 116
- 1935: 117

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2024-11120 CVE-2024-6047: 3
- CVE-2001-0414: 3
- CVE-2019-11500 CVE-2019-11500: 3

### Commands Attempted by Attackers

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 29
- lockr -ia .ssh: 29
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 29
- cat /proc/cpuinfo | grep name | wc -l: 19
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 19
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
- ls -lh $(which ls): 19
- which ls: 19
- crontab -l: 19
- w: 19
- uname -m: 19
- cat /proc/cpuinfo | grep model | grep name | wc -l: 19
- top: 19
- uname: 19
- uname -a: 19
- whoami: 19
- lscpu | grep Model: 19
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 18
- Enter new UNIX password: : 10
- Enter new UNIX password::: 8

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 434
- 2402000: 434
- ET SCAN NMAP -sS window 1024: 160
- 2009582: 160
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 126
- 2023753: 126
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET HUNTING RDP Authentication Bypass Attempt: 45
- 2034857: 45

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 28
- root/123@@@: 13
- sa/1165: 10
- root/3245gs5662d34: 10
- root/Qaz123qaz: 11

### Files Uploaded/Downloaded

- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- ): 1
- SOAP-ENV:Envelope>: 5

### HTTP User-Agents

- No HTTP user-agents were recorded in this period.

### SSH Clients and Servers

- No SSH clients or servers were recorded in this period.

### Top Attacker AS Organizations

- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

- The attacker at 171.102.83.142 was particularly persistent, generating a large volume of traffic targeting port 445.
- The commands attempted by attackers suggest a focus on reconnaissance and establishing persistent access through SSH authorized_keys.
- The `urbotnetisass` malware was downloaded, indicating an attempt to infect the honeypot with a botnet client.
- A significant number of Suricata alerts were for traffic from IPs on the Dshield blocklist, indicating that the honeypot is being targeted by known malicious actors.
