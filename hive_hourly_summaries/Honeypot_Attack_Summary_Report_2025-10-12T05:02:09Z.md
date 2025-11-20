# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T05:01:39Z

**Timeframe of Report:** 2025-10-12T04:20:01Z to 2025-10-12T05:00:01Z

**Files Used to Generate Report:**
- agg_log_20251012T042001Z.json
- agg_log_20251012T044001Z.json
- agg_log_20251012T050001Z.json

## Executive Summary

This report summarizes 23,822 attacks detected by the honeypot network. The majority of attacks were captured by the Dionaea, Honeytrap, and Cowrie honeypots. The most targeted service was SMB on port 445. A significant number of attacks originated from the IP address 122.121.74.82. Attackers were observed attempting to exploit vulnerabilities related to remote code execution and denial of service. Additionally, there were numerous attempts to install malicious software, including variants of the Mozi botnet.

## Detailed Analysis

### Attacks by Honeypot

- Dionaea: 7732
- Honeytrap: 6478
- Cowrie: 5147
- Suricata: 2132
- Ciscoasa: 1798
- Sentrypeer: 200
- Mailoney: 155
- Tanner: 77
- ConPot: 44
- Redishoneypot: 24
- H0neytr4p: 21
- Adbhoney: 5
- ElasticPot: 3
- Heralding: 3
- Honeyaml: 3

### Top Attacking IPs

- 122.121.74.82: 6392
- 45.128.199.212: 2377
- 196.251.88.103: 927
- 43.229.78.35: 840
- 188.166.115.135: 605
- 147.45.112.157: 470
- 87.201.127.149: 347
- 37.186.84.29: 357
- 36.80.190.210: 385
- 84.38.183.16: 227
- 5.154.94.12: 253

### Top Targeted Ports/Protocols

- 445: 6829
- 5038: 2565
- 22: 826
- TCP/21: 234
- 5060: 200
- 25: 155
- 5903: 190
- 8333: 95
- 21: 115

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 20
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 12
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 2
- CVE-1999-0183: 1

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 22
- `lockr -ia .ssh`: 22
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo ...`: 22
- `cat /proc/cpuinfo | grep name | wc -l`: 17
- `Enter new UNIX password: `: 16
- `Enter new UNIX password:`: 16
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 17
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 17

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 537
- 2402000: 537
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 297
- 2023753: 297
- ET SCAN NMAP -sS window 1024: 161
- 2009582: 161
- ET HUNTING RDP Authentication Bypass Attempt: 118
- 2034857: 118
- ET FTP FTP CWD command attempt without login: 117
- 2010731: 117
- ET FTP FTP PWD command attempt without login: 116
- 2010735: 116

### Users / Login Attempts

- cron/: 63
- 345gs5662d34/345gs5662d34: 21
- root/1qaz@WSX: 6
- test/5555555: 6
- ubnt/66666: 4
- root/Ind0n3t2020: 4
- config/111111: 4

### Files Uploaded/Downloaded

- Mozi.m: 3
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

### HTTP User-Agents

- No HTTP User-Agents were logged in this timeframe.

### SSH Clients and Servers

- No SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations

- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- The vast majority of attacks are automated and opportunistic, focusing on common vulnerabilities and weak credentials.
- The IP address 122.121.74.82 was responsible for a large number of attacks, primarily targeting the SMB service on port 445.
- The attempted commands suggest that attackers are trying to establish persistent access by modifying SSH keys and disabling security features.
- The presence of Mozi malware and other botnet-related files indicates that attackers are attempting to recruit the honeypot into their botnets for use in further attacks.
