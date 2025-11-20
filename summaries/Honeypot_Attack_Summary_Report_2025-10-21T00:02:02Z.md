# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T00:01:25Z
**Timeframe:** 2025-10-20T23:20:01Z to 2025-10-21T00:00:02Z
**Files Used:**
- agg_log_20251020T232001Z.json
- agg_log_20251020T234001Z.json
- agg_log_20251021T000002Z.json

## Executive Summary

This report summarizes 15,186 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap and Suricata. The most targeted service was SSH on port 22. A wide range of CVEs were observed, with CVE-2019-11500 and CVE-2021-3449 being the most frequent. Attackers attempted numerous commands, primarily focused on system enumeration.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 9491
- **Honeytrap:** 3217
- **Suricata:** 1308
- **Dionaea:** 542
- **Sentrypeer:** 326
- **Adbhoney:** 63
- **Mailoney:** 42
- **H0neytr4p:** 40
- **Miniprint:** 37
- **Tanner:** 37
- **ElasticPot:** 34
- **Redishoneypot:** 31
- **Ciscoasa:** 10
- **Honeyaml:** 4
- **Dicompot:** 2
- **ssh-rsa:** 2

### Top Attacking IPs
- 81.19.135.103
- 72.146.232.13
- 196.203.109.209
- 134.122.45.20
- 183.110.116.126
- 154.91.170.52
- 202.165.15.132
- 118.194.230.250
- 103.23.199.128
- 79.174.84.12

### Top Targeted Ports/Protocols
- 22
- 445
- 5060
- 5901
- 5903
- 8333
- 5905
- TCP/80
- 9100
- 443

### Most Common CVEs
- CVE-2019-11500
- CVE-2021-3449
- CVE-2006-2369
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2024-3721
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2024-12847
- CVE-2023-52163
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2018-7600

### Commands Attempted by Attackers
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

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- user01/Password01
- deploy/123123
- deploy/3245gs5662d34
- kk/123
- user01/3245gs5662d34
- mehmet/mehmet123
- deploy/1234
- root/1234567u
- sebastien/123

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- json
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
- soap-envelope
- addressing
- k.php?a=x86_64,E02ZM0A91A10935DH

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were logged in this timeframe.

## Key Observations and Anomalies
- A significant amount of reconnaissance activity was observed, with attackers attempting to gather information about the system's CPU, memory, and running processes.
- The command `cd ~; chattr -ia .ssh; lockr -ia .ssh` was frequently used, suggesting an attempt to modify SSH authorized keys.
- Several files related to the "urbotnetisass" malware were downloaded, indicating a targeted campaign.
- The attacker with IP `81.19.135.103` was particularly aggressive, generating over 1,100 events in a short period.
- A wide variety of CVEs were targeted, suggesting that attackers are using a broad set of exploits to compromise systems.
- The Suricata logs show a high number of "ET DROP Dshield Block Listed Source group 1" and "ET SCAN MS Terminal Server Traffic on Non-standard Port" signatures, indicating that many of the attacking IPs are known bad actors.
