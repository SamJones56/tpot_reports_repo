
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T09:01:24Z
**Timeframe:** 2025-10-04T08:20:01Z to 2025-10-04T09:00:01Z
**Files Used:**
- agg_log_20251004T082001Z.json
- agg_log_20251004T084002Z.json
- agg_log_20251004T090001Z.json

## Executive Summary

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 11,592 attacks were recorded. The most targeted services were Suricata, Cowrie, and Mailoney. The top attacking IP address was 81.4.194.194, which was responsible for a significant number of attacks. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

## Detailed Analysis

### Attacks by Honeypot

- **Suricata:** 2932
- **Cowrie:** 3710
- **Mailoney:** 1674
- **Ciscoasa:** 1573
- **Honeytrap:** 803
- **Sentrypeer:** 349
- **Dionaea:** 236
- **Redishoneypot:** 85
- **Tanner:** 87
- **Adbhoney:** 42
- **H0neytr4p:** 49
- **ConPot:** 30
- **ElasticPot:** 8
- **Honeyaml:** 14

### Top Attacking IPs

- 81.4.194.194: 1523
- 86.54.42.238: 821
- 176.65.141.117: 820
- 187.103.193.144: 362
- 196.251.80.29: 356
- 196.251.80.27: 325
- 103.157.25.60: 272
- 106.51.1.63: 204
- 103.52.115.189: 209
- 115.190.89.75: 135
- 117.72.213.218: 124
- 46.105.87.113: 162
- 185.243.5.68: 104
- 95.38.101.192: 95
- 185.213.175.171: 98
- 154.221.29.240: 81
- 45.186.251.70: 115
- 5.172.19.42: 93
- 88.214.25.24: 76
- 159.13.36.0: 109

### Top Targeted Ports/Protocols

- TCP/445: 1519
- 25: 1674
- 22: 579
- 5060: 349
- 445: 131
- 80: 89
- 6379: 85
- 23: 60
- 3306: 60
- 443: 49
- 27017: 37
- TCP/80: 62
- TCP/22: 37
- 10001: 16
- TCP/443: 17
- TCP/3389: 13
- TCP/1521: 13
- UDP/161: 15
- 31337: 10
- UDP/5060: 10

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2006-2369: 1
- CVE-2024-3721 CVE-2024-3721: 1

### Commands Attempted by Attackers

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 16
- lockr -ia .ssh: 16
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 16
- cat /proc/cpuinfo | grep name | wc -l: 16
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 16
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 16
- ls -lh $(which ls): 16
- which ls: 16
- crontab -l: 16
- w: 16
- uname -m: 16
- cat /proc/cpuinfo | grep model | grep name | wc -l: 16
- top: 16
- uname: 16
- uname -a: 20
- whoami: 16
- lscpu | grep Model: 16
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 16
- Enter new UNIX password: : 12
- Enter new UNIX password:": 12

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1516
- 2024766: 1516
- ET DROP Dshield Block Listed Source group 1: 435
- 2402000: 435
- ET SCAN NMAP -sS window 1024: 175
- 2009582: 175
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 56
- 2023753: 56
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 34
- 2403347: 34
- ET SCAN Potential SSH Scan: 21
- 2001219: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 25
- 2403343: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 19
- 2403350: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 19
- 2403345: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 16
- 2403344: 16
- ET HUNTING RDP Authentication Bypass Attempt: 12
- 2034857: 12
- ET SCAN Sipsak SIP scan: 9
- 2008598: 9

### Users / Login Attempts

- a2billinguser/: 49
- 345gs5662d34/345gs5662d34: 13
- root/LeitboGi0ro: 5
- root/2glehe5t24th1issZs: 5
- superadmin/admin123: 5
- root/nPSpP4PBW0: 5
- test/zhbjETuyMffoL8F: 4
- test/3245gs5662d34: 4
- tiktok/tiktok: 2
- kent/kent123: 2
- sebastian/sebastian: 2
- backup/backup@123: 2
- root/Suraj@123: 2
- root/adminHW: 2
- root/123456@Abc: 2
- postgres/1234567890: 2
- postgres/1234: 2
- root/Hamza@123: 2
- postgres/123: 2
- root/admin123.: 2

### Files Uploaded/Downloaded

- sh: 98
- wget.sh;: 12
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2
- Mozi.a+jaws: 2
- w.sh;: 3
- c.sh;: 3
- ?format=json: 2

### HTTP User-Agents
- No user agents were recorded in this timeframe.

### SSH Clients
- No SSH clients were recorded in this timeframe.

### SSH Servers
- No SSH servers were recorded in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this timeframe.

## Key Observations and Anomalies

- A high volume of attacks originated from the IP address 81.4.194.194, primarily targeting TCP port 445. These attacks triggered the "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature, suggesting a coordinated campaign to exploit the vulnerability associated with this backdoor.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was frequently used, indicating attempts to install a persistent SSH key for backdoor access.
- Several attackers attempted to download and execute shell scripts and ELF binaries, such as `w.sh`, `c.sh`, and `*.urbotnetisass`, which are likely components of botnet malware.
- The most common CVEs observed were related to older vulnerabilities, suggesting that attackers are still targeting systems that may not be patched against these known exploits.

This concludes the Honeypot Attack Summary Report.
