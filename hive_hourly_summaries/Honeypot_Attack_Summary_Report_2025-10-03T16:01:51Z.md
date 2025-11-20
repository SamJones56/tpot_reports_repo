
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T16:01:28Z
**Timeframe of Report:** 2025-10-03T15:20:01Z to 2025-10-03T16:00:01Z
**Files Used to Generate Report:**
- agg_log_20251003T152001Z.json
- agg_log_20251003T154002Z.json
- agg_log_20251003T160001Z.json

## Executive Summary
This report summarizes 11,619 malicious events recorded by the T-Pot honeypot network. The primary attack vectors observed were SSH brute-force attempts and scans for common vulnerabilities. The Cowrie honeypot recorded the highest number of interactions, indicating a strong focus on SSH-based attacks. A significant portion of the attacks originated from a small number of IP addresses, suggesting targeted campaigns.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5437
- **Ciscoasa:** 2066
- **Dionaea:** 1193
- **Mailoney:** 1326
- **Suricata:** 985
- **Sentrypeer:** 306
- **Honeytrap:** 111
- **Adbhoney:** 45
- **H0neytr4p:** 51
- **ConPot:** 27
- **Tanner:** 31
- **Redishoneypot:** 12
- **Honeyaml:** 19
- **Ipphoney:** 5
- **ElasticPot:** 2
- **Dicompot:** 3

### Top Attacking IPs
- **38.34.18.221:** 1156
- **86.54.42.238:** 821
- **176.65.141.117:** 498
- **43.157.67.116:** 391
- **152.32.215.227:** 352
- **38.248.12.102:** 336
- **103.119.92.117:** 332
- **103.174.115.196:** 331
- **152.32.172.117:** 292
- **156.245.239.180:** 209
- **94.183.191.41:** 197
- **203.69.224.106:** 228
- **177.130.248.114:** 222
- **185.156.73.166:** 216
- **92.63.197.59:** 201

### Top Targeted Ports/Protocols
- **445:** 1158
- **25:** 1324
- **22:** 665
- **5060:** 306
- **23:** 44
- **443:** 47
- **80:** 37
- **UDP/161:** 37
- **TCP/80:** 55
- **10001:** 22
- **6379:** 12
- **5555:** 9
- **3306:** 8
- **TCP/5432:** 14

### Most Common CVEs
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2021-3449
- CVE-2019-11500
- CVE-2019-16920
- CVE-2024-12856, CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-31983
- CVE-2023-47565
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051, CVE-2024-33112, CVE-2022-37056, CVE-2019-10891
- CVE-2024-3721
- CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
- CVE-2021-42013
- CVE-2006-2369

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `whoami`
- `Enter new UNIX password:`

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 247
- **ET SCAN NMAP -sS window 1024:** 183
- **ET INFO Reserved Internal IP Traffic:** 58
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 32:** 30
- **GPL SNMP request udp:** 12
- **ET CINS Active Threat Intelligence Poor Reputation IP group 67:** 14
- **ET CINS Active Threat Intelligence Poor Reputation IP group 68:** 10
- **GPL SNMP public access udp:** 10
- **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 13

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 38
- **test/zhbjETuyMffoL8F:** 9
- **root/nPSpP4PBW0:** 9
- **foundry/foundry:** 9
- **root/3245gs5662d34:** 9
- **superadmin/admin123:** 6
- **superadmin/3245gs5662d34:** 6
- **root/2glehe5t24th1issZs:** 7

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm5.urbotnetisass;
- arm6.urbotnetisass;
- arm7.urbotnetisass;
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;
- rondo.dgx.sh||busybox
- rondo.dgx.sh||curl
- rondo.dgx.sh)|sh&

### HTTP User-Agents
- No HTTP user agents were recorded in the logs.

### SSH Clients and Servers
- No SSH clients or servers were recorded in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in the logs.

## Key Observations and Anomalies
- The vast majority of commands are reconnaissance-focused, gathering system information.
- A recurring pattern of deleting and replacing SSH authorized keys was observed, indicating attempts to maintain persistent access.
- Several attackers attempted to download and execute shell scripts, likely to install malware or cryptominers. The filenames `w.sh`, `c.sh`, and various `urbotnetisass` variants were common.
- The CVEs detected span a wide range of years, with attackers still attempting to exploit older, well-known vulnerabilities.

This concludes the Honeypot Attack Summary Report.
