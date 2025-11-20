
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T19:01:32Z
**Timeframe:** 2025-10-02T18:20:01Z to 2025-10-02T19:00:02Z

**Files Used:**
- agg_log_20251002T182001Z.json
- agg_log_20251002T184001Z.json
- agg_log_20251002T190002Z.json

---

## Executive Summary

This report summarizes 12,770 events collected from the honeypot network. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH-based threats. A significant number of attacks also targeted Cisco ASA, Mailoney, and Suricata monitored services. Attackers were observed attempting to gain access using common default credentials and exploiting older vulnerabilities. A recurring pattern of activity involved attempts to download and execute malicious shell scripts, likely to enlist the compromised system into a botnet.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6461
- Ciscoasa: 2674
- Mailoney: 1689
- Suricata: 1172
- Sentrypeer: 280
- Dionaea: 164
- Honeytrap: 119
- Adbhoney: 49
- H0neytr4p: 38
- Redishoneypot: 34
- Tanner: 44
- ConPot: 23
- Honeyaml: 15
- ElasticPot: 2
- Wordpot: 1
- Ipphoney: 1
- Dicompot: 4

### Top Attacking IPs
- 138.68.167.183: 985
- 86.54.42.238: 821
- 176.65.141.117: 820
- 38.47.94.38: 327
- 208.115.196.124: 287
- 128.199.16.106: 366
- 92.63.197.55: 356
- 185.156.73.166: 356
- 107.150.112.242: 292
- 92.63.197.59: 316

### Top Targeted Ports/Protocols
- 25: 1689
- 22: 906
- 5060: 280
- 445: 112
- 80: 52
- 443: 38
- 23: 48
- 6379: 31
- 81: 28
- TCP/80: 57

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449
- CVE-2019-11500
- CVE-2023-26801
- CVE-1999-0183

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- GPL SNMP request udp
- GPL SNMP public access udp

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- superadmin/admin123
- root/LeitboGi0ro
- root/nPSpP4PBW0
- root/2glehe5t24th1issZs
- foundry/foundry
- test/zhbjETuyMffoL8F
- root/3245gs5662d34

### Files Uploaded/Downloaded
- wget.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- w.sh;
- c.sh;
- arm5.urbotnetisass;
- arm5.urbotnetisass
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

---

## Key Observations and Anomalies

- **Repetitive Botnet Activity:** A significant portion of the command and file download activity is automated and repetitive, with multiple IPs attempting the same sequence of commands to download and execute scripts. This is characteristic of botnet recruitment.
- **Focus on Older Vulnerabilities:** The CVEs targeted are relatively old, suggesting that attackers are scanning for unpatched and legacy systems.
- **High Volume of Credential Stuffing:** The large number of login attempts with common and default credentials indicates widespread credential stuffing campaigns.

---
