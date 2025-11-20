Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T11:01:22Z
**Timeframe:** 2025-10-02T10:20:01Z to 2025-10-02T11:00:01Z
**Files Analyzed:**
- agg_log_20251002T102001Z.json
- agg_log_20251002T104001Z.json
- agg_log_20251002T110001Z.json

### Executive Summary

This report summarizes 17,976 detected attacks between 10:20 AM and 11:00 AM UTC. The majority of attacks targeted the Dionaea honeypot. The most prominent attack vector was scanning and exploitation of Windows SMB services, as indicated by the high volume of traffic on port 445 and the prevalence of the "DoublePulsar Backdoor" signature. A significant number of brute-force attempts were also observed against SSH services.

### Detailed Analysis

**Attacks by Honeypot:**
* Dionaea: 6657
* Cowrie: 4899
* Suricata: 2457
* Mailoney: 1684
* Ciscoasa: 1095
* Honeytrap: 1000
* Tanner: 71
* Sentrypeer: 28
* Adbhoney: 21
* H0neytr4p: 21
* Redishoneypot: 16
* Honeyaml: 9
* ConPot: 7
* ElasticPot: 6
* Heralding: 3
* Ipphoney: 2

**Top Attacking IPs:**
* 27.147.191.233
* 41.106.128.125
* 49.206.197.28
* 86.54.42.238
* 176.65.141.117
* 41.209.126.101
* 57.128.190.44
* 38.57.234.191
* 34.69.0.72
* 172.245.92.249

**Top Targeted Ports/Protocols:**
* 445
* 25
* 22
* TCP/445
* 8333
* 80
* TCP/22
* 23
* 5060
* TCP/80

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
* CVE-2021-3449 CVE-2021-3449
* CVE-1999-0183
* CVE-2019-11500 CVE-2019-11500
* CVE-2024-4577 CVE-2002-0953
* CVE-2024-4577 CVE-2024-4577
* CVE-2021-35394 CVE-2021-35394
* CVE-2001-0414
* CVE-2023-26801 CVE-2023-26801
* CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
* CVE-2021-42013 CVE-2021-42013

**Commands Attempted by Attackers:**
* uname -a
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* crontab -l
* w
* uname -m
* top

**Signatures Triggered:**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
* ET DROP Dshield Block Listed Source group 1
* ET SCAN NMAP -sS window 1024
* ET INFO Reserved Internal IP Traffic
* ET CINS Active Threat Intelligence Poor Reputation IP group 50
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32
* ET SCAN Potential SSH Scan
* GPL SNMP request udp
* ET SCAN Suspicious inbound to PostgreSQL port 5432
* GPL SNMP public access udp

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* root/nPSpP4PBW0
* root/3245gs5662d34
* foundry/foundry
* root/LeitboGi0ro
* superadmin/admin123
* test/zhbjETuyMffoL8F
* root/2glehe5t24th1issZs
* seekcy/Joysuch@Locate2024
* seekcy/Joysuch@Locate2023

**Files Uploaded/Downloaded:**
* sh
* wget.sh;
* arm.urbotnetisass;
* arm5.urbotnetisass;
* arm6.urbotnetisass;
* arm7.urbotnetisass;
* x86_32.urbotnetisass;
* mips.urbotnetisass;
* mipsel.urbotnetisass;
* w.sh;
* c.sh;

**HTTP User-Agents:**
* No user agents were logged.

**SSH Clients:**
* No SSH clients were logged.

**SSH Servers:**
* No SSH servers were logged.

**Top Attacker AS Organizations:**
* No AS organizations were logged.

### Key Observations and Anomalies
- A significant amount of scanning and exploitation attempts for SMB (port 445) were observed, primarily from IPs in Vietnam and Algeria.
- A large number of SMTP (port 25) probes were detected from two specific IPs.
- Several attackers attempted to download and execute malicious shell scripts and binaries, indicating attempts to install malware or establish persistence. The filenames suggest a botnet-related activity.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, indicating attempts to install a persistent SSH key for backdoor access.
- Several CVEs related to older vulnerabilities were targeted, suggesting that attackers are still scanning for unpatched systems.
