Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T19:01:24Z
**Timeframe:** 2025-10-25T18:20:01Z to 2025-10-25T19:00:01Z
**Files Analyzed:**
- agg_log_20251025T182001Z.json
- agg_log_20251025T184001Z.json
- agg_log_20251025T190001Z.json

### Executive Summary
This report summarizes 22,676 events collected from the honeypot network over the past hour. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. A significant portion of the traffic originated from IP address `80.94.95.238`. The most frequently targeted ports were 5060 (SIP) and 22 (SSH). Attackers were observed attempting to exploit several vulnerabilities, including CVE-2002-0013 and CVE-2019-11500. A variety of shell commands were executed, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 9078
- Honeytrap: 5106
- Suricata: 3063
- Sentrypeer: 3377
- Ciscoasa: 1658
- Mailoney: 118
- Adbhoney: 43
- Dionaea: 72
- Redishoneypot: 62
- Tanner: 28
- H0neytr4p: 19
- Heralding: 25
- ConPot: 11
- ElasticPot: 4
- Honeyaml: 5
- Dicompot: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 80.94.95.238: 3190
- 107.174.226.42: 3166
- 72.167.220.12: 943
- 206.189.83.92: 446
- 103.146.202.84: 236
- 190.153.249.99: 446
- 167.71.65.227: 350
- 103.28.57.98: 330
- 188.166.169.185: 273
- 23.227.147.163: 267
- 201.184.50.251: 262
- 210.79.190.46: 243
- 172.245.177.148: 194
- 108.85.73.157: 262
- 181.212.34.237: 184
- 173.249.45.217: 204
- 36.91.166.34: 179
- 101.36.108.134: 247

**Top Targeted Ports/Protocols:**
- 5060: 3377
- 22: 1383
- 8333: 159
- 5901: 130
- 5903: 126
- 25: 118
- 6379: 62
- 8086: 70
- UDP/5060: 18
- UDP/161: 19
- TCP/22: 46
- TCP/80: 50

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2009-2765
- CVE-1999-0183
- CVE-2005-4050

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `w`
- `top`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET VOIP REGISTER Message Flood UDP
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET Cins Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- GPL SNMP request udp

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/faltara!
- root/Testing@123
- zabbix/zaq1@wsx
- pi/raspberry
- root/fatto6530ft2fatto6530ft33

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- rondo.dtm.sh||curl
- wget.sh
- w.sh
- c.sh
- Mozi.m

**HTTP User-Agents:**
- No HTTP user agents were logged in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were logged in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged in this period.

### Key Observations and Anomalies
- A large number of commands executed are related to manipulating SSH authorized_keys, indicating a focus on establishing persistent access.
- The `urbotnetisass` malware was downloaded for multiple architectures (ARM, x86, MIPS), suggesting a widespread, multi-architecture campaign.
- A significant number of scans for MS Terminal Server traffic on non-standard ports were detected, which could be an attempt to find vulnerable RDP services.