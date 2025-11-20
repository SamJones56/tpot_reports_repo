
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T09:01:43Z
**Timeframe:** 2025-10-03T08:20:01Z to 2025-10-03T09:00:01Z

**Files Used to Generate Report:**
- agg_log_20251003T082001Z.json
- agg_log_20251003T084001Z.json
- agg_log_20251003T090001Z.json

## Executive Summary
This report summarizes 24,639 events captured by the honeypot network. A significant number of attacks were logged, with the `Honeytrap`, `Cowrie`, and `Sentrypeer` honeypots recording the most activity. The primary attack vectors observed were SSH brute-force attempts, SIP scanning, and exploitation of various known vulnerabilities. The most prolific attacking IP addresses were `45.234.176.18` and `23.94.26.58`.

## Detailed Analysis

### Attacks by honeypot:
- Honeytrap: 9554
- Cowrie: 6015
- Sentrypeer: 3521
- Suricata: 3380
- Ciscoasa: 1858
- Redishoneypot: 90
- Adbhoney: 47
- Dionaea: 59
- H0neytr4p: 21
- Tanner: 35
- Mailoney: 28
- ConPot: 18
- Dicompot: 4
- Miniprint: 3
- Honeyaml: 4
- Ipphoney: 1
- ElasticPot: 1

### Top attacking IPs:
- 45.234.176.18: 9135
- 23.94.26.58: 4708
- 196.251.88.103: 717
- 23.175.48.211: 912
- 117.72.213.21: 325
- 196.251.80.30: 280
- 185.156.73.166: 259
- 103.186.1.120: 236
- 1.9.107.43: 213
- 92.63.197.55: 248
- 92.63.197.59: 227
- 14.103.228.246: 185
- 107.175.189.123: 149
- 110.41.155.122: 171
- 117.50.213.218: 141
- 186.96.151.198: 134
- 20.127.224.153: 144
- 161.132.50.17: 197
- 155.248.164.42: 133
- 206.189.131.246: 124

### Top targeted ports/protocols:
- 5060: 3521
- UDP/5060: 2367
- 22: 881
- 6379: 90
- 80: 34
- 25: 28
- 1433: 17
- TCP/1433: 18
- TCP/22: 18
- 27017: 13
- 443: 17
- TCP/443: 15
- 10001: 13
- 5555: 5
- TCP/5555: 4
- 17000: 8
- TCP/8080: 6
- 23: 6
- 8084: 6
- 3001: 6

### Most common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2023-26801 CVE-2023-26801
- CVE-2016-5696
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0183

### Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
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
- Enter new UNIX password:
- echo "root:0PGZRcvidZQ8"|chpasswd|bash

### Signatures triggered:
- ET SCAN Sipsak SIP scan
- 2008598
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- 2400031
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- 2403346
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- 2403350
- ET INFO curl User-Agent Outbound
- 2013028
- ET HUNTING curl User-Agent to Dotted Quad
- 2034567
- ET CINS Active Threat Intelligence Poor Reputation IP group 68
- 2403367

### Users / login attempts:
- 345gs5662d34/345gs5662d34
- root/2glehe5t24th1issZs
- test/zhbjETuyMffoL8F
- root/nPSpP4PBW0
- foundry/foundry
- superadmin/admin123
- root/LeitboGi0ro
- root/3245gs5662d34
- webuser/12345
- root/esther1
- jean/jean123
- james/james
- saad/saad
- ubuntu/P@ssw0rd2025
- anonymous/
- wangyao/wangyao123
- test/test123
- sahil/sahil123
- root/qwert123.
- root/12345-Qwert

### Files uploaded/downloaded:
- wget.sh;
- w.sh;
- c.sh;
- soap-envelope
- addressing
- discovery
- env:Envelope>

### HTTP User-Agents:
- No user agents were recorded in this timeframe.

### SSH clients and servers:
- No specific SSH clients or servers were recorded in this timeframe.

### Top attacker AS organizations:
- No AS organizations were recorded in this timeframe.

## Key Observations and Anomalies
- The vast majority of `Honeytrap` events originated from a single IP address: `45.234.176.18`.
- Similarly, a large number of `Sentrypeer` events originated from `23.94.26.58`. This suggests targeted scanning activity from these sources.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently observed, indicating a common tactic of attempting to gain persistent access by adding an SSH key to the `authorized_keys` file.
- The presence of commands like `rm -rf /data/local/tmp; ... wget ...` indicates attempts to download and execute malicious scripts on compromised systems.
- A mix of old and new CVEs were targeted, highlighting the importance of patching systems against both well-known and recent vulnerabilities.
