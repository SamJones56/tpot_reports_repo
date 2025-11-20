
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T01:01:25Z
**Timeframe:** 2025-10-21T00:20:01Z to 2025-10-21T01:00:01Z
**Files Used:**
- agg_log_20251021T002001Z.json
- agg_log_20251021T004002Z.json
- agg_log_20251021T010001Z.json

## Executive Summary

This report summarizes 9,823 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacker IP was 134.199.207.7, and the most targeted port was 22 (SSH). A variety of CVEs were observed, with the most common being related to older vulnerabilities. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing further access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4912
- Honeytrap: 2820
- Suricata: 1392
- Sentrypeer: 397
- Dionaea: 120
- ConPot: 29
- Tanner: 43
- Adbhoney: 27
- Mailoney: 26
- H0neytr4p: 18
- Ciscoasa: 14
- Redishoneypot: 12
- Honeyaml: 6
- Wordpot: 3
- ElasticPot: 2
- ssh-rsa: 2

### Top Attacking IPs
- 134.199.207.7: 1001
- 72.146.232.13: 882
- 222.108.173.170: 341
- 116.212.131.138: 293
- 221.179.57.254: 238
- 185.243.5.158: 248
- 107.170.36.5: 236
- 14.29.175.242: 235
- 181.188.172.6: 174
- 190.128.241.2: 174
- 203.210.135.87: 178
- 81.19.135.103: 133
- 128.1.44.115: 129
- 49.7.220.97: 154
- 14.153.12.217: 142
- 74.208.133.247: 115
- 68.183.149.135: 112
- 92.191.96.115: 94
- 196.251.80.165: 70
- 36.50.176.16: 59

### Top Targeted Ports/Protocols
- 22: 954
- 5060: 397
- TCP/445: 291
- 5903: 202
- 5901: 103
- 8333: 90
- 5905: 80
- 5904: 78
- TCP/80: 50
- 80: 47
- 5909: 44
- 5908: 41
- 5907: 41
- 5902: 42
- 27017: 102
- 49153: 26
- 25: 18
- 1025: 23
- 19080: 21
- 8728: 22

### Most Common CVEs
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2024-3721
- CVE-2005-4050
- CVE-2002-1149

### Commands Attempted by Attackers
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
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
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET HUNTING curl User-Agent to Dotted Quad
- ET INFO curl User-Agent Outbound

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- spectrum/spectrum
- root/Aesx5099
- test01/test01
- root/Aew3Aoph
- user01/Password01
- root/AffaireMedia
- root/AfKfFk2650
- root/afl2013
- admin/
- root/Admin!12345
- testing/testing
- admin01/admin01
- superuser/123
- reboot/reboot
- supervisor/passwd
- user/svn1234
- user/K7inqk7WSZ
- user/Justforyou8866
- user/Jsyd@yhsj!@#123

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- ?format=json
- )
- json

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- A significant number of commands are related to establishing a persistent SSH connection by adding a public key to `authorized_keys`.
- The `DoublePulsar` signature indicates attempts to exploit the Equation Group vulnerability.
- Attackers frequently use commands to gather system information, such as `lscpu`, `uname`, and `free`.
- There is a mix of brute-force login attempts with common and complex passwords.
- The file downloads (`wget.sh`, `w.sh`, `c.sh`) suggest attempts to download and execute malicious scripts.
