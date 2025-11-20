
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T11:01:28Z
**Timeframe:** 2025-10-07T10:20:01Z to 2025-10-07T11:00:02Z

**Files Used:**
- agg_log_20251007T102001Z.json
- agg_log_20251007T104001Z.json
- agg_log_20251007T110002Z.json

## Executive Summary

This report summarizes the honeypot activity over the last three collection periods, totaling 15,247 events. The majority of attacks targeted the Cowrie honeypot, with significant activity also observed on Honeytrap and Mailoney. The most frequent attacks originated from IP addresses 86.54.42.238 and 170.64.145.101. The most targeted ports were 25 (SMTP) and 22 (SSH). A number of CVEs were detected, with the most common being related to older vulnerabilities. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 8745
- Honeytrap: 2887
- Mailoney: 1692
- Suricata: 1347
- Sentrypeer: 395
- H0neytr4p: 45
- Tanner: 27
- Adbhoney: 27
- Redishoneypot: 21
- ConPot: 10
- ElasticPot: 7
- Dionaea: 11
- Ciscoasa: 7
- Heralding: 3
- Miniprint: 12
- Dicompot: 3
- Honeyaml: 8

### Top Attacking IPs

- 86.54.42.238: 1627
- 170.64.145.101: 1602
- 156.238.229.20: 297
- 172.86.95.98: 375
- 178.18.241.171: 284
- 43.160.246.180: 307
- 34.123.134.194: 174
- 103.210.21.178: 182
- 103.157.25.60: 164
- 14.103.158.69: 160
- 103.220.207.174: 190
- 205.185.125.150: 179
- 172.104.176.233: 184
- 103.57.64.214: 188
- ... and others

### Top Targeted Ports/Protocols

- 25: 1692
- 22: 1110
- 5060: 395
- 8333: 130
- 5038: 249
- 5903: 95
- 23: 65
- TCP/22: 65
- 443: 41
- TCP/80: 27
- ... and others

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 6
- CVE-1999-0265: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2003-0825: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-1999-0183: 1
- CVE-2005-4050: 1
- CVE-2023-26801 CVE-2023-26801: 1

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 54
- `lockr -ia .ssh`: 54
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 53
- `cat /proc/cpuinfo | grep name | wc -l`: 53
- `Enter new UNIX password: `: 53
- `Enter new UNIX password:`: 53
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 53
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 53
- `ls -lh $(which ls)`: 53
- `which ls`: 53
- `crontab -l`: 53
- `w`: 53
- `uname -m`: 53
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 53
- `top`: 53
- `uname`: 53
- `uname -a`: 53
- `whoami`: 53
- `lscpu | grep Model`: 53
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 53

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 440
- 2402000: 440
- ET SCAN NMAP -sS window 1024: 153
- 2009582: 153
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET SCAN Potential SSH Scan: 53
- 2001219: 53
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 28
- 2023753: 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 19
- 2403346: 19
- ... and others

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 53
- ubuntu/3245gs5662d34: 13
- server/3245gs5662d34: 8
- vpn/vpn!123: 5
- ansible/P@ssw0rd: 4
- guest/guest!: 4
- guest/3245gs5662d34: 4
- git/3245gs5662d34: 4
- user2/123123: 4
- remoto/Passw0rd@123: 4
- mc/Password@123: 4
- mysql/123: 4
- mysql/3245gs5662d34: 4
- elasticsearch/P@ssw0rd@123: 4
- ... and others

### Files Uploaded/Downloaded

- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- w.sh: 1
- c.sh: 1
- wget.sh: 1

### HTTP User-Agents

- No user agents were logged.

### SSH Clients and Servers

- No specific SSH clients or servers were logged.

### Top Attacker AS Organizations

- No AS organizations were logged.

## Key Observations and Anomalies

- The high volume of attacks on Cowrie (SSH honeypot) and Mailoney (SMTP honeypot) suggests that attackers are actively targeting these services.
- The repeated use of the same SSH key in attempted commands indicates a coordinated attack campaign.
- The commands attempted by attackers are consistent with initial access and reconnaissance activities, with a focus on gathering system information.
- The presence of commands related to downloading and executing shell scripts from external sources is a strong indicator of malware infection attempts.
- The CVEs detected are mostly older, suggesting that attackers are still attempting to exploit known vulnerabilities that may not be patched on all systems.
