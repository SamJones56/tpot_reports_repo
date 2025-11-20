# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T19:01:37Z
**Timeframe:** 2025-10-06T18:20:01Z to 2025-10-06T19:01:01Z
**Files Used:**
- agg_log_20251006T182001Z.json
- agg_log_20251006T184001Z.json
- agg_log_20251006T190001Z.json

---

### Executive Summary

This report summarizes 17,186 malicious activities recorded across the honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. A significant portion of the attacks originated from the IP address 103.220.207.174. The most frequently targeted port was port 22 (SSH). Several CVEs were detected, with CVE-2021-44228 (Log4Shell) being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

---

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6833
- Honeytrap: 6599
- Suricata: 1685
- Ciscoasa: 1189
- Sentrypeer: 374
- Dionaea: 228
- Mailoney: 103
- Adbhoney: 35
- H0neytr4p: 31
- Tanner: 29
- ElasticPot: 22
- Honeyaml: 26
- Redishoneypot: 18
- Dicompot: 10
- Heralding: 3
- ConPot: 1

**Top Attacking IPs:**
- 103.220.207.174: 3654
- 80.94.95.238: 696
- 162.243.168.76: 490
- 67.207.83.103: 490
- 218.161.90.126: 466
- 180.252.94.109: 421
- 103.148.100.146: 422
- 172.86.95.98: 364
- 79.175.151.48: 491
- 155.4.244.179: 283
- 103.153.110.189: 219
- 122.51.140.49: 192
- 175.196.245.105: 228
- 194.0.234.215: 184
- 94.182.174.254: 164
- 182.18.161.165: 154
- 206.189.131.246: 144
- 115.240.221.28: 129
- 185.255.91.51: 120
- 181.104.58.194: 105

**Top Targeted Ports/Protocols:**
- 22: 817
- 5060: 374
- 445: 175
- 25: 103
- 8333: 99
- 5903: 95
- 5908: 49
- 5907: 49
- 5909: 50
- 23: 41
- 80: 30
- TCP/80: 24
- TCP/8080: 19
- 443: 24
- 9200: 19
- 6379: 12

**Most Common CVEs:**
- CVE-2021-44228: 16
- CVE-2019-11500: 3
- CVE-2021-3449: 3
- CVE-2002-0013: 3
- CVE-2003-0825: 2
- CVE-2006-2369: 1
- CVE-1999-0517: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 46
- lockr -ia .ssh: 46
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 46
- cat /proc/cpuinfo | grep name | wc -l: 46
- Enter new UNIX password: : 46
- Enter new UNIX password::: 46
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 46
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 46
- ls -lh $(which ls): 46
- which ls: 46
- crontab -l: 46
- w: 46
- uname -m: 46
- cat /proc/cpuinfo | grep model | grep name | wc -l: 46
- top: 46
- uname: 46
- uname -a: 46
- whoami: 46
- lscpu | grep Model: 46
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 46

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 424
- 2402000: 424
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 346
- 2023753: 346
- ET SCAN NMAP -sS window 1024: 163
- 2009582: 163
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 20
- 2403343: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 20
- 2403302: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 19
- 2403348: 19

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 46
- abc/abc!: 12
- abc/3245gs5662d34: 12
- vpn/123vpn: 12
- vpn/P@ssw0rd1: 11
- root/1234567: 6
- jenkins/jenkins@123: 6
- administrator/administrator@1: 6
- deployer/3245gs5662d34: 3
- adminuser/adminuser.123: 6
- ec2-user/Password123!: 5
- oracle/P@ssw0rd1: 4
- oracle/3245gs5662d34: 4
- deploy/deploy!123: 4
- sshuser/1: 4
- deployer/P@ssw0rd@123: 4
- monitor/password@123: 6
- ubuntu/3245gs5662d34: 6

**Files Uploaded/Downloaded:**
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients:**
- No SSH clients were recorded in this period.

**SSH Servers:**
- No SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in this period.

---

### Key Observations and Anomalies

- A single IP address, 103.220.207.174, was responsible for a disproportionately large number of events, indicating a targeted or persistent attack from a single source.
- The vast majority of commands are identical and appear to be part of a standardized script used by attackers to profile the system and attempt to install a malicious SSH key.
- The files downloaded (`wget.sh`, `w.sh`, `c.sh`) suggest attempts to install malware or other malicious scripts onto the honeypot.
- The high number of scans for MS Terminal Server on non-standard ports, along with SSH, suggests that attackers are broadly scanning for common remote access services.

---
