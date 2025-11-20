
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T13:01:28Z
**Timeframe:** 2025-10-06T12:20:01Z to 2025-10-06T13:00:01Z
**Log Files:**
- agg_log_20251006T122001Z.json
- agg_log_20251006T124001Z.json
- agg_log_20251006T130001Z.json

## Executive Summary

This report summarizes 18,585 malicious events recorded across three honeypot log files. The majority of attacks targeted the Sentrypeer honeypot, with a significant focus on port 5060. The most active IP address was 108.174.63.94, responsible for over half of all recorded attacks. Attackers primarily attempted to exploit the Log4j vulnerability (CVE-2021-44228) and gain SSH access by adding their public keys to the authorized_keys file.

## Detailed Analysis

### Attacks by Honeypot
- Sentrypeer: 10000
- Cowrie: 2602
- Honeytrap: 1650
- Ciscoasa: 1215
- Suricata: 1147
- Mailoney: 891
- Dionaea: 889
- ConPot: 47
- Adbhoney: 36
- Tanner: 33
- H0neytr4p: 22
- Honeyaml: 20
- ElasticPot: 18
- Redishoneypot: 15

### Top Attacking IPs
- 108.174.63.94: 9665
- 213.149.166.133: 836
- 176.65.141.117: 820
- 172.86.95.98: 370
- 185.186.26.225: 262
- 150.5.169.138: 208
- 103.157.25.60: 208
- 40.115.18.231: 129
- 145.249.109.167: 129
- 157.180.74.71: 129
- 202.184.140.252: 124

### Top Targeted Ports/Protocols
- 5060: 10000
- 25: 891
- 445: 845
- 22: 310
- 8333: 99
- 5902: 101
- 5903: 95
- UDP/5060: 54

### Most Common CVEs
- CVE-2021-44228 CVE-2021-44228: 26
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2024-3721 CVE-2024-3721: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 18
- cat /proc/cpuinfo | grep name | wc -l: 18
- Enter new UNIX password: : 18
- Enter new UNIX password::: 18
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 18
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 18
- ls -lh $(which ls): 17
- which ls: 17
- crontab -l: 17
- w: 17
- uname -m: 17
- cat /proc/cpuinfo | grep model | grep name | wc -l: 17
- top: 17

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 303
- 2402000: 303
- ET SCAN NMAP -sS window 1024: 130
- 2009582: 130
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 82
- 2023753: 82
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET VOIP REGISTER Message Flood UDP: 49
- 2009699: 49
- ET HUNTING RDP Authentication Bypass Attempt: 40
- 2034857: 40

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 15
- es/es.2024: 3
- creosote/creosote123: 3
- creosote/3245gs5662d34: 3
- ftpuser/ftpuser1024: 3
- teamspeak/teamspeak123.1234: 3
- ftpuser/ftpuser.2: 3
- ubuntu/ubuntu.123: 2
- vpn/vpn_123654: 2
- devops/devops_12: 2
- test1/tester321: 2
- testuser/target: 2

### Files Uploaded/Downloaded
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3
- ): 1

### HTTP User-Agents
- No user agents recorded in the logs.

### SSH Clients
- No SSH clients recorded in the logs.

### SSH Servers
- No SSH servers recorded in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations recorded in the logs.

## Key Observations and Anomalies

- The overwhelming majority of attacks were directed at port 5060, indicating a focus on VoIP-related services.
- The IP address 108.174.63.94 was responsible for a disproportionate number of attacks, suggesting a targeted campaign from a single source.
- A common attack pattern involved attempts to modify SSH configurations to allow for public key authentication, indicating a focus on establishing persistent access.
- Several attackers attempted to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`), a common technique for installing malware or backdoors.
- The presence of commands to gather system information (e.g., `lscpu`, `free -m`) suggests that attackers are performing reconnaissance to understand the compromised environment.
- The CVEs detected indicate that attackers are targeting known vulnerabilities, particularly the Log4j vulnerability (CVE-2021-44228).
