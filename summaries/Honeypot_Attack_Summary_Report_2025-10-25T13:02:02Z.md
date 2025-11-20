
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T13:01:35Z
**Timeframe:** 2025-10-25T12:20:01Z to 2025-10-25T13:00:01Z
**Files Used:**
- agg_log_20251025T122001Z.json
- agg_log_20251025T124001Z.json
- agg_log_20251025T130001Z.json

## Executive Summary

This report summarizes 21,541 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command injection attempts. A significant number of events were also logged by the Heralding and Suricata honeypots. The most prominent attacking IP address was 185.243.96.105. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to exploit several vulnerabilities, including older CVEs.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 8,127
- Heralding: 4,349
- Suricata: 3,366
- Honeytrap: 3,080
- Ciscoasa: 1,844
- Dionaea: 221
- Sentrypeer: 193
- Tanner: 78
- Adbhoney: 76
- Mailoney: 118
- Redishoneypot: 29
- H0neytr4p: 32
- ConPot: 11
- Dicompot: 7
- Miniprint: 6
- Ipphoney: 2
- Honeyaml: 2

### Top Attacking IPs

- 185.243.96.105: 4,262
- 109.205.211.9: 2,340
- 134.209.202.50: 566
- 45.81.23.49: 287
- 185.158.23.150: 277
- 164.128.136.184: 266
- 113.193.234.210: 288
- 41.216.178.119: 243
- 222.107.156.227: 287
- 206.189.75.41: 194

### Top Targeted Ports/Protocols

- vnc/5900: 4,349
- 22: 1,151
- 5060: 193
- 3306: 118
- 8333: 127
- 80: 80
- 445: 51
- 25: 118
- 5903: 129
- 5901: 110

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2021-44228 CVE-2021-44228: 5
- CVE-2002-1149: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2005-4050: 3
- CVE-2025-22457 CVE-2025-22457: 1

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 43
- `lockr -ia .ssh`: 43
- `cat /proc/cpuinfo | grep name | wc -l`: 43
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 43
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 43
- `ls -lh $(which ls)`: 43
- `which ls`: 43
- `crontab -l`: 43
- `w`: 43
- `uname -m`: 43
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 42
- `Enter new UNIX password: `: 28

### Signatures Triggered

- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1,394
- 2023753: 1,394
- ET HUNTING RDP Authentication Bypass Attempt: 680
- 2034857: 680
- ET DROP Dshield Block Listed Source group 1: 282
- 2402000: 282
- ET SCAN NMAP -sS window 1024: 192
- 2009582: 192
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 40
- /Passw0rd: 24
- /passw0rd: 15
- /1q2w3e4r: 15
- root/3245gs5662d34: 14
- /qwertyui: 10

### Files Uploaded/Downloaded

- wget.sh;: 28
- c.sh;: 7
- w.sh;: 7
- arm.urbotnetisass;: 3
- arm5.urbotnetisass;: 3
- arm6.urbotnetisass;: 3
- arm7.urbotnetisass;: 3
- x86_32.urbotnetisass;: 3
- mips.urbotnetisass;: 3
- mipsel.urbotnetisass;: 3

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

## Key Observations and Anomalies

- **High Volume of VNC Scans:** The most frequently targeted port was 5900 (VNC), indicating widespread scanning for exposed remote desktop services.
- **Repetitive Shell Commands:** Attackers consistently used a series of commands to gather system information (`uname`, `lscpu`, `free`, etc.) and to establish persistent access by adding an SSH key to `authorized_keys`.
- **Malware Download Attempts:** Multiple attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) and ELF executables (`.urbotnetisass`) were observed. This suggests automated attacks aimed at deploying malware on compromised systems.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, with a focus on default or weak credentials.

This report highlights a consistent and automated barrage of attacks against the honeypot infrastructure. The tactics observed are typical of botnets seeking to expand their reach by scanning for vulnerable devices and deploying malware.
