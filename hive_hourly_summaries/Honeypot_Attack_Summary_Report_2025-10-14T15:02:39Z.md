
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T15:02:05Z
**Timeframe:** 2025-10-14T14:20:01Z to 2025-10-14T15:00:01Z
**Files:** agg_log_20251014T142001Z.json, agg_log_20251014T144001Z.json, agg_log_20251014T150001Z.json

## Executive Summary

This report summarizes 17,279 events collected from the honeypot network. The primary attack vectors observed were reconnaissance and brute-force attempts against Cowrie, Honeytrap, and Sentrypeer services. A significant portion of the traffic originated from a small number of IP addresses, suggesting targeted attacks. Multiple CVEs were detected, and attackers attempted to execute various commands to gain control of the systems.

## Detailed Analysis

### Attacks by Honeypot

*   **Cowrie:** 5545
*   **Honeytrap:** 3847
*   **Sentrypeer:** 3450
*   **Ciscoasa:** 1688
*   **Suricata:** 1524
*   **Dionaea:** 905
*   **Mailoney:** 84
*   **H0neytr4p:** 55
*   **Adbhoney:** 43
*   **Redishoneypot:** 40
*   **Tanner:** 27
*   **ElasticPot:** 19
*   **Dicompot:** 17
*   **Miniprint:** 9
*   **Ipphoney:** 5
*   **ConPot:** 2

### Top Attacking IPs

*   **206.191.154.180:** 1380
*   **185.243.5.146:** 1222
*   **190.103.31.169:** 670
*   **185.243.5.148:** 759
*   **196.251.84.181:** 477
*   **45.236.188.4:** 470
*   **172.86.95.98:** 409
*   **88.210.63.16:** 397
*   **172.86.95.115:** 395
*   **62.141.43.183:** 322
*   **89.117.54.101:** 302
*   **194.55.235.130:** 256
*   **193.24.123.88:** 246
*   **41.111.178.165:** 232

### Top Targeted Ports/Protocols

*   **5060:** 3450
*   **22:** 827
*   **445:** 719
*   **5903:** 195
*   **5901:** 151
*   **1433:** 139
*   **TCP/1433:** 137

### Most Common CVEs

*   CVE-2021-3449 CVE-2021-3449
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2018-10562 CVE-2018-10561
*   CVE-2006-2369
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

### Commands Attempted by Attackers

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 22
*   `lockr -ia .ssh`: 22
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 22
*   `cat /proc/cpuinfo | grep name | wc -l`: 22
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 22
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 22
*   `ls -lh $(which ls)`: 22
*   `which ls`: 22
*   `crontab -l`: 22
*   `w`: 22
*   `uname -m`: 22
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 22
*   `top`: 22
*   `uname`: 22
*   `uname -a`: 22
*   `whoami`: 22
*   `lscpu | grep Model`: 22
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 22
*   `Enter new UNIX password: `: 14
*   `Enter new UNIX password:`: 14

### Signatures Triggered

*   **ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753:** 341
*   **ET DROP Dshield Block Listed Source group 1 / 2402000:** 253
*   **ET SCAN NMAP -sS window 1024 / 2009582:** 148
*   **ET HUNTING RDP Authentication Bypass Attempt / 2034857:** 138
*   **ET SCAN Suspicious inbound to MSSQL port 1433 / 2010935:** 129
*   **ET INFO Reserved Internal IP Traffic / 2002752:** 57
*   **ET INFO CURL User Agent / 2002824:** 31
*   **ET SCAN Potential SSH Scan / 2001219:** 30

### Users / Login Attempts

*   **345gs5662d34/345gs5662d34:** 21
*   **root/123@@@:** 15
*   **guest/guest2025:** 6
*   **user/9:** 6
*   **blank/blank2001:** 6
*   **debian/555555:** 6
*   **root/Password@2025:** 11

### Files Uploaded/Downloaded

*   gpon80&ipv=0
*   bot.html)
*   soap-envelope
*   addressing
*   discovery
*   devprof
*   soap:Envelope>

### HTTP User-Agents

*   No HTTP User-Agents were logged in this period.

### SSH Clients and Servers

*   No SSH clients or servers were logged in this period.

### Top Attacker AS Organizations

*   No attacker AS organizations were logged in this period.

## Key Observations and Anomalies

*   A large number of attacks were concentrated on a few specific IP addresses, indicating a targeted campaign rather than random scanning.
*   The commands executed suggest an attempt to establish persistent access by adding an SSH key to the `authorized_keys` file.
*   The presence of multiple CVEs related to older vulnerabilities suggests that attackers are still attempting to exploit known security holes.
*   The high number of events on port 5060 (Sentrypeer) indicates a focus on VoIP-related attacks.
*   No successful breaches were reported by any of the honeypots. All recorded events are attempts that were successfully logged and contained.
