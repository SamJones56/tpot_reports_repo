# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T16:01:34Z
**Timeframe:** 2025-10-07T15:20:01Z to 2025-10-07T16:00:01Z
**Files Used:**
- agg_log_20251007T152001Z.json
- agg_log_20251007T154001Z.json
- agg_log_20251007T160001Z.json

---

## Executive Summary

This report summarizes 13,122 events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie (SSH/Telnet), Mailoney (SMTP), and Honeytrap honeypots. A significant portion of the activity involved reconnaissance scans and automated exploitation attempts.

The most prominent attack vector was SMTP relay attempts, reflected by the high volume of traffic on port 25. SSH brute-force and command injection attempts were also highly prevalent. Attackers frequently attempted to exploit CVE-2021-44228 (Log4Shell). A notable observation is the consistent attempt by multiple attackers to deploy a new SSH authorized key for persistent access.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7,203
- **Honeytrap:** 2,085
- **Suricata:** 1,735
- **Mailoney:** 1,280
- **Sentrypeer:** 614
- **ConPot:** 38
- **Adbhoney:** 35
- **Tanner:** 27
- **Redishoneypot:** 20
- **H0neytr4p:** 27
- **Dionaea:** 11
- **Honeyaml:** 14
- **Ipphoney:** 12
- **Dicompot:** 6
- **Heralding:** 3
- **Ciscoasa:** 2

### Top Attacking IPs
- **93.115.79.198:** 936
- **45.140.17.52:** 831
- **176.65.141.117:** 820
- **209.38.88.14:** 675
- **185.255.126.223:** 564
- **86.54.42.238:** 390
- **113.30.191.232:** 362
- **91.237.163.110:** 422
- **79.168.139.28:** 401
- **125.21.59.218:** 293
- **193.106.245.20:** 293

### Top Targeted Ports/Protocols
- **25:** 1,280
- **22:** 1,014
- **5060:** 614
- **8333:** 197
- **5903:** 95
- **23:** 117
- **TCP/5432:** 69
- **55555:** 30
- **TCP/22:** 44
- **10443:** 37

### Most Common CVEs
- **CVE-2021-44228:** 27
- **CVE-2002-0013, CVE-2002-0012:** 5
- **CVE-2002-0013, CVE-2002-0012, CVE-1999-0517:** 2
- **CVE-2019-11500:** 1
- **CVE-2016-6563:** 1
- **CVE-2023-26801:** 1
- **CVE-2006-2369:** 1
- **CVE-2021-35394:** 1

### Commands Attempted by Attackers
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 34
- **lockr -ia .ssh:** 34
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...":** 34
- **cat /proc/cpuinfo | grep name | wc -l:** 34
- **Enter new UNIX password:** 34
- **uname -a:** 34
- **whoami:** 34
- **tftp; wget; /bin/busybox URRJB:** 1

### Signatures Triggered
- **ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753):** 570
- **ET DROP Dshield Block Listed Source group 1 (2402000):** 358
- **ET SCAN NMAP -sS window 1024 (2009582):** 159
- **ET INFO Reserved Internal IP Traffic (2002752):** 57
- **ET SCAN Suspicious inbound to PostgreSQL port 5432 (2010939):** 48
- **ET SCAN Potential SSH Scan (2001219):** 29
- **ET SCAN Suspicious inbound to MSSQL port 1433 (2010935):** 21

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 34
- **sysadmin/sysadmin@1:** 12
- **lab/3245gs5662d34:** 4
- **ubuntu/666666:** 3
- **ubuntu/Password1234:** 3
- **rustserver/Passw0rd@123:** 3
- **postgres/postgres:** 3
- **oracle/oracle123:** 3

### Files Uploaded/Downloaded
- **wget.sh;**: 24
- **w.sh;**: 7
- **c.sh;**: 7
- **mips**: 2
- **Mozi.m**: 2
- **Space.mips;**: 2

### HTTP User-Agents
- No user-agents were logged.

### SSH Clients
- No specific SSH clients were logged.

### SSH Servers
- No specific SSH servers were logged.

### Top Attacker AS Organizations
- No attacker AS organizations were logged.

---

## Key Observations and Anomalies

1.  **Surge in SMTP Activity:** There was a dramatic increase in attacks targeting port 25 (SMTP) in the last monitoring period, primarily logged by the Mailoney honeypot. This suggests a large-scale campaign focused on spam relay or reconnaissance of mail servers.

2.  **Automated SSH Key Injection:** A recurring and dominant pattern is the execution of a series of shell commands designed to remove existing SSH configurations and inject a new public key (`ssh-rsa AAAAB3N...`). This indicates a widespread, automated campaign to gain persistent access to compromised servers.

3.  **High-Volume, Short-Duration Attacks:** The IP address `176.65.141.117` was responsible for 820 events in a very short timeframe and only appeared in the most recent log file. This type of burst activity is indicative of a fast-moving, automated scanner or a newly activated bot.

4.  **Persistent Log4Shell Scanning:** The continued high frequency of attempts to exploit `CVE-2021-44228` highlights that attackers still find this vulnerability to be a valuable entry point for initial access.
