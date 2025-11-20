Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T16:01:30Z
**Timeframe:** 2025-10-06T15:20:01Z to 2025-10-06T16:00:01Z
**Files Used:**
- agg_log_20251006T152001Z.json
- agg_log_20251006T154001Z.json
- agg_log_20251006T160001Z.json

### Executive Summary
This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 9,388 attacks were recorded, with Cowrie, Honeytrap, and Suricata being the most frequently targeted honeypots. The majority of attacks originated from a diverse set of IP addresses, with a significant number targeting ports 22 (SSH) and 5060 (SIP). Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access. Multiple CVEs were exploited, with CVE-2021-44228 (Log4j) being the most common.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 3432
- Honeytrap: 1899
- Suricata: 1680
- Ciscoasa: 1232
- Sentrypeer: 458
- Dionaea: 423
- H0neytr4p: 80
- Redishoneypot: 43
- Mailoney: 39
- ConPot: 35
- Adbhoney: 34
- Tanner: 24
- Ipphoney: 4
- Honeyaml: 3
- ElasticPot: 2

**Top Attacking IPs:**
- 188.235.159.76
- 170.64.159.245
- 196.251.88.103
- 80.94.95.238
- 172.86.95.98
- 85.185.112.6
- 88.210.63.16
- 221.225.83.45

**Top Targeted Ports/Protocols:**
- 22
- 5060
- 445
- TCP/22
- 443
- 5903
- 6379
- TCP/80

**Most Common CVEs:**
- CVE-2021-44228
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2006-2369
- CVE-2005-4050
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2020-10987
- CVE-2023-31983
- CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051, CVE-2024-33112, CVE-2022-37056, CVE-2019-10891

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- crontab -l
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan

**Users / Login Attempts:**
- ubuntu/ubuntu
- admin/120983
- root/12345
- 345gs5662d34/345gs5662d34
- admin/intelcore2duo
- anonymous/
- root/adminHW
- solana/1234567890

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- server.cgi?func=server02_main_submit...
- rondo.qre.sh||busybox
- rondo.qre.sh||curl
- login_pic.asp

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies
- The high number of attacks on Cowrie (SSH honeypot) suggests a focus on compromising systems via SSH.
- The prevalence of CVE-2021-44228 (Log4j) indicates that attackers are still actively exploiting this vulnerability.
- The commands attempted by attackers show a clear pattern of reconnaissance, attempting to establish persistence, and downloading additional malware.
- The absence of HTTP User-Agents, SSH client/server information, and AS organization data might indicate limitations in the current logging setup or that attacks are primarily at the network layer without full session establishment.

This concludes the Honeypot Attack Summary Report.
