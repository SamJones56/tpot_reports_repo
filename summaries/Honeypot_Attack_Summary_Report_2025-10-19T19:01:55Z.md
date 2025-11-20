
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T19:01:31Z
**Timeframe:** 2025-10-19T18:20:01Z to 2025-10-19T19:00:01Z
**Files Used:**
- agg_log_20251019T182001Z.json
- agg_log_20251019T184001Z.json
- agg_log_20251019T190001Z.json

---

## Executive Summary

This report summarizes 21,888 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force and command execution attempts. A significant number of events were also logged by Honeytrap and Suricata. The most prominent attacking IP address was 198.23.238.154. The most targeted port was 5038, commonly used for Asterisk Manager Interface (AMI), followed closely by ports 22 (SSH) and 5060 (SIP). A recurring pattern of commands suggests attackers are attempting to install SSH keys for persistent access.

---

## Detailed Analysis

### Attacks by Honeypot

* **Cowrie:** 10216
* **Honeytrap:** 5507
* **Suricata:** 1965
* **Sentrypeer:** 1712
* **Mailoney:** 906
* **Dionaea:** 694
* **Ciscoasa:** 685
* **H0neytr4p:** 66
* **Miniprint:** 45
* **ElasticPot:** 25
* **Dicompot:** 15
* **ConPot:** 17
* **Tanner:** 11
* **Honeyaml:** 10
* **Redishoneypot:** 9
* **Adbhoney:** 4
* **Ipphoney:** 1

### Top Attacking IPs

* **198.23.238.154:** 2791
* **20.164.21.26:** 1250
* **188.166.223.182:** 1246
* **115.242.61.98:** 905
* **72.146.232.13:** 900
* **198.23.190.58:** 862
* **23.94.26.58:** 836
* **176.65.141.119:** 821
* **80.246.81.187:** 635
* **198.12.68.114:** 603

### Top Targeted Ports/Protocols

* **5038:** 2695
* **22:** 1863
* **5060:** 1712
* **UDP/5060:** 929
* **25:** 883
* **445:** 635
* **5903:** 231
* **8333:** 172
* **5901:** 116

### Most Common CVEs

* **CVE-2005-4050:** 921
* **CVE-2019-15107:** 8
* **CVE-2019-11500:** 6
* **CVE-2021-3449:** 5
* **CVE-2002-0013 CVE-2002-0012:** 3
* **CVE-2001-0414:** 2
* **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 2
* **CVE-1999-0183:** 1
* **CVE-2021-35394:** 1

### Commands Attempted by Attackers

* **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 25
* **lockr -ia .ssh:** 25
* **cd ~ && rm -rf .ssh && ... (full command to add SSH key):** 25
* **cat /proc/cpuinfo | grep name | wc -l:** 25
* **cat /proc/cpuinfo | grep name | head -n 1 | awk ...:** 25
* **free -m | grep Mem | awk ...:** 25
* **ls -lh $(which ls):** 25
* **which ls:** 25
* **crontab -l:** 25
* **w:** 25
* **uname -m:** 25
* **cat /proc/cpuinfo | grep model | grep name | wc -l:** 25
* **top:** 25
* **uname:** 25
* **uname -a:** 25
* **whoami:** 25
* **lscpu | grep Model:** 25
* **df -h | head -n 2 | awk ...:** 25
* **Enter new UNIX password: :** 18
* **Enter new UNIX password:** 13
* **uname -s -v -n -r -m:** 5

### Signatures Triggered

* **ET VOIP MultiTech SIP UDP Overflow (2003237):** 921
* **ET DROP Dshield Block Listed Source group 1 (2402000):** 269
* **ET SCAN NMAP -sS window 1024 (2009582):** 130
* **ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753):** 80
* **ET INFO Reserved Internal IP Traffic (2002752):** 50
* **ET CINS Active Threat Intelligence Poor Reputation IP group 46 (2403345):** 24
* **ET SCAN Potential SSH Scan (2001219):** 19

### Users / Login Attempts

* **345gs5662d34/345gs5662d34:** 24
* **user01/Password01:** 16
* **deploy/123123:** 12
* **config/1234567:** 4
* **nobody/nobody2016:** 4
* **admin/00:** 4
* **admin/admin123:** 4
* **unknown/888888:** 4
* **root/2222:** 4

### Files Uploaded/Downloaded

* **session_login.cgi:** 8
* **wget.sh;**: 4
* **w.sh;**: 1
* **c.sh;**: 1
* **ohsitsvegawellrip.sh:** 1

### HTTP User-Agents
* (No data)

### SSH Clients
* (No data)

### SSH Servers
* (No data)

### Top Attacker AS Organizations
* (No data)

---

## Key Observations and Anomalies

1.  **Coordinated Command Execution:** A large number of identical commands were executed in sequence across multiple sessions, originating from different IPs. This suggests a botnet attempting to perform reconnaissance and establish persistence by adding a specific SSH key to `authorized_keys`.
2.  **VoIP Targeting:** The most frequent signature triggered (`ET VOIP MultiTech SIP UDP Overflow`) and the high number of connections to SIP ports (5060) indicate a widespread, ongoing campaign targeting VoIP systems.
3.  **Lack of Sophistication:** The login attempts consist of common and default credentials, and the executed commands are basic reconnaissance scripts. This behavior is typical of automated, opportunistic attacks rather than targeted campaigns.
4.  **No successful data exfiltration or deep system compromise was observed in the logs.** The attacks were limited to initial access attempts and basic command execution.
---
