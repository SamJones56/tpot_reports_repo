
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T00:01:31Z
**Timeframe:** 2025-10-11T23:20:01Z to 2025-10-12T00:00:02Z
**Files Used:**
- agg_log_20251011T232001Z.json
- agg_log_20251011T234001Z.json
- agg_log_20251012T000002Z.json

---

## Executive Summary

This report summarizes 24,010 events collected from the T-Pot honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. The most prominent attacker IP is 185.144.27.63. A significant number of alerts were triggered by the Suricata IDS, with a large portion related to the DoublePulsar backdoor, suggesting attempts to exploit SMB vulnerabilities. The primary targeted ports were 22 (SSH) and 445 (SMB). A variety of CVEs were detected, pointing to attackers attempting to exploit known vulnerabilities.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 14,503
- **Suricata:** 3,247
- **Honeytrap:** 2,984
- **Ciscoasa:** 1,886
- **Dionaea:** 730
- **Mailoney:** 177
- **Tanner:** 151
- **Sentrypeer:** 144
- **Redishoneypot:** 52
- **H0neytr4p:** 45
- **Adbhoney:** 32
- **Honeyaml:** 22
- **ElasticPot:** 12
- **ConPot:** 12
- **Ipphoney:** 6
- **Dicompot:** 4
- **Heralding:** 3

### Top Attacking IPs
- 185.144.27.63
- 156.197.107.223
- 41.68.184.107
- 196.251.84.181
- 129.0.165.10
- 106.51.92.114
- 45.78.226.118
- 202.125.94.71
- 139.59.24.22
- 138.124.186.209

### Top Targeted Ports/Protocols
- 22
- TCP/445
- 445
- 5903
- 25
- 80
- 5060
- 8333
- 5908
- 5909

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-35394 CVE-2021-35394
- CVE-2006-2369
- CVE-2018-2893 CVE-2018-2893 CVE-2018-2893
- CVE-2016-6563
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- operator/operator0
- test/1
- root/linux
- ftp/video
- sh/cd /tmp || ...
- unknown/qwer1234
- gast/gast
- nobody/654321

### Files Uploaded/Downloaded
- wget.sh;
- ns#
- ohshit.sh;
- rdf-schema#
- types#
- core#
- XMLSchema#
- www.drupal.org)
- Mozi.m
- XMLSchema-instance
- `cd

### HTTP User-Agents
- None recorded.

### SSH Clients and Servers
- **Clients:** None recorded.
- **Servers:** None recorded.

### Top Attacker AS Organizations
- None recorded.

---

## Key Observations and Anomalies

1.  **High Volume of DoublePulsar Scans:** The Suricata logs show a large number of events related to the DoublePulsar backdoor, indicating widespread scanning and exploitation attempts for the vulnerability (likely related to MS17-010). The IP `156.197.107.223` was solely responsible for these alerts.

2.  **Persistent SSH Brute-Forcing and Payload Delivery:** The IP `185.144.27.63` was extremely active across all three log files, consistently attempting to brute-force SSH credentials and execute commands. The commands attempted by this and other actors are typical of botnet recruitment, involving downloading and executing shell scripts from remote servers.

3.  **Credential Stuffing:** A wide variety of username/password combinations were attempted. The pair `345gs5662d34/345gs5662d34` was the most frequent, suggesting a targeted or bot-driven campaign using this specific credential.

4.  **Reconnaissance Activity:** Commands such as `cat /proc/cpuinfo`, `uname -a`, and `free -m` were frequently used, which is common for attackers trying to understand the environment of a compromised machine to tailor further attacks.
