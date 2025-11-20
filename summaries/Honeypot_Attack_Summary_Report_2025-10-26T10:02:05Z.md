# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T10:01:34Z
**Timeframe:** 2025-10-26T09:20:01Z to 2025-10-26T10:00:01Z
**Files Used:**
- agg_log_20251026T092001Z.json
- agg_log_20251026T094001Z.json
- agg_log_20251026T100001Z.json

---

### Executive Summary

This report summarizes a total of 21,721 attacks recorded across three honeypot log files over a period of approximately 40 minutes. The majority of attacks were detected by the Suricata honeypot, with a significant number of attempts also logged by Cowrie and Honeytrap. The most prominent attacker IP was 109.205.211.9, responsible for over 25% of the total attacks. Port 445 (SMB) was the most targeted port, indicating a high volume of attempts to exploit file-sharing services. A variety of CVEs were targeted, with a focus on older vulnerabilities. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

---

### Detailed Analysis

#### Attacks by Honeypot
- **Suricata:** 7,045
- **Cowrie:** 4,931
- **Honeytrap:** 4,531
- **Dionaea:** 2,310
- **Ciscoasa:** 1,762
- **Sentrypeer:** 737
- **Mailoney:** 108
- **Adbhoney:** 91
- **Tanner:** 59
- **ConPot:** 52
- **H0neytr4p:** 27
- **Redishoneypot:** 21
- **ElasticPot:** 11
- **Dicompot:** 10
- **Miniprint:** 10
- **Ipphoney:** 8
- **Wordpot:** 3
- **Heralding:** 3
- **Honeyaml:** 2

#### Top Attacking IPs
- **109.205.211.9:** 5,533
- **41.139.164.134:** 1,740
- **59.182.215.119:** 1,069
- **185.243.5.121:** 485
- **115.113.198.245:** 451
- **196.0.120.6:** 357
- **183.91.11.36:** 347
- **185.177.239.199:** 342
- **80.94.95.238:** 298
- **104.208.108.166:** 264
- **38.25.39.212:** 257
- **84.22.147.211:** 249
- **14.194.101.210:** 246

#### Top Targeted Ports/Protocols
- **445 (SMB):** 2,211
- **TCP/445:** 1,074
- **5060 (SIP):** 737
- **22 (SSH):** 615
- **8333:** 148
- **5903 (VNC):** 134
- **5901 (VNC):** 117
- **25 (SMTP):** 108
- **TCP/80 (HTTP):** 55
- **80 (HTTP):** 41

#### Most Common CVEs
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2002-1149
- CVE-1999-0183
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2023-31983
- CVE-2020-10987
- CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051, CVE-2019-10891, CVE-2024-33112, CVE-2025-11488, CVE-2022-37056

#### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

#### Signatures Triggered
- **ET SCAN MS Terminal Server Traffic on Non-standard Port (sid:2023753):** 3,053
- **ET HUNTING RDP Authentication Bypass Attempt (sid:2034857):** 1,423
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (sid:2024766):** 1,063
- **ET DROP Dshield Block Listed Source group 1 (sid:2402000):** 444
- **ET SCAN NMAP -sS window 1024 (sid:2009582):** 177

#### Users / Login Attempts
- **345gs5662d34/345gs5662d34**
- **root/3245gs5662d34**
- **root/Gempsa2018mycodeadvancec0m**
- **root/Gempsa2018t**
- **root/Geo2012**
- **root/German22**
- **root/Geron8585**
- **admin/120393**
- **admin/120282**
- **admin/120281**
- **ping/ping**
- **git/gogs123**

#### Files Uploaded/Downloaded
- `wget.sh`
- `w.sh`
- `c.sh`
- `server.cgi`
- `rondo.qre.sh`
- `login_pic.asp`
- `?format=json`

---

### Key Observations and Anomalies

- **High Volume of SMB Traffic:** The significant number of attacks targeting port 445 suggests a widespread campaign to exploit SMB vulnerabilities, possibly related to older vulnerabilities like WannaCry or other ransomware.
- **Persistent SSH Key Installation:** A recurring command involves adding an SSH key to the `authorized_keys` file. This indicates a clear objective to establish persistent, passwordless access to compromised systems. The use of `chattr` and `lockr` suggests an attempt to make these changes immutable.
- **Reconnaissance Commands:** The frequent use of commands like `uname`, `lscpu`, `free`, and `df` indicates that attackers are performing reconnaissance to understand the system's architecture and resources before deploying further payloads.
- **Use of `wget` and `curl`:** Attackers frequently use `wget` and `curl` to download additional scripts and payloads from remote servers. The URLs used in these commands should be considered malicious and blocked.
- **DoublePulsar Backdoor:** The triggering of the "DoublePulsar Backdoor" signature is a strong indicator of attempts to install a known NSA-leaked exploit, which is a serious threat.
