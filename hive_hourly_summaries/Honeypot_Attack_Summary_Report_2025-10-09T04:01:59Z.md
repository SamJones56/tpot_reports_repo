Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T04:01:35Z
**Timeframe Covered:** 2025-10-09T03:20:01Z - 2025-10-09T04:00:01Z
**Log Files Used:**
- agg_log_20251009T032001Z.json
- agg_log_20251009T034001Z.json
- agg_log_20251009T040001Z.json

---

### Executive Summary

This report summarizes 19,003 malicious events captured by the honeypot network. The most engaged honeypot was Cowrie, logging 6,706 events, primarily related to SSH and Telnet brute-force attempts and command execution. Suricata detected 4,809 network intrusions, with a significant amount of traffic related to SMB exploits.

The most prominent activity was scanning and exploitation attempts targeting SMB (TCP/445), likely from automated bots spreading malware like WannaCry, indicated by the `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signature. Brute-force attacks against SSH (port 22) and email services (port 25) were also highly prevalent. Top attacking IPs originate from various geolocations, with `5.44.172.76` and `86.54.42.238` being the most active sources. Attackers consistently attempted to execute a series of reconnaissance commands to profile the system and subsequently tried to add their public SSH key to the `authorized_keys` file for persistent access.

---

### Detailed Analysis

**Attacks by Honeypot**
- **Cowrie:** 6,706
- **Suricata:** 4,809
- **Honeytrap:** 3,237
- **Mailoney:** 1,688
- **Ciscoasa:** 1,543
- **Dionaea:** 751
- **Sentrypeer:** 59
- **H0neytr4p:** 35
- **ConPot:** 26
- **Tanner:** 113
- **Honeyaml:** 14
- **Adbhoney:** 4
- **Ipphoney:** 5
- **ElasticPot:** 3
- **Redishoneypot:** 3
- **Dicompot:** 3
- **Heralding:** 3
- **Wordpot:** 1

**Top 10 Attacking IPs**
- **5.44.172.76:** 2,376
- **86.54.42.238:** 1,641
- **80.94.95.238:** 961
- **46.1.103.71:** 429
- **192.3.105.24:** 337
- **103.82.240.194:** 283
- **188.246.224.87:** 292
- **161.132.37.66:** 233
- **114.219.56.203:** 207
- **91.108.227.22:** 288

**Top Targeted Ports/Protocols**
- **TCP/445:** 2,379
- **25:** 1,688
- **22:** 918
- **TCP/21:** 210
- **5903:** 200
- **80:** 111
- **21:** 102
- **8333:** 80
- **23:** 59
- **5901:** 71

**Most Common CVEs**
- CVE-2001-0414
- CVE-1999-0183
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2018-10562 CVE-2018-10561

**Commands Attempted by Attackers**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `whoami`
- `uname -a`
- `top`

**Top 10 Signatures Triggered**
- `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`: 2,370
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 818
- `ET DROP Dshield Block Listed Source group 1`: 418
- `ET SCAN NMAP -sS window 1024`: 153
- `ET FTP FTP PWD command attempt without login`: 105
- `ET FTP FTP CWD command attempt without login`: 103
- `ET HUNTING RDP Authentication Bypass Attempt`: 108
- `ET INFO Reserved Internal IP Traffic`: 60
- `ET SCAN Potential SSH Scan`: 22
- `ET CINS Active Threat Intelligence Poor Reputation IP group 46`: 24

**Top 10 Users / Login Attempts**
- **345gs5662d34/345gs5662d34:** 33
- **support/abcdefgh:** 8
- **default/default22:** 6
- **blank/blank22:** 6
- **default/techsupport:** 6
- **supervisor/admin123:** 6
- **support/support1234567890:** 6
- **test/test33:** 6
- **operator/1q2w3e4r:** 6
- **guest/guest3:** 4

**Files Uploaded/Downloaded**
- `ip`: 2
- `rondo.naz.sh|sh&...`: 1
- `rondo.qpu.sh||wget`: 1
- `rondo.qpu.sh)|sh&echo`: 1
- `gpon80&ipv=0`: 4

**HTTP User-Agents**
- None observed in the provided logs.

**SSH Clients and Servers**
- **Clients:** None observed in the provided logs.
- **Servers:** None observed in the provided logs.

**Top Attacker AS Organizations**
- None observed in the provided logs.

---

### Key Observations and Anomalies

1.  **High Volume of SMB Exploitation:** The vast majority of Suricata alerts are related to the DoublePulsar backdoor, indicating widespread, automated scanning and exploitation of the vulnerability associated with WannaCry ransomware. This is the most significant threat observed.
2.  **Automated SSH Reconnaissance and Persistence:** A consistent pattern of commands was executed in Cowrie sessions. Attackers are not manually exploring but are running automated scripts to gather system information (CPU, memory, etc.) and immediately attempt to install a persistent SSH key. This indicates botnet-driven activity aimed at building a network of compromised devices.
3.  **Mail Service Brute-Forcing:** A significant number of events targeted port 25 (SMTP). This suggests large-scale attempts to find open relays for spam campaigns or to brute-force credentials for corporate email accounts.
4.  **Lack of Sophistication:** The attacks, while high in volume, are largely unsophisticated and rely on exploiting old, well-known vulnerabilities (SMBv1) or weak credentials (SSH brute-force). This is typical of widespread, automated botnet activity rather than targeted attacks.