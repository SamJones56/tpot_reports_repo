
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T22:01:29Z
**Timeframe:** 2025-10-21T21:20:01Z to 2025-10-21T22:00:01Z
**Log Files:**
- agg_log_20251021T212001Z.json
- agg_log_20251021T214001Z.json
- agg_log_20251021T220001Z.json

---

## Executive Summary

This report summarizes 24,554 events collected from the honeypot network. The majority of attacks were captured by the Dionaea, Suricata, and Honeytrap honeypots. The most frequently targeted service was SMB on port 445. A significant number of attacks originated from the IP address 120.210.147.60. Multiple CVEs were detected, with CVE-2022-27255 being the most common. Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access via SSH authorized keys.

---

## Detailed Analysis

### Attacks by Honeypot
- **Dionaea:** 6,319
- **Suricata:** 5,147
- **Honeytrap:** 4,007
- **Heralding:** 3,291
- **Cowrie:** 2,991
- **Ciscoasa:** 1,693
- **Sentrypeer:** 690
- **H0neytr4p:** 94
- **Tanner:** 66
- **Mailoney:** 78
- **ElasticPot:** 53
- **Redishoneypot:** 42
- **ssh-rsa:** 34
- **Adbhoney:** 18
- **Dicompot:** 9
- **Honeyaml:** 10
- **ConPot:** 5
- **Ipphoney:** 3
- **Wordpot:** 2
- **ssh-ed25519:** 2

### Top Attacking IPs
- **120.210.147.60:** 3,145
- **113.193.2.42:** 3,117
- **10.208.0.3:** 3,299
- **185.243.96.105:** 3,291
- **72.146.232.13:** 1,148
- **198.23.190.58:** 524
- **88.210.63.16:** 351
- **107.170.36.5:** 252
- **107.150.97.192:** 209
- **196.251.71.24:** 176
- **41.77.220.188:** 188
- **167.250.224.25:** 136
- **115.78.226.174:** 140
- **23.94.26.58:** 128
- **103.90.225.35:** 116
- **103.23.199.128:** 85
- **68.183.149.135:** 74
- **54.38.52.18:** 154
- **45.56.66.46:** 44
- **162.243.173.102:** 43

### Top Targeted Ports/Protocols
- **445:** 6,273
- **vnc/5900:** 3,288
- **5060:** 690
- **22:** 707
- **UDP/5060:** 263
- **2020:** 224
- **5903:** 226
- **8333:** 123
- **80:** 67
- **443:** 92
- **5901:** 118
- **25:** 78
- **9200:** 38
- **23:** 40
- **TCP/80:** 42
- **5904:** 78
- **5905:** 79

### Most Common CVEs
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-2024-3721
- CVE-2019-11500
- CVE-2021-3449
- CVE-2025-57819
- CVE-2018-10562
- CVE-2018-10561
- CVE-1999-0517

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/uptime 2 > /dev/null | cut -d. -f1`
- `uname -a`
- `whoami`
- `w`
- `uname -m`
- `crontab -l`
- `which ls`
- `ls -lh $(which ls)`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`

### Signatures Triggered
- **ET INFO VNC Authentication Failure:** 3,288
- **2002920:** 3,288
- **ET DROP Dshield Block Listed Source group 1:** 335
- **2402000:** 335
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 313
- **2023753:** 313
- **ET SCAN Sipsak SIP scan:** 215
- **2008598:** 215
- **ET SCAN NMAP -sS window 1024:** 170
- **2009582:** 170
- **ET HUNTING RDP Authentication Bypass Attempt:** 119
- **2034857:** 119
- **ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255):** 40
- **2038669:** 40
- **ET INFO Reserved Internal IP Traffic:** 58

### Users / Login Attempts
- **root/:** 34
- **/passw0rd:** 16
- **/1q2w3e4r:** 13
- **/1qaz2wsx:** 8
- **/Passw0rd:** 7
- **345gs5662d34/345gs5662d34:** 6
- **root/Ati493ati:** 4
- **root/AtsC00m!:** 4
- **/qwertyui:** 7
- **odin/odin:** 4
- **root/AtzitM2015:** 4
- **root/aug5roEv:** 4
- **root/AUSnet2015:** 3
- **root/Av1dad0n11:** 3
- **root/aum.ganapati:** 4

### Files Uploaded/Downloaded
- **wget.sh;**: 8
- **gpon80&ipv=0**: 4
- **w.sh;**: 2
- **c.sh;**: 2

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

---

## Key Observations and Anomalies

- **High Volume of SMB and VNC Scans:** The vast majority of traffic targeted ports 445 (SMB) and 5900 (VNC), indicating widespread, automated scanning for these services.
- **Persistent SSH Key Installation:** A recurring pattern involves attackers attempting to remove existing SSH configurations and install their own public key (`authorized_keys`). This is a common technique to gain persistent access to a compromised machine.
- **Targeting of Realtek Devices:** The presence of exploits for CVE-2022-27255 suggests that attackers are actively targeting vulnerabilities in Realtek SDKs, which are common in IoT and embedded devices.
- **Lack of Sophistication:** The majority of observed attacks are automated and rely on common vulnerabilities and weak credentials. The command execution patterns do not indicate highly sophisticated, targeted attacks.
---
