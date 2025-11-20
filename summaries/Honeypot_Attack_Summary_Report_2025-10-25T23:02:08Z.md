Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T23:01:32Z
**Timeframe:** 2025-10-25T22:20:01Z to 2025-10-25T23:00:01Z
**Files Used:**
- agg_log_20251025T222001Z.json
- agg_log_20251025T224001Z.json
- agg_log_20251025T230001Z.json

### Executive Summary
This report summarizes honeypot activity over a short period, totaling 25,608 observed events. The primary attack vectors were SSH (Cowrie), network scanning (Honeytrap), and Suricata alerts. The most prolific attacker IP was `109.205.211.9`. A significant portion of the activity involved attempts to modify SSH authorized_keys and reconnaissance commands to profile the system. Multiple CVEs were detected, with CVE-2022-27255 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8,832
- Honeytrap: 6,970
- Suricata: 6,762
- Ciscoasa: 1,766
- Dionaea: 639
- Sentrypeer: 378
- Mailoney: 102
- H0neytr4p: 52
- Adbhoney: 33
- Tanner: 22
- Redishoneypot: 16
- ElasticPot: 10
- Honeyaml: 8
- ConPot: 8
- Ipphoney: 5
- Heralding: 3
- Medpot: 2

**Top Attacking IPs:**
- 109.205.211.9
- 80.94.95.238
- 206.189.83.92
- 138.197.43.50
- 41.139.169.77
- 181.143.226.68
- 155.248.164.42
- 223.221.36.42
- 23.94.26.58
- 102.176.81.29

**Top Targeted Ports/Protocols:**
- 22
- 445
- 5060
- 8333
- 5903
- 5901
- 25
- TCP/22
- 5905
- 5904

**Most Common CVEs:**
- CVE-2022-27255 CVE-2022-27255
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/2
- root/password1000
- yql/yql
- mark/mark1
- mark/3245gs5662d34
- share/share
- root/finefood
- noel/noel123

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- rondo.dtm.sh||busybox
- rondo.dtm.sh||curl
- rondo.dtm.sh)|sh

**HTTP User-Agents:**
- (No data)

**SSH Clients:**
- (No data)

**SSH Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

### Key Observations and Anomalies
- A significant number of commands are geared towards establishing persistent SSH access by modifying the `.ssh/authorized_keys` file.
- Attackers are frequently using system reconnaissance commands like `uname -a`, `lscpu`, and `free -m` to understand the environment they have compromised.
- The `arm.*.urbotnetisass` and `rondo.dtm.sh` files suggest attempts to download and execute malware payloads, likely for botnet recruitment.
- The high number of "MS Terminal Server Traffic on Non-standard Port" alerts indicates widespread scanning for RDP services.
- The presence of CVE-2022-27255 (Realtek eCos RSDK/MSDK Stack-based Buffer Overflow) indicates that attackers are targeting IoT devices.
