Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T05:01:45Z
**Timeframe:** 2025-10-22T04:20:02Z to 2025-10-22T05:00:01Z
**Files Used:**
- agg_log_20251022T042002Z.json
- agg_log_20251022T044001Z.json
- agg_log_20251022T050001Z.json

### Executive Summary
This report summarizes 27,967 events collected from the honeypot network. The majority of attacks were detected by Suricata, Cowrie, and Heralding honeypots. The most prominent attack vector was VNC authentication failures, originating from a small number of IP addresses. A number of CVEs were targeted, and attackers attempted various commands, including efforts to add SSH keys for persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 8202
- Cowrie: 7495
- Heralding: 5581
- Honeytrap: 3043
- Ciscoasa: 1800
- Dionaea: 1308
- Sentrypeer: 273
- Mailoney: 101
- Tanner: 26
- H0neytr4p: 26

**Top Attacking IPs:**
- 10.208.0.3: 5587
- 185.243.96.105: 5582
- 111.175.37.46: 3014
- 180.232.204.50: 1139
- 72.146.232.13: 1176
- 185.231.59.125: 926
- 177.27.71.43: 680
- 112.196.70.142: 253
- 88.210.63.16: 293
- 23.91.96.123: 258

**Top Targeted Ports/Protocols:**
- vnc/5900: 5581
- 22: 1550
- 445 (TCP/445): 1861
- 5060: 273
- 5903: 221
- 1433 (TCP/1433): 143
- 8333: 134
- 25: 101
- 5901: 110

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2021-3449
- CVE-1999-0183
- CVE-2024-3721
- CVE-2018-10562, CVE-2018-10561
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2002-0013, CVE-2002-0012

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- uname -a
- whoami
- uname -s -v -n -r -m

**Signatures Triggered:**
- ET INFO VNC Authentication Failure: 5581
- ET DROP Dshield Block Listed Source group 1: 461
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 680
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 288
- ET SCAN NMAP -sS window 1024: 176
- ET HUNTING RDP Authentication Bypass Attempt: 130
- ET SCAN Suspicious inbound to MSSQL port 1433: 91

**Users / Login Attempts:**
- /Passw0rd: 30
- /1q2w3e4r: 18
- /passw0rd: 16
- 345gs5662d34/345gs5662d34: 9
- root/balcao2015: 4
- root/balcao9420202: 4
- user01/Password01: 3

**Files Uploaded/Downloaded:**
- wget.sh;: 4
- gpon80&ipv=0: 4
- 11: 2
- fonts.gstatic.com: 2
- w.sh;: 1
- c.sh;: 1

**HTTP User-Agents:**
- No HTTP User-Agents were recorded in this period.

**SSH Clients and Servers:**
- **Clients:** No SSH clients were recorded in this period.
- **Servers:** No SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in this period.

### Key Observations and Anomalies
- The overwhelming number of events are related to VNC authentication failures, all targeting port 5900 from the IP address `185.243.96.105`. This suggests a targeted and persistent attack from a single source.
- A significant number of commands were executed by attackers, indicating successful initial access. Many of these commands are focused on reconnaissance and establishing persistence, such as adding a new SSH key to `authorized_keys`.
- The presence of DoublePulsar backdoor activity is a critical finding, indicating more sophisticated attacks are occurring.
- The variety of CVEs being targeted shows a broad-spectrum approach by some attackers, attempting to exploit a range of vulnerabilities.