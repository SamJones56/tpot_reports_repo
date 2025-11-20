Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T18:01:41Z
**Timeframe:** 2025-10-20T17:20:01Z to 2025-10-20T18:00:01Z
**Files:** agg_log_20251020T172001Z.json, agg_log_20251020T174001Z.json, agg_log_20251020T180001Z.json

### Executive Summary
This report summarizes 22,098 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. Attackers were observed targeting a variety of services, with a focus on SSH (port 22) and SMB (port 445). A significant number of brute-force login attempts and exploit attempts for various CVEs were recorded.

### Detailed Analysis

**Attacks by Honeypot**
* Cowrie: 9630
* Honeytrap: 8260
* Suricata: 3154
* Sentrypeer: 378
* Dionaea: 185
* Redishoneypot: 145
* Mailoney: 127
* Adbhoney: 38
* Tanner: 44
* ElasticPot: 26
* Ciscoasa: 30
* H0neytr4p: 20
* Miniprint: 19
* ConPot: 13
* Dicompot: 11
* Honeyaml: 12
* Ipphoney: 6

**Top Attacking IPs**
* 77.83.240.70: 3431
* 45.176.66.83: 1355
* 51.89.1.87: 1250
* 38.75.136.81: 1251
* 117.72.114.221: 1251
* 72.146.232.13: 1215
* 41.216.177.55: 436
* 150.95.190.167: 418
* 202.39.251.216: 291
* 61.12.84.15: 358
* 128.1.44.115: 257
* 57.129.61.16: 277
* 216.108.227.59: 174
* 107.170.36.5: 166
* 185.243.5.158: 169
* 196.251.80.165: 123
* 77.83.207.203: 112

**Top Targeted Ports/Protocols**
* 22: 1682
* TCP/445: 1352
* 6443: 214
* 5060: 378
* 5903: 219
* 8333: 154
* 25: 127
* 6379: 136
* 5901: 114
* 2121: 156
* TCP/80: 60
* 80: 25
* 5904: 76
* 5905: 77

**Most Common CVEs**
* CVE-2002-0013 CVE-2002-0012: 13
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 11
* CVE-2021-44228 CVE-2021-44228: 5
* CVE-2021-3449 CVE-2021-3449: 6
* CVE-2019-11500 CVE-2019-11500: 5
* CVE-2024-4577 CVE-2002-0953: 2
* CVE-2024-4577 CVE-2024-4577: 2
* CVE-2001-0414: 1
* CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
* CVE-2021-42013 CVE-2021-42013: 1
* CVE-2005-4050: 1

**Commands Attempted by Attackers**
* lscpu | grep Model: 34
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 34
* uname -a: 34
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 34
* lockr -ia .ssh: 34
* cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 34
* cat /proc/cpuinfo | grep name | wc -l: 34
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 34
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 34
* ls -lh $(which ls): 34
* which ls: 34
* crontab -l: 34
* w: 33
* uname -m: 33
* cat /proc/cpuinfo | grep model | grep name | wc -l: 33
* top: 33
* uname: 32
* whoami: 33
* Enter new UNIX password: : 24
* Enter new UNIX password::: 25

**Signatures Triggered**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1348
* ET DROP Dshield Block Listed Source group 1: 349
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 282
* ET SCAN NMAP -sS window 1024: 172
* ET HUNTING RDP Authentication Bypass Attempt: 80
* ET INFO Reserved Internal IP Traffic: 59
* GPL INFO SOCKS Proxy attempt: 15
* ET SCAN Potential SSH Scan: 14
* ET CINS Active Threat Intelligence Poor Reputation IP group 47: 24
* ET CINS Active Threat Intelligence Poor Reputation IP group 45: 22
* ET CINS Active Threat Intelligence Poor Reputation IP group 46: 21
* ET CINS Active Threat Intelligence Poor Reputation IP group 43: 21
* ET CINS Active Threat Intelligence Poor Reputation IP group 49: 11
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 11
* ET CINS Active Threat Intelligence Poor Reputation IP group 51: 10
* ET SCAN Suspicious inbound to MSSQL port 1433: 9

**Users / Login Attempts**
* 345gs5662d34/345gs5662d34: 32
* user01/Password01: 11
* deploy/123123: 11
* sa/GCSsa5560: 8
* gcs_client/SysGal.5560: 8
* gcs_web_client/SysGal.5560: 8
* root/adminbtl: 4
* root/adminbtl2013: 4
* root/ADMINGEOLOG: 4
* root/admingfhjkm: 4
* root/adminelas123: 4
* root/AdminElastix252015: 4
* root/3245gs5662d34: 3
* deploy/3245gs5662d34: 3
* root/1qazZXCV: 3
* tester/test: 3
* dima/dima: 3
* nikola/3245gs5662d34: 3
* yinshishu/123: 3
* behzad/behzad123: 3
* hanif/hanif123: 3
* brs/brs: 3
* hussain/hussain: 3
* manasa/3245gs5662d34: 3
* user1/123123: 3

**Files Uploaded/Downloaded**
* sh: 90
* wget.sh;: 16
* w.sh;: 4
* c.sh;: 4

**HTTP User-Agents**
* (No user agents recorded in this period)

**SSH Clients and Servers**
* (No specific client/server software versions recorded)

**Top Attacker AS Organizations**
* (No AS organization data available in the logs)

### Key Observations and Anomalies
* A large number of commands executed are related to reconnaissance and establishing a foothold, such as enumerating system hardware, managing SSH keys, and attempting to disable security features.
* The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...` is a clear indicator of attackers trying to install their SSH key for persistent access.
* The file `sh` being downloaded/uploaded 90 times suggests the use of shell scripts for automation by the attackers.
* The DoublePulsar backdoor signature was triggered a high number of times, indicating attempts to exploit the SMB vulnerability (likely related to EternalBlue).
