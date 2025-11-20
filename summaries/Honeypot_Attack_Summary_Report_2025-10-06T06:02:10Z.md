
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T06:01:44Z
**Timeframe:** Approximately 1 hour of logs from 2025-10-06 between 05:20 and 06:00 UTC.
**Log Files:**
- agg_log_20251006T052001Z.json
- agg_log_20251006T054001Z.json
- agg_log_20251006T060001Z.json

---

## Executive Summary

This report summarizes 14,820 malicious events captured by the honeypot network. The majority of attacks were intercepted by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force attempts. A significant number of attacks also targeted SMB services (port 445), primarily logged by the Dionaea and Honeytrap honeypots.

Attackers predominantly originated from IP addresses `137.184.79.87`, `119.93.102.70`, and `176.65.141.117`. The most frequently targeted services were SMB (port 445), SSH (port 22), and SMTP (port 25).

Automated attack scripts were observed attempting system reconnaissance and attempting to install malicious SSH authorized keys. Additionally, multiple scans targeting the Log4j vulnerability (CVE-2021-44228) were detected. Network IDS signatures were frequently triggered by sources on DShield and Spamhaus blocklists.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6108
- **Honeytrap:** 2249
- **Dionaea:** 2102
- **Suricata:** 1422
- **Ciscoasa:** 1361
- **Mailoney:** 856
- **Sentrypeer:** 428
- **H0neytr4p:** 89
- **Tanner:** 62
- **Adbhoney:** 39
- **Redishoneypot:** 31
- **Honeyaml:** 25
- **Dicompot:** 15
- **ConPot:** 11
- **Miniprint:** 10
- **ElasticPot:** 5
- **Ipphoney:** 4
- **Heralding:** 3

### Top Attacking IPs
- **137.184.79.87:** 1253
- **119.93.102.70:** 920
- **176.65.141.117:** 820
- **118.194.230.211:** 874
- **189.27.133.195:** 750
- **172.86.95.98:** 416
- **112.196.70.142:** 357
- **222.107.251.147:** 238
- **177.10.201.7:** 288
- **190.119.198.81:** 219
- **120.48.35.28:** 237
- **202.152.201.166:** 169
- **202.157.189.21:** 169
- **115.190.9.96:** 167
- **20.203.42.204:** 184
- **103.233.206.154:** 134
- **14.103.112.14:** 132
- **185.76.34.16:** 154
- **103.253.246.206:** 371
- **41.214.61.216:** 99

### Top Targeted Ports/Protocols
- **445:** 2053
- **22:** 953
- **25:** 856
- **5060:** 428
- **80:** 72
- **443:** 89
- **23:** 88
- **5902:** 102
- **5903:** 96
- **TCP/22:** 60
- **8333:** 53
- **TCP/80:** 29
- **6379:** 28
- **5984:** 57

### Most Common CVEs
- **CVE-2021-44228:** 27
- **CVE-2019-11500:** 1

### Commands Attempted by Attackers
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 25
- **lockr -ia .ssh:** 25
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys...:** 25
- **Enter new UNIX password: :** 20
- **Enter new UNIX password:** 20
- **cat /proc/cpuinfo | grep name | wc -l:** 20
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
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 20

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1 / 2402000:** 479
- **ET SCAN NMAP -sS window 1024 / 2009582:** 140
- **ET INFO Reserved Internal IP Traffic / 2002752:** 58
- **ET SCAN Potential SSH Scan / 2001219:** 48
- **ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) / 2010517:** 31
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46 / 2403345:** 24
- **ET SCAN Suspicious inbound to MSSQL port 1433 / 2010935:** 22
- **ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753:** 20
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44 / 2403343:** 19
- **ET CINS Active Threat Intelligence Poor Reputation IP group 51 / 2403350:** 19
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48 / 2403347:** 17
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45 / 2403344:** 19

### Users / Login Attempts (user/password)
- **345gs5662d34/345gs5662d34:** 25
- **root/root123:** 3
- **desperate/desperate:** 3
- **guest/guest:** 3
- **jixian/jixian123:** 3
- **admin/1234:** 5
- **ftp/ftp:** 3
- **beethoven/123:** 3
- **cerulean/123:** 3
- **admin/admin123:** 2
- **irene/irene:** 2

### Files Uploaded/Downloaded
- **wget.sh;**: 8
- **11**: 3
- **fonts.gstatic.com**: 3
- **css?family=Libre+Franklin...**: 3
- **ie8.css?ver=1.0**: 3
- **html5.js?ver=3.7.3**: 3
- **w.sh;**: 2
- **c.sh;**: 2

### HTTP User-Agents
- (No user-agents recorded in this period)

### SSH Clients and Servers
- (No specific client/server versions recorded in this period)

### Top Attacker AS Organizations
- (No AS organization data recorded in this period)

---

## Key Observations and Anomalies

1.  **High-Volume Automated Attacks:** The prevalence of Cowrie, Mailoney, and Sentrypeer traffic, combined with repetitive reconnaissance commands, indicates widespread, automated scanning and brute-force campaigns.
2.  **SSH Key Manipulation:** A common pattern observed in the Cowrie honeypot involves attackers attempting to remove existing SSH configurations and install their own public key (`.ssh/authorized_keys`). This is a clear attempt to establish persistent access.
3.  **Log4j Scans:** The continued presence of `CVE-2021-44228` in the logs shows that attackers are still actively scanning for the Log4j vulnerability, even years after its disclosure.
4.  **Suspicious Script Downloads:** Attackers were observed attempting to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from a remote server (`151.242.30.16`), likely to install malware or cryptominers.
5.  **Blocklist Evasion:** While many attacking IPs were already on established blocklists (DShield, Spamhaus), the sheer volume suggests attackers are either cycling through IPs rapidly or are undeterred by these classifications.

---
