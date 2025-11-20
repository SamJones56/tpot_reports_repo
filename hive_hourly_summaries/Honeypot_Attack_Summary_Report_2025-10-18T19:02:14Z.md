# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T19:01:34Z

**Timeframe:** This report is a consolidation of the last 3 log files provided.

**Files used to generate the report:**
- `agg_log_20251018T182001Z.json`
- `agg_log_20251018T184001Z.json`
- `agg_log_20251018T190001Z.json`

## Executive Summary

This report summarizes a total of 8,381 attacks recorded across three recent log files. The majority of these attacks were captured by the `Cowrie` honeypot, indicating a high volume of SSH and telnet-based threats. The most targeted service was SSH on port 22. A variety of CVEs were targeted, with CVE-2024-3721 being the most frequently observed. Attackers attempted numerous commands, primarily focused on system reconnaissance and establishing persistent access by adding SSH keys to `.ssh/authorized_keys`.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4746
- **Honeytrap:** 1431
- **Ciscoasa:** 1192
- **Suricata:** 738
- **Sentrypeer:** 156
- **H0neytr4p:** 30
- **Dionaea:** 20
- **Dicompot:** 17
- **ConPot:** 12
- **Mailoney:** 12
- **Tanner:** 10
- **Adbhoney:** 9
- **Ipphoney:** 5
- **ElasticPot:** 2
- **Honeyaml:** 1

### Top Attacking IPs
- 176.9.111.156: 639
- 72.146.232.13: 612
- 218.161.90.126: 433
- 154.83.16.198: 365
- 104.223.122.114: 297
- 167.172.189.176: 297
- 103.86.180.10: 223
- 85.133.206.110: 206
- 152.32.253.152: 198
- 139.59.188.13: 198
- 103.84.236.242: 197
- 152.32.191.75: 135
- 107.170.36.5: 152
- 68.183.149.135: 111
- 179.104.68.87: 94
- 85.208.253.156: 90
- 34.58.124.191: 89
- 141.52.36.57: 70
- 185.243.5.152: 60
- 185.243.5.137: 50

### Top Targeted Ports/Protocols
- 22: 842
- TCP/5900: 194
- 5060: 156
- 8333: 107
- 3388: 100
- 5904: 76
- 5905: 76
- 5901: 41
- 5902: 40
- 5903: 39
- 8088: 27
- 23: 27
- 443: 21
- 8729: 17
- 2077: 16
- 10001: 12
- 25: 9
- TCP/80: 7

### Most Common CVEs
- CVE-2024-3721: 4
- CVE-2021-3449: 3
- CVE-2019-11500: 2
- CVE-2023-26801: 1
- CVE-2002-0013, CVE-2002-0012: 1

### Commands Attempted by Attackers
- `uname -a`: 24
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 23
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 23
- `ls -lh $(which ls)`: 23
- `which ls`: 23
- `crontab -l`: 23
- `w`: 23
- `uname -m`: 23
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 23
- `top`: 23
- `uname`: 23
- `whoami`: 23
- `lscpu | grep Model`: 23
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 23
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 23
- `lockr -ia .ssh`: 23
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 23
- `cat /proc/cpuinfo | grep name | wc -l`: 22
- `Enter new UNIX password: `: 11
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 9

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 147
- 2402000: 147
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 110
- 2400041: 110
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 87
- 2400040: 87
- ET SCAN NMAP -sS window 1024: 80
- 2009582: 80
- ET INFO Reserved Internal IP Traffic: 41
- 2002752: 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 14
- 2403347: 14
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 13
- 2023753: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 9
- 2403344: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 8
- 2403342: 8

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 21
- root/3245gs5662d34: 10
- ftpuser/ftppassword: 7
- root/123@Robert: 6
- keith/123: 4
- mir/mir: 3
- mohamad/mohamad: 3
- root/Frank@123: 3
- peiyuhui/123: 3
- asep/asep123: 2
- root/fuckfuck: 2
- root/123@abc: 2
- boy/123: 2
- dev/dev@2025: 2
- root/Zc123456: 2
- root/123456787: 2
- root/321qazxadminco: 2
- admin/admin2009: 2
- kafka/kafka123: 2
- developer/P@ssw0rd: 2

### Files Uploaded/Downloaded
- wget.sh;: 4
- tajma.mpsl;: 3
- 129.212.146.61:80: 3
- diag_tracert_admin_en.asp: 3
- 129.212.146.61: 2
- system.html: 2
- w.sh;: 1
- c.sh;: 1

### HTTP User-Agents
- Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

### SSH Clients and Servers
- No SSH clients or servers were recorded in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in the logs.

## Key Observations and Anomalies
- **High Volume of Cowrie Attacks:** The consistent targeting of the Cowrie honeypot highlights the unabated threat of automated brute-force attacks against SSH and telnet services.
- **Reconnaissance and Persistence:** The most frequently attempted commands are centered around system reconnaissance (`uname`, `lscpu`, `whoami`, etc.) and establishing persistence by adding a public SSH key to the `.ssh/authorized_keys` file. This is a common tactic for maintaining access to a compromised system.
- **Targeted CVEs:** The logs show a mix of older and more recent CVEs being exploited, suggesting that attackers are using a broad range of exploits to maximize their chances of success.
- **Malware Download Attempts:** The file download attempts, particularly of shell scripts (`wget.sh`, `w.sh`, `c.sh`), indicate clear attempts to download and execute malware on the honeypot. These scripts are likely designed to further compromise the system or use it as part of a botnet.
- **Varied Credentials:** The list of attempted credentials shows a mix of default usernames and passwords, weak and common passwords, and more complex variations. This reflects the varied approaches of attackers, from simple brute-force lists to more targeted attempts.
