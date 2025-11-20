Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T22:01:31Z
**Timeframe:** 2025-10-05T21:20:01Z to 2025-10-05T22:00:01Z

**Files Used:**
- agg_log_20251005T212001Z.json
- agg_log_20251005T214001Z.json
- agg_log_20251005T220001Z.json

### Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 12,487 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and email (Mailoney). A significant portion of the attacks originated from a small number of IP addresses, with a notable concentration of attacks from `134.199.199.208`. Attackers were observed attempting to gain access via brute-force login attempts and execute commands to download and run malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 6726
*   Mailoney: 1690
*   Ciscoasa: 1319
*   Suricata: 1237
*   Honeytrap: 761
*   Sentrypeer: 541
*   H0neytr4p: 38
*   Tanner: 36
*   ConPot: 31
*   Adbhoney: 30
*   Dionaea: 29
*   Honeyaml: 20
*   Redishoneypot: 15
*   Ipphoney: 9
*   ElasticPot: 4
*   Wordpot: 1

**Top Attacking IPs:**
*   134.199.199.208
*   161.132.37.66
*   102.117.233.77
*   86.54.42.238
*   176.65.141.117
*   134.122.77.28
*   172.86.95.98
*   36.138.134.121
*   61.80.179.118
*   183.131.109.155

**Top Targeted Ports/Protocols:**
*   25
*   22
*   5060
*   TCP/443
*   TCP/22
*   80
*   23
*   TCP/5432

**Most Common CVEs:**
*   CVE-2021-3449

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `uname -a`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `Enter new UNIX password:`
*   `uname`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET SCAN Possible SSL Brute Force attack or Site Crawl
*   ET SCAN Potential SSH Scan
*   ET INFO Reserved Internal IP Traffic
*   ET CINS Active Threat Intelligence Poor Reputation IP group 50
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   root/12345
*   postgres/123
*   ingrid/ingrid
*   enzyme/123

**Files Uploaded/Downloaded:**
*   wget.sh;
*   w.sh;
*   c.sh;

**HTTP User-Agents:**
*   (No user agents recorded)

**SSH Clients:**
*   (No SSH clients recorded)

**SSH Servers:**
*   (No SSH servers recorded)

**Top Attacker AS Organizations:**
*   (No AS organizations recorded)

### Key Observations and Anomalies
- A significant number of attacks are focused on SSH and email services, indicating automated brute-force campaigns.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a common attempt to install a persistent SSH key for backdoor access.
- Attackers are using `wget` and `curl` to download and execute malicious scripts, as seen in the "Files Uploaded/Downloaded" and "Commands Attempted" sections.
- The CVE-2021-3449, related to OpenSSL, was triggered, suggesting some attackers are targeting this vulnerability.
- The high number of triggers for the "ET DROP Dshield Block Listed Source group 1" signature indicates that many of the attacking IPs are already known malicious actors.
