Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T14:01:21Z
**Timeframe:** 2025-10-03T13:20:01Z to 2025-10-03T14:00:01Z
**Log Files:**
- agg_log_20251003T132001Z.json
- agg_log_20251003T134001Z.json
- agg_log_20251003T140001Z.json

**Executive Summary**

This report summarizes 13,905 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also logged by Ciscoasa and Suricata. Attackers were observed attempting to gain unauthorized access, execute commands, and download malicious files. The most frequent attacks originated from IP address 129.212.179.192. The most targeted port was 22 (SSH).

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 8970
*   Ciscoasa: 2348
*   Suricata: 1204
*   Mailoney: 649
*   Sentrypeer: 323
*   Honeytrap: 147
*   Adbhoney: 56
*   Miniprint: 42
*   H0neytr4p: 33
*   Tanner: 30
*   Dionaea: 26
*   ConPot: 25
*   Dicompot: 21
*   Honeyaml: 13
*   Redishoneypot: 9
*   ElasticPot: 5
*   Heralding: 3
*   Ipphoney: 1

***Top Attacking IPs***

*   129.212.179.192: 2145
*   210.236.249.126: 1244
*   159.223.80.225: 1153
*   217.154.99.56: 953
*   176.65.141.117: 630
*   14.225.220.78: 560
*   185.156.73.166: 356
*   92.63.197.59: 308
*   185.255.91.226: 218
*   180.108.64.6: 187

***Top Targeted Ports/Protocols***

*   22: 1587
*   25: 649
*   5060: 323
*   23: 156
*   TCP/80: 45
*   TCP/22: 55
*   9100: 42

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012: 11
*   CVE-2021-3449 CVE-2021-3449: 5
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
*   CVE-2019-11500 CVE-2019-11500: 4
*   CVE-1999-0517: 3

***Commands Attempted by Attackers***

*   uname -a: 13
*   whoami: 12
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 11
*   lockr -ia .ssh: 11
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 11
*   cat /proc/cpuinfo | grep name | wc -l: 11
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 11
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 11
*   ls -lh $(which ls): 11
*   which ls: 11

***Signatures Triggered***

*   ET DROP Dshield Block Listed Source group 1: 398
*   2402000: 398
*   ET SCAN NMAP -sS window 1024: 180
*   2009582: 180
*   ET INFO Reserved Internal IP Traffic: 58
*   2002752: 58
*   ET SCAN Potential SSH Scan: 42
*   2001219: 42
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 33
*   2400031: 33

***Users / Login Attempts***

*   User-Agent: Go-http-client/1.1/Connection: close: 15
*   test/zhbjETuyMffoL8F: 9
*   345gs5662d34/345gs5662d34: 9
*   root/nPSpP4PBW0: 5
*   root/abc123: 3
*   root/1qaz@wsx: 3
*   apache/apache: 3
*   nginx/nginx123: 3

***Files Uploaded/Downloaded***

*   wget.sh;: 12
*   w.sh;: 3
*   c.sh;: 3
*   arm.urbotnetisass;: 1
*   arm.urbotnetisass: 1
*   arm5.urbotnetisass;: 1
*   arm5.urbotnetisass: 1

***HTTP User-Agents***

*   No HTTP User-Agents were logged in this period.

***SSH Clients***

*   No SSH clients were logged in this period.

***SSH Servers***

*   No SSH servers were logged in this period.

***Top Attacker AS Organizations***

*   No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

*   A high volume of command execution attempts was observed, primarily focused on system enumeration and establishing persistent access via SSH authorized_keys.
*   Multiple attempts to download and execute shell scripts (e.g., `wget.sh`, `w.sh`, `c.sh`) from remote servers were recorded, indicating attempts to install malware or establish botnet clients.
*   The `Cowrie` honeypot captured the vast majority of malicious activity, suggesting a high prevalence of SSH-based attacks.
*   The presence of CVEs such as CVE-2002-0013 and CVE-2002-0012 indicates that attackers are still attempting to exploit legacy vulnerabilities.