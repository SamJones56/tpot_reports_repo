## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T20:01:43Z
**Timeframe:** 2025-10-05T19:20:01Z to 2025-10-05T20:00:01Z
**Files Analyzed:**
- `agg_log_20251005T192001Z.json`
- `agg_log_20251005T194001Z.json`
- `agg_log_20251005T200001Z.json`

### Executive Summary

This report summarizes 10,997 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attacks. A significant number of events were also logged by Suricata, highlighting network-level scanning and exploit attempts. The most frequent attacker IP was 176.65.141.117, and the most targeted port was port 25 (SMTP), closely followed by port 22 (SSH). Attackers attempted to run various reconnaissance commands and modify SSH authorized_keys. Several CVEs were targeted, with a focus on remote code execution vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 6015
- **Suricata:** 1482
- **Ciscoasa:** 1261
- **Mailoney:** 856
- **Honeytrap:** 694
- **Sentrypeer:** 409
- **H0neytr4p:** 78
- **Tanner:** 69
- **Dionaea:** 37
- **Adbhoney:** 25
- **Redishoneypot:** 18
- **Miniprint:** 17
- **Honeyaml:** 16
- **ConPot:** 14
- **Dicompot:** 3
- **ElasticPot:** 2
- **Ipphoney:** 1

**Top Attacking IPs:**
- 176.65.141.117
- 196.251.80.29
- 182.18.139.237
- 162.241.127.152
- 27.79.44.136
- 172.86.95.98
- 177.75.160.94
- 35.237.94.18
- 104.168.101.178
- 93.193.244.31

**Top Targeted Ports/Protocols:**
- 25
- 22
- 5060
- TCP/5900
- 80
- 443
- TCP/22
- TCP/1433
- 6379
- 9100

**Most Common CVEs:**
- CVE-2024-4577
- CVE-2002-0953
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2021-41773
- CVE-2021-42013
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2005-4050
- CVE-2021-3449
- CVE-2021-35394

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAA... rckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 43/44/48
- ET SCAN MS Terminal Server Traffic on Non-standard Port

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- pencil/pencil@123
- andy/123
- ersatz/ersatz
- simple/123
- japan/japan@123
- fred/3245gs5662d34
- asd/asd123
- arthur/123
- romano/romano123
- golfer/golfer
- camille/camille

**Files Uploaded/Downloaded:**
- sh
- wget.sh;
- w.sh;
- c.sh;
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- rondo.kqa.sh|sh&echo
- ns#
- sign_in

**HTTP User-Agents:**
- *None Recorded*

**SSH Clients:**
- *None Recorded*

**SSH Servers:**
- *None Recorded*

**Top Attacker AS Organizations:**
- *None Recorded*

### Key Observations and Anomalies

- **High Volume of Cowrie Events:** The dominance of Cowrie honeypot events suggests a widespread, automated campaign targeting default or weak SSH/Telnet credentials.
- **SSH Key Manipulation:** The repeated attempts to delete the `.ssh` directory and add a specific public key to `authorized_keys` is a clear indicator of attackers trying to establish persistent access.
- **Reconnaissance Commands:** Attackers are consistently running system reconnaissance commands like `uname`, `lscpu`, `free`, and `df` to understand the environment they have compromised.
- **Download and Execute:** The presence of `wget` and `curl` in command logs, along with shell script filenames in the file download list, points to attempts to fetch and execute secondary payloads.
- **SMTP Traffic:** The high number of connections to port 25 via the Mailoney honeypot suggests potential spam relay or reconnaissance activities targeting email servers.
