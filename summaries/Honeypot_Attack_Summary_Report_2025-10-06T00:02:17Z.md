Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T00:01:42Z
**Timeframe:** 2025-10-05T23:20:01Z to 2025-10-06T00:00:01Z
**Files Used:**
- agg_log_20251005T232001Z.json
- agg_log_20251005T234001Z.json
- agg_log_20251006T000001Z.json

### Executive Summary

This report summarizes 12,410 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of SMTP, SIP, and web-based attacks were also observed. Attackers were observed attempting to gain unauthorized access, execute remote commands, and exploit various vulnerabilities, including older CVEs.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 6,473
- **Mailoney:** 1,645
- **Suricata:** 1,436
- **Ciscoasa:** 1,376
- **Honeytrap:** 701
- **Sentrypeer:** 474
- **Adbhoney:** 76
- **H0neytr4p:** 61
- **Tanner:** 60
- **ElasticPot:** 40
- **Honeyaml:** 23
- **Dionaea:** 20
- **ConPot:** 15
- **Dicompot:** 8
- **Ipphoney:** 2

**Top Attacking IPs:**
- 176.65.141.117
- 86.54.42.238
- 172.86.95.98
- 187.51.208.158
- 171.80.11.236
- 194.190.153.226
- 134.122.77.28
- 103.236.194.32
- 103.176.78.176
- 60.199.224.2

**Top Targeted Ports/Protocols:**
- 25 (SMTP)
- 22 (SSH)
- 5060 (SIP)
- TCP/443 (HTTPS)
- TCP/80 (HTTP)
- 80 (HTTP)
- 9200 (Elasticsearch)
- 443 (HTTPS)
- 23 (Telnet)
- 5555 (ADB)

**Most Common CVEs:**
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2019-11500
- CVE-2023-26801
- CVE-2021-3449
- CVE-2019-16920
- CVE-2024-12856, CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-47565
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051, CVE-2024-33112, CVE-2022-37056, CVE-2019-10891
- CVE-2024-3721
- CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
- CVE-2021-42013

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Possible SSL Brute Force attack or Site Crawl
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET DROP Spamhaus DROP Listed Traffic Inbound
- GPL INFO SOCKS Proxy attempt

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- ingres/ingres
- brenda/brenda@123
- beauty/beauty123
- discovery/discovery@123
- solv/123
- wilma/123
- fun/fun@123
- Sujan/masGdokM1

**Files Uploaded/Downloaded:**
- `wget.sh`
- `w.sh`
- `c.sh`
- `rondo.dgx.sh`
- `apply.cgi`
- `cfg_system_time.htm`

**HTTP User-Agents:**
- No user-agent data was recorded during this period.

**SSH Clients and Servers:**
- No specific SSH client or server software versions were identified in the logs.

**Top Attacker AS Organizations:**
- No AS organization data was available in the logs.

### Key Observations and Anomalies

-   **High Volume of Cowrie Attacks:** The dominance of the Cowrie honeypot suggests a sustained, automated campaign targeting SSH and Telnet services. The commands executed indicate attempts to establish persistent access by adding SSH keys to `authorized_keys`.
-   **Targeting of Mail Services:** The Mailoney honeypot captured a significant number of events, indicating that attackers are actively targeting SMTP servers, likely for spamming or phishing campaigns.
-   **Exploitation of Old and New Vulnerabilities:** The CVEs detected range from very old (e.g., CVE-1999-0517) to more recent ones, suggesting that attackers are using a broad set of exploits to target a wide range of systems.
-   **Automated Scanning and Probing:** The Suricata logs show a high volume of scanning activity, particularly from Nmap, which is a common reconnaissance tool. This indicates that attackers are actively searching for vulnerable systems.
-   **Lack of Sophistication:** Many of the observed attacks appear to be automated and unsophisticated, relying on common credentials and publicly known exploits.

This report highlights the persistent and varied nature of automated threats on the internet. The data suggests that even basic security measures, such as strong passwords and timely patching, can mitigate a significant portion of these attacks. Continued monitoring is recommended to identify any changes in attacker tactics and techniques.
