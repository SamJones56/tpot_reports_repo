### Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T21:01:33Z
**Timeframe:** 2025-10-04T20:20:01Z to 2025-10-04T21:00:01Z
**Files Analyzed:**
- `agg_log_20251004T202001Z.json`
- `agg_log_20251004T204001Z.json`
- `agg_log_20251004T210001Z.json`

### Executive Summary

This report summarizes 11,436 attacks recorded across a distributed honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant portion of the attacks originated from a small number of IP addresses, with a notable concentration of activity from `143.198.96.196` and `82.165.165.172`. The most frequently targeted ports were 25 (SMTP), 22 (SSH), and 5060 (SIP). Analysis of command execution reveals a consistent pattern of attackers attempting to download and execute malicious scripts, as well as efforts to enumerate system information and alter system configurations.

### Detailed Analysis

**Attacks by Honeypot:**
* **Cowrie:** 6256
* **Mailoney:** 1869
* **Ciscoasa:** 1554
* **Suricata:** 906
* **Sentrypeer:** 442
* **Honeytrap:** 152
* **H0neytr4p:** 87
* **Tanner:** 49
* **Dionaea:** 41
* **ElasticPot:** 24
* **Adbhoney:** 20
* **Redishoneypot:** 18
* **Honeyaml:** 11
* **Ipphoney:** 5
* **ConPot:** 2

**Top Attacking IPs:**
* **143.198.96.196:** 1247
* **82.165.165.172:** 1226
* **176.65.141.117:** 986
* **172.86.95.98:** 360
* **38.187.27.30:** 292
* **203.161.56.112:** 252
* **193.32.162.157:** 247
* **103.181.143.216:** 151
* **180.76.250.117:** 182
* **38.57.234.23:** 144

**Top Targeted Ports/Protocols:**
* **25:** 1869
* **22:** 1057
* **5060:** 442
* **443:** 87
* **80:** 55
* **9200:** 24
* **TCP/22:** 39
* **TCP/80:** 38
* **445:** 22
* **TCP/8080:** 16

**Most Common CVEs:**
* **CVE-2019-11500:** 6
* **CVE-2021-3449:** 5
* **CVE-2002-0013, CVE-2002-0012:** 5
* **CVE-2005-4050:** 1
* **CVE-1999-0183:** 1

**Commands Attempted by Attackers:**
* A variety of shell commands were executed, with a focus on reconnaissance, privilege escalation, and payload delivery. The most common commands include `uname -a`, `whoami`, `cat /proc/cpuinfo`, and attempts to modify the `.ssh/authorized_keys` file to establish persistent access. Additionally, there were numerous attempts to download and execute shell scripts from remote servers, such as `w.sh` and `c.sh`.

**Signatures Triggered:**
* **ET DROP Dshield Block Listed Source group 1:** 273
* **ET SCAN NMAP -sS window 1024:** 107
* **ET INFO Reserved Internal IP Traffic:** 43
* **ET SCAN Potential SSH Scan:** 29
* **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 16

**Users / Login Attempts:**
* A wide range of usernames and passwords were used in brute-force attempts. Common usernames included `root`, `admin`, `user`, and service-specific names like `tomcat` and `oracle`. Passwords ranged from simple, default credentials to more complex combinations.

**Files Uploaded/Downloaded:**
* The primary files downloaded by attackers were shell scripts, including `wget.sh`, `w.sh`, and `c.sh`. These scripts are likely used to automate further stages of the attack, such as installing malware or launching DDoS attacks.

**HTTP User-Agents:**
* No HTTP User-Agents were recorded in the logs.

**SSH Clients and Servers:**
* No specific SSH client or server versions were recorded in the logs.

**Top Attacker AS Organizations:**
* No AS organization data was available in the logs.

### Key Observations and Anomalies

* **High-Volume, Coordinated Attacks:** The concentration of attacks from a few IP addresses suggests either a small number of highly active attackers or a coordinated campaign from a botnet.
* **Repetitive Command Execution:** The frequent use of identical command sequences across different sessions and source IPs indicates the use of automated attack scripts.
* **Focus on SSH and SMTP:** The prevalence of attacks on ports 22 and 25 highlights the ongoing threat to these commonly exposed services.
* **Script-Based Payload Delivery:** The consistent attempts to download and execute shell scripts from external sources is a clear indicator of attackers' intent to compromise the system and use it for malicious purposes.

This report provides a snapshot of the threat landscape as observed by the honeypot network. Continuous monitoring is recommended to track evolving attack patterns and identify emerging threats.