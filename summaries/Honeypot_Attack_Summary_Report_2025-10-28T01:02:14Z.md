Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T01:01:36Z
**Timeframe:** 2025-10-28T00:20:02Z to 2025-10-28T01:00:01Z
**Files Used:**
- agg_log_20251028T002002Z.json
- agg_log_20251028T004001Z.json
- agg_log_20251028T010001Z.json

### Executive Summary
This report summarizes 16,597 attacks recorded by honeypots over the last hour. The majority of attacks were captured by the Cowrie honeypot, with a total of 8,193 events. The most frequent attacker IP was 144.172.108.231 with 1,087 attempts. Port 5060 (SIP) was the most targeted port, and a variety of CVEs were exploited, with CVE-2021-44228 (Log4j) being the most common. A significant number of shell commands were executed, indicating attempts to establish control over compromised systems.

### Detailed Analysis

**Attacks by Honeypot:**
*   **Cowrie:** 8193
*   **Honeytrap:** 2693
*   **Ciscoasa:** 1950
*   **Suricata:** 1602
*   **Sentrypeer:** 1536
*   **Dionaea:** 353
*   **Tanner:** 97
*   **Mailoney:** 73
*   **Adbhoney:** 21
*   **ElasticPot:** 14
*   **Honeyaml:** 17
*   **Redishoneypot:** 20
*   **Dicompot:** 7
*   **ConPot:** 8
*   **Heralding:** 3
*   **H0neytr4p:** 9
*   **Wordpot:** 1

**Top Attacking IPs:**
*   **144.172.108.231:** 1087
*   **43.156.66.219:** 394
*   **162.214.211.246:** 404
*   **118.195.182.56:** 409
*   **42.200.78.78:** 356
*   **172.190.89.127:** 424
*   **69.63.77.146:** 224
*   **58.82.128.4:** 216
*   **163.172.99.31:** 230
*   **189.194.140.170:** 336
*   **206.217.136.36:** 261
*   **188.121.118.142:** 247

**Top Targeted Ports/Protocols:**
*   **5060:** 1536
*   **22:** 867
*   **445:** 311
*   **5901:** 236
*   **80:** 96
*   **5903:** 115
*   **5905:** 80
*   **5904:** 79
*   **25:** 73
*   **TCP/22:** 66

**Most Common CVEs:**
*   **CVE-2021-44228:** 5
*   **CVE-2002-0013, CVE-2002-0012:** 4
*   **CVE-2002-0013, CVE-2002-0012, CVE-1999-0517:** 3
*   **CVE-2025-57819:** 3
*   **CVE-2014-2321:** 3
*   **CVE-2025-22457:** 1
*   **CVE-2019-11500:** 2
*   **CVE-1999-0183:** 1
*   **CVE-2021-35394:** 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 70
*   `lockr -ia .ssh`: 70
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 69
*   `cat /proc/cpuinfo | grep name | wc -l`: 69
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 69
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 69
*   `ls -lh $(which ls)`: 69
*   `which ls`: 69
*   `crontab -l`: 69
*   `w`: 69
*   `uname -m`: 69
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 68
*   `top`: 68
*   `uname`: 68
*   `uname -a`: 68
*   `whoami`: 68
*   `lscpu | grep Model`: 68
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 68
*   `Enter new UNIX password: `: 42
*   `Enter new UNIX password:`: 42

**Signatures Triggered:**
*   **ET DROP Dshield Block Listed Source group 1:** 360
*   **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 238
*   **ET SCAN NMAP -sS window 1024:** 176
*   **ET HUNTING RDP Authentication Bypass Attempt:** 90
*   **ET INFO Reserved Internal IP Traffic:** 56
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 47:** 33

**Users / Login Attempts:**
*   **345gs5662d34/345gs5662d34:** 66
*   **root/3245gs5662d34:** 26
*   **root/Jorge_1721:** 4
*   **root/JOSE.ANGEL:** 4
*   **root/paris2024:** 3
*   **user/beautifu:** 3
*   **user/baseball1:** 3

**Files Uploaded/Downloaded:**
*   `wget.sh;`: 8
*   `?format=json`: 2
*   `arm.urbotnetisass;`: 2
*   `arm5.urbotnetisass;`: 2
*   `arm6.urbotnetisass;`: 2
*   `arm7.urbotnetisass;`: 2
*   `x86_32.urbotnetisass;`: 2
*   `mips.urbotnetisass;`: 2
*   `mipsel.urbotnetisass;`: 2
*   `w.sh;`: 2
*   `c.sh;`: 2
*   `arm.uhavenobotsxd;`: 1
*   `arm.uhavenobotsxd`: 1
*   `arm5.uhavenobotsxd;`: 1
*   `arm5.uhavenobotsxd`: 1
*   `arm6.uhavenobotsxd;`: 1
*   `arm6.uhavenobotsxd`: 1
*   `arm7.uhavenobotsxd;`: 1
*   `arm7.uhavenobotsxd`: 1
*   `x86_32.uhavenobotsxd;`: 1

**HTTP User-Agents:**
*   *No user agents reported in this period.*

**SSH Clients:**
*   *No SSH clients reported in this period.*

**SSH Servers:**
*   *No SSH servers reported in this period.*

**Top Attacker AS Organizations:**
*   *No AS organizations reported in this period.*

### Key Observations and Anomalies
- The high number of commands related to modifying the `.ssh` directory suggests a coordinated campaign to maintain persistent access to compromised systems using SSH keys.
- The `wget` and `curl` commands observed indicate attempts to download and execute malicious scripts from external sources, a common tactic for deploying malware.
- The presence of scans for MS Terminal Server on non-standard ports, along with RDP authentication bypass attempts, highlights a focus on exploiting remote access services.
- A wide range of credentials were used in brute-force attacks, with a mix of common and complex passwords, indicating diverse attacker methodologies.
- The variety of honeypots that recorded attacks demonstrates a multi-faceted threat landscape, with attackers targeting a broad range of services and protocols.
