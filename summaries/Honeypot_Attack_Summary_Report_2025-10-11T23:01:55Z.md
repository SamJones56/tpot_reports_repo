Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T23:01:25Z
**Timeframe of aformentioned files:** 2025-10-11T22:20:00Z to 2025-10-11T23:00:00Z
**Files Used:** `agg_log_20251011T222001Z.json`, `agg_log_20251011T224001Z.json`, `agg_log_20251011T230001Z.json`

### Executive Summary
This report summarizes 21,326 events collected from the honeypot network. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH-based threats. The most prominent attacker IP was `185.144.27.63`. Attackers were observed attempting to gain persistent access by adding their SSH keys to the system. A number of CVEs were targeted, and network traffic triggered multiple intrusion detection signatures, primarily related to blocklisted IPs and network scanning.

### Detailed Analysis

**Attacks by Honeypot:**
*   **Cowrie:** 14,048
*   **Honeytrap:** 3,402
*   **Ciscoasa:** 1,830
*   **Suricata:** 1,500
*   **Mailoney:** 153
*   **Sentrypeer:** 141
*   **H0neytr4p:** 77
*   **Dionaea:** 61
*   **Adbhoney:** 20
*   **Tanner:** 25
*   **Dicompot:** 18
*   **Redishoneypot:** 24
*   **ConPot:** 10
*   **Honeyaml:** 13
*   **ElasticPot:** 3
*   **Miniprint:** 1

**Top Attacking IPs:**
*   `185.144.27.63`: 7276
*   `47.100.12.103`: 1284
*   `161.132.37.66`: 1067
*   `196.251.84.181`: 510
*   `45.128.199.212`: 266
*   `207.166.172.99`: 357
*   `178.17.53.66`: 223
*   `105.247.69.196`: 332
*   `118.194.230.250`: 288
*   `51.68.137.61`: 214

**Top Targeted Ports/Protocols:**
*   **22:** 2608
*   **5903:** 189
*   **5060:** 141
*   **25:** 159
*   **443:** 62
*   **5038:** 266
*   **8333:** 90
*   **TCP/22:** 78
*   **5901:** 86
*   **5908:** 82
*   **5909:** 83

**Most Common CVEs:**
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-2016-20016
*   CVE-1999-0517

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `uname -a`
*   `whoami`
*   `crontab -l`
*   `w`
*   `top`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN Potential SSH Scan
*   ET CINS Active Threat Intelligence Poor Reputation IP (various groups)
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 29

**Users / Login Attempts:**
*   `sa/00000000`
*   `345gs5662d34/345gs5662d34`
*   `admin/lamer2398`
*   `support/P@ssword`
*   `sa/111`
*   `default/pass`
*   `admin1234/admin1234`
*   `magento/magento`
*   `root/sKYROOM_1399`
*   `root/Trustno12015`

**Files Uploaded/Downloaded:**
*   `arm.urbotnetisass`
*   `arm5.urbotnetisass`
*   `arm6.urbotnetisass`
*   `arm7.urbotnetisass`
*   `x86_32.urbotnetisass`
*   `mips.urbotnetisass`
*   `mipsel.urbotnetisass`
*   `fonts.gstatic.com`
*   `html5.js`
*   `ie8.css`

**HTTP User-Agents:**
*   No significant user agents were recorded in this period.

**SSH Clients and Servers:**
*   No specific SSH client or server versions were recorded.

**Top Attacker AS Organizations:**
*   No AS organization data was recorded in this period.

### Key Observations and Anomalies
*   **Persistent Attacker:** The IP address `185.144.27.63` was consistently aggressive across all three log files, focusing on SSH attacks.
*   **Malware Delivery:** A recurring command sequence was identified attempting to download and execute several `urbotnetisass` files from IP `94.154.35.154` on Android-based systems (`/data/local/tmp/`). This suggests a coordinated campaign to build a botnet.
*   **SSH Key Injection:** The most common malicious command involved attempts to remove SSH folder immutability (`chattr -ia`) and inject a public SSH key into `authorized_keys`. This is a clear indicator of attackers trying to establish persistent, passwordless access to compromised systems.
*   **Reconnaissance:** Basic system reconnaissance commands (`uname`, `whoami`, `lscpu`, `df`) were frequently executed, likely to identify the environment and tailor further attacks.
