Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T23:01:38Z
**Timeframe:** 2025-10-09T22:20:01Z to 2025-10-09T23:00:01Z
**Files Used:**
* `agg_log_20251009T222001Z.json`
* `agg_log_20251009T224001Z.json`
* `agg_log_20251009T230001Z.json`

### Executive Summary

This report summarizes a total of 21,947 events recorded across three honeypot log files. The majority of these events were captured by the Cowrie and Honeytrap honeypots. A significant portion of the attacks originated from the IP address 159.65.237.176. The most frequently targeted ports were 22 (SSH) and 5060 (SIP). Analysis of the command and control tactics reveals a consistent pattern of attempts to add a malicious SSH key to the `authorized_keys` file for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 10,037
* Honeytrap: 6,521
* Suricata: 2,292
* Ciscoasa: 1,665
* Sentrypeer: 884
* Tanner: 111
* Dionaea: 100
* Mailoney: 111
* Miniprint: 53
* ConPot: 44
* H0neytr4p: 47
* Redishoneypot: 24
* Honeyaml: 14
* Adbhoney: 22
* ElasticPot: 7
* Dicompot: 3
* ssh-rsa: 4
* Ipphoney: 5
* Heralding: 3

**Top Attacking IPs:**
* 159.65.237.176: 3701
* 167.250.224.25: 1451
* 216.9.225.39: 1049
* 129.212.185.61: 999
* 101.126.135.131: 598
* 178.128.152.40: 312
* 175.12.108.55: 321
* 85.208.253.229: 353
* 210.79.190.46: 238
* 88.210.63.16: 213

**Top Targeted Ports/Protocols:**
* 22: 1446
* 5060: 884
* UDP/5060: 527
* 5903: 204
* 80: 118
* 25: 118
* 5901: 96
* 5908: 79
* 5909: 81
* 8333: 80
* 3388: 55
* 9100: 53

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012: 6
* CVE-2021-3449 CVE-2021-3449: 3
* CVE-2019-11500 CVE-2019-11500: 3
* CVE-2021-44228 CVE-2021-44228: 2
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
* CVE-2005-4050: 1

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
* `cat /proc/cpuinfo | grep name | wc -l`
* `Enter new UNIX password:`
* `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `ls -lh $(which ls)`
* `which ls`
* `crontab -l`
* `w`
* `uname -m`
* `cat /proc/cpuinfo | grep model | grep name | wc -l`
* `top`
* `uname`
* `uname -a`
* `whoami`
* `lscpu | grep Model`
* `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

**Signatures Triggered:**
* ET SCAN Sipsak SIP scan / 2008598
* ET DROP Dshield Block Listed Source group 1 / 2402000
* ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753
* ET SCAN NMAP -sS window 1024 / 2009582
* ET HUNTING RDP Authentication Bypass Attempt / 2034857
* ET INFO Reserved Internal IP Traffic / 2002752
* ET CINS Active Threat Intelligence Poor Reputation IP group 42 / 2403341
* ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) / 2010517
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28 / 2400027
* ET CINS Active Threat Intelligence Poor Reputation IP group 43 / 2403342

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* supervisor/qwerty123
* operator/123654
* vpn/vpn123123
* kafka/kafka!
* support/passw0rd
* debian/debian!
* operator/operator00
* default/123abc
* root/root13
* root/root999
* root/issab3l@
* root/issab3l@123
* root/issab3l@1234
* ts3server/3245gs5662d34

**Files Uploaded/Downloaded:**
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
* ie8.css?ver=1.0
* html5.js?ver=3.7.3
* wget.sh;
* w.sh;
* c.sh;

**HTTP User-Agents:**
* No HTTP user agents were logged in the provided data.

**SSH Clients and Servers:**
* No specific SSH client or server versions were logged in the provided data.

**Top Attacker AS Organizations:**
* No attacker AS organizations were logged in the provided data.

### Key Observations and Anomalies

*   **Consistent TTPs:** The repeated use of the command to add an SSH key to `authorized_keys` across multiple attacking IPs suggests a coordinated campaign or the use of a common attack toolkit.
*   **SIP Scanning:** A large number of events were related to SIP scanning, indicating a focus on VoIP infrastructure. The "ET SCAN Sipsak SIP scan" signature was the most frequently triggered.
*   **High Volume from Single IP:** The IP address 159.65.237.176 was responsible for a disproportionately high number of events, primarily targeting the Cowrie honeypot.
*   **RDP and VNC Scans:** There is evidence of scanning for remote access services like RDP and VNC on non-standard ports.
