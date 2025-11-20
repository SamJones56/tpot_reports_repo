Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T16:01:43Z
**Timeframe:** 2025-10-09T15:20:01Z to 2025-10-09T16:00:02Z
**Files Used:**
- agg_log_20251009T152001Z.json
- agg_log_20251009T154002Z.json
- agg_log_20251009T160002Z.json

### Executive Summary
This report summarizes 17,622 malicious events recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. The most prominent attacking IP address was 167.250.224.25. A significant number of attacks targeted port 25 (SMTP), followed closely by port 22 (SSH) and port 5060 (SIP). Attackers were observed attempting to exploit several vulnerabilities, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 7,243
- **Honeytrap:** 2,705
- **Suricata:** 2,077
- **Mailoney:** 1,683
- **Ciscoasa:** 1,640
- **Sentrypeer:** 1,138
- **Dionaea:** 832
- **Tanner:** 167
- **Redishoneypot:** 42
- **Adbhoney:** 17
- **H0neytr4p:** 22
- **Honeyaml:** 16
- **ConPot:** 18
- **Ipphoney:** 14
- **Dicompot:** 6
- **ElasticPot:** 2

**Top Attacking IPs:**
- **167.250.224.25:** 2,331
- **86.54.42.238:** 1,641
- **47.243.13.66:** 1,164
- **80.94.95.238:** 873
- **78.31.71.38:** 788
- **1.53.36.195:** 744
- **8.219.56.235:** 628
- **72.240.125.133:** 189
- **190.108.76.143:** 189
- **88.210.63.16:** 296
- **103.171.85.186:** 141
- **45.140.17.52:** 138
- **103.59.95.12:** 129
- **91.132.196.202:** 179
- **103.123.168.58:** 189
- **36.93.249.106:** 110
- **103.144.87.192:** 104
- **59.12.160.91:** 99
- **159.89.121.144:** 72
- **68.183.193.0:** 67

**Top Targeted Ports/Protocols:**
- **25:** 1,685
- **22:** 1,321
- **5060:** 1,138
- **445:** 762
- **5903:** 208
- **80:** 167
- **23:** 86
- **5908:** 83
- **5909:** 82
- **5901:** 71
- **8333:** 56
- **6379:** 39
- **11211:** 37
- **TCP/1433:** 22
- **UDP/5060:** 59
- **5907:** 48
- **TCP/22:** 33
- **27017:** 32
- **10443:** 33

**Most Common CVEs:**
- **CVE-2002-0013 CVE-2002-0012:** 10
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-2021-44228 CVE-2021-44228:** 4
- **CVE-2021-35394 CVE-2021-35394:** 3
- **CVE-2001-0414:** 2
- **CVE-2006-2369:** 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`
- `uname -s -v -n -r -m`
- `echo -e "nc\\nPFNcQ8diuxIO\\nPFNcQ8diuxIO"|passwd|bash`

**Signatures Triggered:**
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 804
- **ET DROP Dshield Block Listed Source group 1:** 322
- **ET HUNTING RDP Authentication Bypass Attempt:** 121
- **ET SCAN NMAP -sS window 1024:** 163
- **ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source):** 42
- **ET INFO Reserved Internal IP Traffic:** 57
- **ET SCAN Potential SSH Scan:** 25
- **ET VOIP Modified Sipvicious Asterisk PBX User-Agent:** 27
- **ET SCAN Suspicious inbound to MSSQL port 1433:** 15
- **ET SCAN Suspicious inbound to Oracle SQL port 1521:** 10
- **ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper:** 18

**Users / Login Attempts:**
- A wide variety of default and common credentials were attempted, including `root`, `debian`, `supervisor`, `guest`, `operator`, and `ubnt`.
- Brute-force attempts included patterns like `root/1ss4bel.123`, `root/1ss@be12024`, and password variations.
- A significant number of attempts used identical usernames and passwords, such as `345gs5662d34/345gs5662d34`.

**Files Uploaded/Downloaded:**
- `w.sh`
- `c.sh`
- `wget.sh`
- `UnHAnaAW.mpsl;`
- `Mozi.m dlink.mips'`
- `rondo.kqa.sh|sh&echo`
- `botx.mpsl;`
- Web assets like `fonts.gstatic.com` and CSS/JS files were also requested.

**HTTP User-Agents:**
- No specific HTTP User-Agents were logged in the provided data snippets.

**SSH Clients and Servers:**
- SSH client and server versions were not explicitly detailed in the aggregated logs.

**Top Attacker AS Organizations:**
- AS organization data was not available in the provided logs.

### Key Observations and Anomalies
- The high volume of SMTP traffic (port 25) from IP `86.54.42.238` is a notable event, suggesting a potential large-scale spam or mail-based attack campaign.
- The consistent use of commands to modify SSH authorized_keys files indicates a primary attacker goal of establishing persistent remote access.
- Several downloaded shell scripts (`.sh` files) point to attempts to install malware or join the compromised system to a botnet.
- The mixture of CVEs targeted suggests that attackers are running broad, automated scans for multiple vulnerabilities rather than focusing on a single exploit.
