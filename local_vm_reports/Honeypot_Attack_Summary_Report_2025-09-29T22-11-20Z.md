# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T22-08-47Z
**Timeframe:** 2025-09-28T14-14:01Z to 2025-09-29T21:00:01Z

**Files used to generate the report:**
- Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T10-02-22Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T11-01-58Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T12-02-14Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T13-02-20Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T14-02-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T14:58:05Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:42:56Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T16:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T17:20:43Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T18:43:06Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T19:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T20:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T21:01:52Z.md

## Executive Summary

This report provides a comprehensive summary of malicious activities observed across our distributed honeypot network over the last 24 hours. A total of **339,474** events were captured and analyzed, revealing a relentless barrage of automated attacks from a wide array of global sources. The threat landscape is dominated by reconnaissance, brute-force attacks, and attempts to exploit known vulnerabilities, characteristic of botnet-driven campaigns seeking to expand their footprint.

The most heavily targeted services were remote access protocols, with the **Cowrie** honeypot (emulating SSH and Telnet) logging **122,235** events, accounting for over 36% of all recorded activity. This indicates a persistent focus by adversaries on compromising systems via weak credentials. Network scanning and exploit attempts were also rampant, with **Honeytrap**, **Suricata**, and **Ciscoasa** honeypots collectively recording over **130,000** events.

A significant portion of attacks was highly concentrated, originating from a small number of hyper-aggressive IP addresses. Notably, IP `162.244.80.233` was responsible for over 15,000 events alone, primarily consisting of service probes. OSINT analysis identified this IP as a likely Minecraft server, suggesting a possible compromised machine or a misconfigured scanner. Other top attackers, such as `39.107.106.103` (linked to Alibaba in China), have been flagged by threat intelligence platforms for direct involvement in spam, brute-force, and DDoS activities.

The most frequent targets were well-known service ports, including **TCP/445 (SMB)**, **TCP/22 (SSH)**, **UDP/5060 (SIP)**, and **TCP/25 (SMTP)**. This highlights a continued focus on exploiting vulnerabilities in file sharing, remote administration, VoIP, and email services. Attackers were observed attempting to exploit a wide range of vulnerabilities, from recent critical issues like **CVE-2021-44228 (Log4Shell)** to legacy vulnerabilities dating back to 1999, indicating the use of comprehensive, non-discriminatory scanning tools.

Post-exploitation activity, captured primarily by the Cowrie honeypot, reveals a consistent attacker playbook:
1.  **Reconnaissance:** Execute commands like `uname`, `lscpu`, and `whoami` to profile the compromised system.
2.  **Persistence:** Attempt to install a persistent backdoor by clearing existing SSH configurations and adding the attacker's own public key to `.ssh/authorized_keys`.
3.  **Malware Deployment:** Download and execute multi-architecture malware, with filenames such as `arm.urbotnetisass` and scripts like `w.sh`, clearly aimed at recruiting the device into a botnet.

The analysis reveals several distinct attacker signatures, including the use of the comment "mdrfckr" in SSH keys and specific, repeated credential pairs like `345gs5662d34/345gs5662d34`, suggesting these automated campaigns are operated by specific, identifiable threat groups.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
| :--- | :--- | :--- |
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by honeypot

| Honeypot | Attack Count | Percentage |
| :--- | :--- | :--- |
| Cowrie | 122,235 | 36.01% |
| Honeytrap | 56,128 | 16.53% |
| Suricata | 47,848 | 14.09% |
| Ciscoasa | 38,719 | 11.41% |
| Dionaea | 11,821 | 3.48% |
| Mailoney | 6,505 | 1.92% |
| Sentrypeer | 4,500 | 1.33% |
| Adbhoney | 868 | 0.26% |
| Tanner | 848 | 0.25% |
| Redishoneypot | 842 | 0.25% |
| H0neytr4p | 502 | 0.15% |
| ConPot | 499 | 0.15% |
| Others & Unspecified | 48,159 | 14.19% |

### Top source countries
*Note: Source country data was not consistently available across all analyzed summary reports.*

### Top 20 Attacking IPs

| IP Address | Attack Count |
| :--- | :--- |
| 162.244.80.233 | 16,366 |
| 137.184.169.79 | 3,497 |
| 4.144.169.44 | 3,422 |
| 45.78.224.98 | 2,707 |
| 147.182.150.164 | 2,667 |
| 121.52.153.77 | 2,634 |
| 86.54.42.238 | 2,463 |
| 208.109.190.200 | 2,333 |
| 134.199.202.5 | 2,173 |
| 45.140.17.52 | 2,093 |
| 39.107.106.103 | 1,817 |
| 103.190.200.2 | 1,336 |
| 106.14.67.229 | 1,250 |
| 164.92.85.77 | 1,247 |
| 8.218.160.83 | 1,220 |
| 45.78.192.211 | 1,218 |
| 157.92.145.135 | 1,070 |
| 45.8.17.45 | 1,069 |
| 143.198.32.86 | 770 |
| 107.150.110.167 | 765 |

### Top 20 Targeted Ports/Protocols

| Port | Protocol | Service | Attack Count |
| :--- | :--- | :--- | :--- |
| 22 | TCP | SSH | 13,875 |
| 445 | TCP | SMB | 12,056 |
| 5060 | UDP/TCP | SIP | 5,420 |
| 8333 | TCP | Bitcoin | 2,059 |
| 25 | TCP | SMTP | 1,844 |
| 80 | TCP | HTTP | 1,189 |
| 23 | TCP | Telnet | 1,155 |
| 6379 | TCP | Redis | 954 |
| 1433 | TCP | MSSQL | 733 |
| 443 | TCP | HTTPS | 689 |
| 9200 | TCP | Elasticsearch | 412 |
| 8888 | TCP | Misc/Alt HTTP | 355 |
| 1080 | TCP | SOCKS | 321 |
| 9000 | TCP | Misc/Alt HTTP | 299 |
| 8080 | TCP | Alt HTTP | 288 |
| 5900 | TCP | VNC | 245 |
| 8728 | TCP | MikroTik | 211 |
| 9090 | TCP | Web Proxy | 198 |
| 2222 | TCP | Alt SSH | 187 |
| 5432 | TCP | PostgreSQL | 185 |

### Most Common CVEs
*Note: This list includes all unique CVEs detected across the reports. The high frequency of Log4Shell is notable.*
- **CVE-2021-44228 (Log4Shell)**
- CVE-2002-0013 / CVE-2002-0012 (SNMP vulnerabilities)
- CVE-1999-0517 (Default SNMP Community Strings)
- CVE-2019-11500 (Pulse Secure VPN RCE)
- CVE-2021-3449 (OpenSSL DoS)
- CVE-2022-27255 (Zyxel/MIPS router RCE)
- CVE-2005-4050 (SIP DoS)
- CVE-1999-0265
- CVE-2006-2369
- CVE-2024-3721
- CVE-2018-13379 (Fortinet SSL VPN Path Traversal)
- CVE-2016-20016
- CVE-2014-6271 (Shellshock)
- CVE-2021-41773 / CVE-2021-42013 (Apache Path Traversal)
- CVE-2018-10561 / CVE-2018-10562 (Dasan GPON RCE)
- And various others targeting routers, IoT devices, and web applications.

### Top 20 Commands Attempted by Attackers

| Command | Count |
| :--- | :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 448 |
| `lockr -ia .ssh` | 448 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys...` | 448 |
| `uname -a` | 425 |
| `cat /proc/cpuinfo | grep name | wc -l` | 415 |
| `whoami` | 410 |
| `w` | 405 |
| `uname -m` | 405 |
| `crontab -l` | 402 |
| `which ls` | 401 |
| `ls -lh $(which ls)` | 401 |
| `free -m | grep Mem | awk '{...}'` | 401 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{...}'` | 400 |
| `lscpu | grep Model` | 398 |
| `top` | 397 |
| `uname` | 397 |
| `df -h | head -n 2 | awk '{...}'` | 395 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 394 |
| `Enter new UNIX password:` | 154 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill ...` | 66 |

### Signatures Triggered
*Note: A selection of the most common and significant signatures.*
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET SCAN Potential SSH Scan
- ET EXPLOIT Apache Obfuscated log4j RCE Attempt (CVE-2021-44228)

### Top 20 Users / Login Attempts

| Username / Password | Attempts |
| :--- | :--- |
| 345gs5662d34 / 345gs5662d34 | 296 |
| root / 3245gs5662d34 | 129 |
| root / nPSpP4PBW0 | 95 |
| root / LeitboGi0ro | 80 |
| root / Passw0rd | 78 |
| test / zhbjETuyMffoL8F | 68 |
| root / Linux@123 | 55 |
| root / (empty) | 52 |
| foundry / foundry | 29 |
| seekcy / Joysuch@Locate2022 | 20 |
| sa / (empty or simple) | 20 |
| root / 123456 | 18 |
| root / admin | 17 |
| user / user | 15 |
| admin / admin | 14 |
| git / 123 | 13 |
| esuser / esuser | 12 |
| oracle / oracle | 12 |
| mysql / mysql | 12 |
| minecraft / server | 11 |

### Files Uploaded/Downloaded
*Note: Filenames indicate a focus on multi-architecture botnet deployment.*
- `arm.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `w.sh`
- `c.sh`
- `wget.sh`
- `Mozi.m dlink.mips`
- `k.php`
- `apply.cgi`

### HTTP User-Agents
*Note: This data was not consistently available in the source reports.*

### SSH clients and servers
*Note: This data was not consistently available in the source reports.*

### Top attacker AS organizations
*Note: This data was not consistently available in the source reports.*

## Google Searches
OSINT was conducted on the top 5 most frequently observed attacking IP addresses.
- **162.244.80.233:** Associated with a Minecraft server (`play.diversionpvp.net`) hosted by Pilot Fiber, Inc. in New York. While the IP itself has no direct malicious reports, its high volume of activity suggests it may be a compromised game server or is being used as a network scanner.
- **39.107.106.103:** Located in China and registered to Hangzhou Alibaba Advertising Co., Ltd. This IP has been flagged by multiple threat intelligence platforms for direct involvement in spam, brute-force attacks, DDoS attacks, and port scanning. It is considered a significant threat.
- **121.52.153.77:** Traced to the National University of Modern Languages (NUML) in Islamabad, Pakistan, on the Pakistan Education & Research Network (PERN). The activity from an educational institution suggests a compromised system within their network is being used as part of a botnet.
- **147.182.150.164:** Belongs to DigitalOcean's network. This IP is listed on multiple blacklists for abuse, spam, and suspicious SSH activity. It is highly likely to be a virtual private server being used for malicious campaigns.
- **137.184.169.79:** An IP address from a DigitalOcean datacenter in Toronto, Canada. While this specific IP had no direct negative reports at the time of investigation, the provider's infrastructure is a known hotbed for hosting malicious actors, warranting caution.

## Key Observations and Anomalies

- **Hyper-Aggressive Scanners:** A small number of IPs are responsible for a disproportionate amount of traffic. `162.244.80.233` logged over 15,000 events in a single 40-minute window, indicating an extremely aggressive, likely automated, service discovery scan.
- **Botnet "Signatures":** The repeated use of the credential pair `345gs5662d34/345gs5662d34` and the comment `mdrfckr` within SSH `authorized_keys` payloads strongly suggest a specific botnet or threat actor group with consistent tooling.
- **Multi-Architecture Malware:** The consistent attempts to download malware for various CPU architectures (ARM, MIPS, x86) under the filename pattern `*.urbotnetisass` is a clear indicator of a sophisticated IoT botnet campaign designed to infect a wide range of devices from routers and cameras to standard servers.
- **Standardized Post-Exploitation:** The sequence of commands executed by attackers is remarkably uniform: disable immutability on the `.ssh` directory, wipe it, insert a new SSH key, and then run a battery of reconnaissance commands. This demonstrates a fully automated and scripted attack chain.
- **Exploitation of Old and New:** Attackers are not limiting themselves to new vulnerabilities. The continued, widespread scanning for legacy CVEs (e.g., from 1999 and 2002) alongside critical, recent ones (Log4Shell) shows that their tooling is designed to find any weakness, regardless of age, maximizing their chances of a successful compromise.
- **Institutional Compromise:** The identification of an attacking IP from a Pakistani university (`121.52.153.77`) highlights the common tactic of using compromised systems in trusted institutions to launch attacks, leveraging their reputation and network resources.
