# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T06:19:48Z
**Timeframe:** 2025-10-06T07:02:22Z - 2025-10-07T06:02:10Z

**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-06T09:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T10:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T11:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T12:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T13:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T13:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T13:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T14:02:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T15:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T16:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T17:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T18:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T19:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T21:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T22:01:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T23:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T00:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T01:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T02:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T03:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:02:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:03:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:03:29Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:03:48Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:04:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:04:30Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T04:04:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T05:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T06:02:10Z.md

### Executive Summary
This report provides a comprehensive analysis of honeypot network activity from 2025-10-06T07:02:22Z to 2025-10-07T06:02:10Z. During this period, a significant volume of malicious activity was observed, with a total of over 750,000 attacks recorded across all honeypots. The majority of these attacks were automated and opportunistic, targeting common vulnerabilities and misconfigurations. The Cowrie and Dionaea honeypots were the most frequently targeted, indicating a high volume of SSH and SMB-based attacks. The most prominent attacking IPs originated from a diverse range of countries, with South Africa, China, and France being the most notable. The most frequently exploited vulnerability was CVE-2021-44228 (Log4Shell), highlighting the continued risk posed by this critical flaw. A significant number of commands attempted by attackers were focused on reconnaissance, privilege escalation, and establishing persistence through the creation of backdoors and the installation of malicious software. The Suricata IDS detected a high volume of "DoublePulsar Backdoor" installation attempts, suggesting that many of the attacking systems are likely compromised and part of larger botnets.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 250,000+ |
| Dionaea | 200,000+ |
| Suricata | 100,000+ |
| Honeytrap | 75,000+ |
| Ciscoasa | 50,000+ |
| Mailoney | 30,000+ |
| Sentrypeer | 20,000+ |
| Other | 25,000+ |

**Top Source Countries**

| Country | Attack Count |
|---|---|
| South Africa | 100,000+ |
| China | 75,000+ |
| France | 50,000+ |
| Indonesia | 40,000+ |
| Australia | 30,000+ |
| United States | 25,000+ |
| Russia | 20,000+ |
| Germany | 15,000+ |
| Netherlands | 10,000+ |
| United Kingdom | 5,000+ |

**Top Attacking IPs**

| IP Address | Attack Count |
|---|---|
| 196.25.125.58 | 3,093+ |
| 120.55.160.161 | 2,929+ |
| 5.39.12.192 | 2,438+ |
| 182.10.161.232 | 1,402+ |
| 170.64.232.235 | 1,461+ |

**Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---|---|
| 445 (SMB) | 250,000+ |
| 22 (SSH) | 150,000+ |
| 25 (SMTP) | 100,000+ |
| 5060 (SIP) | 50,000+ |
| 80 (HTTP) | 25,000+ |
| 443 (HTTPS) | 20,000+ |
| 6379 (Redis) | 10,000+ |
| 5900 (VNC) | 5,000+ |

**Most Common CVEs**

| CVE | Description |
|---|---|
| CVE-2021-44228 | Apache Log4j Remote Code Execution |
| CVE-2018-14847 | MikroTik RouterOS Authentication Bypass |
| CVE-2019-11500 | Pulse Secure VPN Remote Code Execution |
| CVE-2002-0013 | Multiple Vendor Telnet Authentication Bypass |
| CVE-2002-0012 | Multiple Vendor Telnet Authentication Bypass |
| CVE-1999-0517 | Multiple Vendor Telnet Authentication Bypass |

**Commands Attempted by Attackers**

| Command | Description |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | Attempt to modify SSH authorized keys |
| `lockr -ia .ssh` | Attempt to lock SSH authorized keys |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys` | Attempt to add a new SSH key |
| `cat /proc/cpuinfo` | Gather information about the CPU |
| `uname -a` | Gather information about the system |
| `wget.sh;`, `w.sh;`, `c.sh;` | Download and execute malicious scripts |
| `tftp; wget; /bin/busybox` | Download and execute malicious binaries |

**Signatures Triggered**

| Signature | Description |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | Attempt to install the DoublePulsar backdoor |
| ET DROP Dshield Block Listed Source group 1 | Traffic from a known malicious IP address |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | Scanning for open RDP ports |
| ET HUNTING RDP Authentication Bypass Attempt | Attempt to bypass RDP authentication |
| ET SCAN NMAP -sS window 1024 | Nmap scan detected |
| ET INFO VNC Authentication Failure | Failed VNC authentication attempt |

**Users / Login Attempts**

| Username | Password |
|---|---|
| 345gs5662d34 | 345gs5662d34 |
| guest | guest |
| bridget | bridget123 |
| include | include@123 |
| tty | tty123 |
| anne | anne123 |
| ruben | ruben123 |
| cad | cad@123 |
| imbroglio | imbroglio123 |

**Files Uploaded/Downloaded**

| Filename | Description |
|---|---|
| wget.sh | Shell script to download and execute malicious code |
| w.sh | Shell script to download and execute malicious code |
| c.sh | Shell script to download and execute malicious code |
| Mozi.m | Malware associated with the Mozi botnet |
| dlink.mips | Malware targeting D-Link devices |

**HTTP User-Agents**

*No significant user agents were recorded in this period.*

**SSH Clients and Servers**

*No significant SSH clients or servers were recorded in this period.*

**Top Attacker AS Organizations**

*No significant attacker AS organizations were recorded in this period.*

### Key Observations and Anomalies
- **High Volume of Automated Attacks:** The vast majority of observed attacks were automated and indiscriminate, targeting common vulnerabilities and default credentials. This is consistent with the activity of botnets and opportunistic attackers.
- **Prevalence of Log4Shell:** The continued high volume of exploitation attempts for CVE-2021-44228 (Log4Shell) indicates that many systems remain unpatched and vulnerable to this critical flaw.
- **Targeting of SSH and SMB:** The Cowrie and Dionaea honeypots, which emulate SSH and SMB services respectively, were the most heavily targeted. This highlights the ongoing focus of attackers on compromising these common services.
- **Botnet Activity:** The high number of "DoublePulsar Backdoor" signatures detected by Suricata, along with the download of known malware such as Mozi, strongly suggests that a significant portion of the attacking IPs are compromised systems that are part of larger botnets.
- **Geographic Distribution of Attackers:** The attacks originated from a wide range of countries, with South Africa, China, and France being the most prominent. This global distribution is typical of large-scale automated attacks.

### Google Searches

- OSINT on IP address 196.25.125.58
- OSINT on IP address 120.55.160.161
- OSINT on IP address 5.39.12.192
- OSINT on IP address 182.10.161.232
- OSINT on IP address 170.64.232.235
- information on CVE-2021-44228
