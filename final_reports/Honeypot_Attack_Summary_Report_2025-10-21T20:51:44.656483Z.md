# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T20:46:02Z
**Timeframe:** 2025-10-21T08:46:02Z to 2025-10-21T20:46:02Z

**Files Used for Report Generation:**
- Honeypot_Attack_Summary_Report_2025-10-21T09:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T10:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T11:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T12:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T13:02:11Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T14:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T15:02:21Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T16:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T17:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T19:02:17Z.md
- Honeypot_Attack_Summary_Report_2025-10-21T20:02:00Z.md

---

### **Executive Summary**

Over the past 12 hours, our honeypot network has observed a significant volume of malicious activity, totaling over 184,000 recorded events. The threat landscape was dominated by automated scanning, brute-force attacks, and exploitation attempts targeting common vulnerabilities. The **Cowrie** (SSH/Telnet) honeypot logged the highest number of interactions, indicating a persistent and widespread campaign against these services.

Key findings from this period include:

*   **High-Volume Attack Campaigns:** A small number of IP addresses were responsible for a disproportionately large volume of attacks. Notably, **`94.153.137.178`** (Iraq), **`142.4.197.12`** (Canada), and **`72.146.232.13`** (Microsoft, US) were consistently identified as hyper-aggressive, suggesting automated, botnet-driven activity. OSINT analysis confirms that `72.146.232.13` and `94.153.137.178` are known sources of malicious traffic.
*   **Dominant Attack Vectors:** The most heavily targeted services were **SMB (TCP/445)** and **SSH (TCP/22)**. The high frequency of SMB attacks, often correlated with the `DoublePulsar Backdoor` signature, points to continued, widespread scanning for vulnerabilities related to the EternalBlue exploit.
*   **Consistent TTPs:** A clear and repeated tactic, technique, and procedure (TTP) was observed across numerous attackers. This involves gaining initial access, performing system reconnaissance (`uname`, `lscpu`, `whoami`), and immediately attempting to establish persistence by deleting the existing `.ssh` directory and adding a new public key to `authorized_keys`.
*   **Malware and Botnet Activity:** The analysis identified the presence of known malware droppers and botnets. The script **`ohsitsvegawellrip.sh`** was downloaded, a known first-stage downloader. Furthermore, the file **`Mozi.m`** was observed, indicating activity from the notorious Mozi IoT botnet, which has recently seen a resurgence through integration with other malware families like Androxgh0st.
*   **Exploitation of Common CVEs:** Attackers leveraged a mix of old and new vulnerabilities. CVEs related to remote code execution and information disclosure were most common, with **`CVE-2019-11500`** and **`CVE-2021-3449`** appearing frequently.

In conclusion, the threat landscape is characterized by high-volume, automated attacks targeting low-hanging fruit: weak credentials on SSH/Telnet and unpatched SMB vulnerabilities. The tactics are consistent and point towards botnet-driven campaigns focused on expanding their foothold by compromising new devices, with clear evidence of known malware families being actively deployed.

---

### **Detailed Analysis**

#### **Our IPs**

| Honeypot | Private IP | Public IP |
| :--- | :--- | :--- |
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115|
| sens-tel | 10.208.0.3 | 34.165.197.224|
| sens-dub | 172.31.36.128| 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163|

#### **Attacks by Honeypot (Aggregated)**

| Honeypot | Total Events |
| :--- | :--- |
| Cowrie | 76,000+ |
| Honeytrap | 45,000+ |
| Suricata | 25,000+ |
| Dionaea | 15,000+ |
| Sentrypeer | 6,000+ |
| Others | <5,000 each |

#### **Top Source Countries**
*(Note: Country data is derived from the geolocation of top attacking IPs and may not be exhaustive.)*
- United States
- Iraq
- Canada
- India
- Vietnam
- China
- Germany
- Russia

#### **Top Attacking IPs**

| IP Address | Total Events (Approx.) |
| :--- | :--- |
| 142.4.197.12 | 6,500+ |
| 72.146.232.13 | 6,000+ |
| 94.153.137.178 | 3,100+ |
| 5.182.209.68 | 4,000+ |
| 14.241.1.119 | 1,400+ |
| 106.51.31.166| 1,400+ |
| 83.239.178.110| 1,300+ |
| 51.89.1.87 | 1,200+ |

#### **Top Targeted Ports/Protocols**

| Port/Protocol | Service |
| :--- | :--- |
| 445/TCP | SMB |
| 22/TCP | SSH |
| 5060/UDP | SIP |
| 5903/TCP | VNC |
| 23/TCP | Telnet |
| 80/TCP | HTTP |
| 6379/TCP | Redis |
| 8333/TCP | Bitcoin |

#### **Most Common CVEs**

| CVE ID | Description |
| :--- | :--- |
| CVE-2019-11500 | Unspecified vulnerability in a wide range of products. |
| CVE-2021-3449 | OpenSSL denial-of-service vulnerability. |
| CVE-2022-27255 | Mitel MiVoice Connect vulnerability allowing RCE. |
| CVE-2002-0013 / 0012| Multiple buffer overflows in SNMP message processing. |
| CVE-1999-0517 | `phf` CGI program remote command execution. |
| Multiple | Associated with DoublePulsar/EternalBlue exploits. |

#### **Commands Attempted by Attackers (Common Patterns)**

| Command | Purpose |
| :--- | :--- |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys` | **Persistence:** Wipes existing SSH keys and installs the attacker's key. |
| `uname -a`, `lscpu`, `whoami` | **Reconnaissance:** Gathers basic system, OS, and user information. |
| `free -m`, `df -h` | **Reconnaissance:** Checks system memory and disk resources. |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | **Defense Evasion:** Attempts to remove immutability from SSH files before modification. |
| `tftp; wget; /bin/busybox [payload]` | **Execution:** Uses multiple tools to download and run a malicious payload. |
| `Enter new UNIX password:` | **Credential Access:** Interaction with prompts to change user passwords. |

#### **Signatures Triggered (Top 5)**

| Signature Name | Description | Count |
| :--- | :--- | :--- |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor communication | Indicates exploitation of SMB vulnerability (EternalBlue). | High |
| ET DROP Dshield Block Listed Source group 1 | Traffic from an IP on the DShield Top 20 attackers list. | High |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | Scanning for Remote Desktop Protocol on unusual ports. | High |
| ET SCAN NMAP -sS window 1024 | Nmap stealth scan detected. | Medium |
| ET HUNTING RDP Authentication Bypass Attempt | Attempt to bypass RDP authentication. | Medium |

#### **Users / Login Attempts**

| Username | Password | Notes |
| :--- | :--- | :--- |
| 345gs5662d34 | 345gs5662d34 | Common bot-like credential. |
| root | (various) | Most common target username with thousands of password attempts. |
| odin | odin | Common default credential. |
| pi | raspberry | Default credential for Raspberry Pi devices. |
| user01 | Password01 | Common default/weak credential. |
| deploy | 123123 | Common weak credential for deployment accounts. |

#### **Files Uploaded/Downloaded**

| Filename | Type | Notes |
| :--- | :--- | :--- |
| `sh`, `wget.sh`, `w.sh`, `c.sh` | Shell Script | Generic names for downloaded scripts, likely first-stage droppers. |
| `ohsitsvegawellrip.sh` | Shell Script | **Known Malware Dropper.** Used to download further payloads. |
| `Mozi.m` | Malware | Payload associated with the **Mozi IoT Botnet**. |
| `.i` | Executable | Generic name for a downloaded binary, executed immediately. |

---

### **OSINT Investigations**

#### **OSINT on High-Frequency IPs**

| IP Address | Location | Owner/ASN | Summary of Findings |
| :--- | :--- | :--- | :--- |
| 72.146.232.13 | United States | Microsoft Corporation (AS8075) | Confirmed malicious. Widely reported for SSH attacks and network abuse. Blocking is recommended. Part of a larger ASN known for generating unwanted traffic. |
| 94.153.137.178 | Baghdad, Iraq | Iq online | Present on multiple blacklists for HTTP and SSH abuse. Port scans reveal multiple vulnerabilities. Assessed as a compromised system or one actively used for malicious purposes. |
| 142.4.197.12 | Quebec, Canada | OVH Hosting, Inc. | No adverse findings on major threat intelligence platforms (VirusTotal, AbuseIPDB). While responsible for a high volume of traffic against our honeypot, it is not publicly flagged as malicious. This may indicate a newly compromised server. |

#### **OSINT on CVEs and Malware**

| Identifier | Summary |
| :--- | :--- |
| DoublePulsar / EternalBlue | This exploit, developed by the NSA and leaked in 2017, targets a vulnerability in Microsoft's SMB protocol. Despite its age, it remains highly effective due to unpatched systems and is a primary tool for worms and botnets to propagate. The high number of triggers confirms its continued prevalence. |
| `ohsitsvegawellrip.sh` | This script is a known malware dropper. Its function is to use legitimate system tools like `wget` and `curl` to download and execute more dangerous, second-stage malware onto a compromised machine, effectively bypassing simple signature-based detection. |
| `Mozi.m` Botnet | A notorious P2P IoT botnet that was dominant in 2019-2020. After a period of dormancy, its code and capabilities have been integrated into newer botnets like Androxgh0st, leading to a resurgence. It targets weak credentials and vulnerabilities in IoT devices to expand its network for DDoS attacks and data theft. |

---

### **Key Observations and Anomalies**

*   **Hyper-Aggressive IPs:** The concentration of tens of thousands of attacks from a handful of IPs (`142.4.197.12`, `72.146.232.13`, etc.) is a clear indicator of automated, bot-driven campaigns. The actors are not attempting to be subtle.
*   **Standardized Attack Playbook:** The repeated sequence of reconnaissance (`uname`, `lscpu`) followed immediately by SSH key manipulation (`rm -rf .ssh`, `echo "ssh-rsa..."`) is a standardized playbook. This suggests the use of a common attack script or botnet C2 instructions, prioritizing persistent access above all else.
*   **Living Off the Land (LotL):** Attackers consistently use built-in system tools like `wget`, `curl`, `tftp`, and `sh` to download and execute payloads. This LotL technique makes detection harder as it relies on legitimate software for malicious ends.
*   **IoT Botnet Resurgence:** The detection of the `Mozi.m` payload is a significant finding. It confirms that our honeypots are being targeted by large-scale IoT botnets that are actively recruiting new devices. This aligns with recent threat intelligence reports about the resurgence of Mozi's code in the wild.

### **Unusual Attacker Origins**

While many attacks originate from expected locations like major data centers in the US and Europe, the high volume of traffic from **Baghdad, Iraq (`94.153.137.178`)** is noteworthy. This source is not a typical hub for such large-scale automated attacks, suggesting a potentially significant compromised network segment or a dedicated threat actor operating from that region.

---
**End of Report**