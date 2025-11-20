
# Honeypot Attack Summary Report

## 1. Report Information

*   **Report ID:** HSR-20250928-210119
*   **Generation Date:** 2025-09-28T21:01:19Z
*   **Reporting Period:** 2025-09-28T20:36:19Z to 2025-09-28T21:00:01Z
*   **Data Sources:** T-Pot Honeypot Network Logs (`agg_log_20250928T203619Z.json`, `agg_log_20250928T204001Z.json`, `agg_log_20250928T210001Z.json`)

## 2. Executive Summary

This report provides a consolidated summary of malicious activities recorded by our T-Pot honeypot network over a period of approximately 24 minutes. During this interval, a total of **16,904** events were captured across various honeypot services. The threat landscape was dominated by automated attacks, primarily targeting SSH services, with significant activity also observed against web and IoT protocols.

The majority of attacks originated from a diverse set of IP addresses, indicating widespread and distributed scanning and exploitation attempts. The most prominent attack vector was brute-force login attempts against SSH servers, which is consistent with common tactics used by botnets to expand their reach.

A significant number of events were logged by the **Cowrie** honeypot, which emulates SSH and Telnet services, indicating a high volume of credential stuffing and brute-force attacks. The **Honeytrap** and **Suricata** honeypots also recorded substantial activity, highlighting a broad range of scanning and probing activities across multiple ports and services.

This report will provide a detailed analysis of the observed attacks, including breakdowns by honeypot type, top attacking IP addresses, targeted ports, CVEs exploited, credentials used, and commands executed by the attackers.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The following table details the distribution of attacks across the different honeypot services deployed in the T-Pot network. The Cowrie honeypot, which emulates SSH and Telnet services, accounted for the overwhelming majority of recorded events, indicating that attackers are heavily focused on compromising these remote access protocols.

| Honeypot Service | Event Count | Percentage of Total |
| :--- | :--- | :--- |
| Cowrie | 9,710 | 57.44% |
| Honeytrap | 3,043 | 18.00% |
| Suricata | 2,080 | 12.30% |
| Ciscoasa | 1,491 | 8.82% |
| Sentrypeer | 288 | 1.70% |
| Adbhoney | 101 | 0.60% |
| Tanner | 57 | 0.34% |
| ConPot | 42 | 0.25% |
| Dionaea | 40 | 0.24% |
| H0neytr4p | 27 | 0.16% |
| Redishoneypot | 9 | 0.05% |
| Mailoney | 6 | 0.04% |
| ssh-rsa | 4 | 0.02% |
| Dicompot | 3 | 0.02% |
| Honeyaml | 3 | 0.02% |
| **Total** | **16,904** | **100%** |

### 3.2. Top 10 Attacking IP Addresses

The following table lists the top 10 most active IP addresses during the reporting period. These IPs were responsible for a significant portion of the total attack volume, suggesting they are likely part of automated attack infrastructures, such as botnets or compromised servers.

| IP Address | Event Count |
| :--- | :--- |
| 143.198.32.86 | 1,516 |
| 45.78.192.211 | 1,218 |
| 35.204.172.132 | 930 |
| 107.150.110.167 | 765 |
| 34.128.77.56 | 634 |
| 190.129.114.222 | 547 |
| 35.199.95.142 | 507 |
| 193.32.162.157 | 439 |
| 185.156.73.167 | 379 |
| 185.156.73.166 | 379 |

### 3.3. Top 10 Targeted Destination Ports

The following table shows the top 10 destination ports targeted by attackers. The prevalence of port 22 (SSH) further supports the conclusion that remote access services are the primary target. The targeting of other ports, such as 5900 (VNC) and 5060 (SIP), indicates a broader interest in compromising a variety of services.

| Port | Protocol/Service | Event Count |
| :--- | :--- | :--- |
| 22 | SSH | 1,487 |
| 5900 | VNC | 489 |
| 5060 | SIP | 288 |
| 80 | HTTP | 180 |
| 8333 | Bitcoin | 88 |
| 22 (TCP) | SSH | 73 |
| 8022 | SSH Alt | 39 |
| 23 | Telnet | 46 |
| 3333 | - | 33 |

### 3.4. Observed CVEs

The following CVEs (Common Vulnerabilities and Exposures) were detected in the attack traffic. This indicates that attackers are attempting to exploit known vulnerabilities in various software and systems.

| CVE | Count |
| :--- | :--- |
| CVE-1999-0265 | 27 |
| CVE-2002-0013, CVE-2002-0012 | 4 |
| CVE-2019-11500 | 3 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 2 |
| CVE-2006-2369 | 2 |
| CVE-2021-3449 | 1 |
| CVE-2024-3721 | 1 |

### 3.5. Top 10 Credentials Used in Attacks

The following table lists the top 10 username and password combinations observed in brute-force and credential stuffing attacks. The use of common and default credentials remains a popular tactic for attackers.

| Username/Password | Count |
| :--- | :--- |
| 345gs5662d34/345gs5662d34 | 33 |
| root/Passw0rd | 12 |
| test/3245gs5662d34 | 11 |
| esuser/esuser | 10 |
| root/Qaz12!@# | 8 |
| wfp/wfp | 8 |
| root/LeitboGi0ro | 8 |
| root/123456Abc | 7 |
| justin/justin123 | 7 |
| sonar/sonar | 7 |

### 3.6. Top 10 Commands Executed by Attackers

Upon gaining access to the honeypot systems, attackers executed a series of commands to perform reconnaissance, establish persistence, and attempt to download additional malicious payloads. The most frequently observed commands are listed below.

| Command | Count |
| :--- | :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 38 |
| `lockr -ia .ssh` | 38 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 38 |
| `cat /proc/cpuinfo | grep name | wc -l` | 38 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 38 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 37 |
| `which ls` | 37 |
| `ls -lh $(which ls)` | 37 |
| `crontab -l` | 37 |
| `w` | 37 |

## 4. Notes and Limitations

*   The data in this report is based solely on the activity observed by the T-Pot honeypot network. It does not represent the full spectrum of threats on the internet.
*   Honeypots are designed to be attractive targets for automated attacks. The high volume of events does not necessarily reflect a targeted attack against our organization.
*   The IP addresses listed in this report are the sources of the attacks as seen by the honeypots. These may be compromised systems or servers used by attackers to hide their true origin.
*   This report is generated based on data from a limited time window and may not be representative of long-term trends.
