# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T02:01:32Z
**Timeframe:** 2025-10-15T01:20:01Z to 2025-10-15T02:00:01Z
**Files Used:** `agg_log_20251015T012001Z.json`, `agg_log_20251015T014001Z.json`, `agg_log_20251015T020001Z.json`

## Executive Summary

This report summarizes 18,972 events collected from the honeypot network. The primary attack vectors observed were directed at mail services (SMTP), remote access protocols (SMB, SSH, RDP), and database services (Redis). A significant number of commands were attempted, indicating efforts to establish persistent access and control over compromised systems.

## Detailed Analysis

### Attacks by Honeypot

*   **Cowrie:** 4108
*   **Honeytrap:** 4246
*   **Mailoney:** 1770
*   **Ciscoasa:** 1965
*   **Dionaea:** 1821
*   **Suricata:** 1758
*   **Sentrypeer:** 1551
*   **Redishoneypot:** 1515

### Top Attacking IPs

*   **47.251.171.50:** 2019
*   **200.87.27.60:** 1812
*   **206.191.154.180:** 1313
*   **86.54.42.238:** 822
*   **176.65.141.119:** 821
*   **196.251.88.103:** 609
*   **172.86.95.98:** 427

### Top Targeted Ports/Protocols

*   **25 (SMTP):** 1770
*   **445 (SMB):** 1810
*   **6379 (Redis):** 1515
*   **5060 (SIP):** 1551
*   **22 (SSH):** 634

### Most Common CVEs

*   CVE-2019-11500
*   CVE-2002-0013, CVE-2002-0012
*   CVE-2018-10562, CVE-2018-10561

### Commands Attempted by Attackers

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `whoami`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `uname -m`
*   Various `nohup bash -c` commands to download and execute malicious payloads.

### Signatures Triggered

*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET INFO Reserved Internal IP Traffic

### Users / Login Attempts

*   **root/:** 102
*   **345gs5662d34/345gs5662d34:** 12
*   **ftpuser/ftppassword:** 7
*   **ubnt/66:** 6
*   **blank/blank2011:** 6

### Files Uploaded/Downloaded

*   `&currentsetting.htm=1`
*   `gpon8080&ipv=0`

### HTTP User-Agents
* None observed in this period.

### SSH Clients and Servers
* No specific SSH client or server versions were logged.

### Top Attacker AS Organizations
* No specific AS organizations were logged.

## Key Observations and Anomalies

*   **High Volume of Mail-related Attacks:** The Mailoney honeypot recorded a significant number of events, indicating a focus on exploiting or leveraging mail servers.
*   **Persistent Access Attempts:** The repeated use of commands to modify SSH authorized_keys files suggests a clear intent to establish persistent, unauthorized access.
*   **Payload Delivery via TCP:** Numerous commands involved establishing a TCP connection to a remote server to download and execute a file, a common malware delivery technique.
*   **System Enumeration:** The presence of commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` demonstrates that attackers are actively profiling the systems they compromise.
