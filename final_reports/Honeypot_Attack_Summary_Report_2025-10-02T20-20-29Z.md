# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T20:19:17Z
**Timeframe:** 2025-10-02T04:19:17Z to 2025-10-02T20:19:17Z (Last 16 Hours)

**Files Used to Generate Report:**
- `Honeypot_Attack_Summary_Report_2025-10-02T05:02:04Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T06:02:06Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T07:01:57Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T08:01:54Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T09:02:07Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T10:01:41Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T11:01:43Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T12:02:02Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T13:01:44Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T16:02:03Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T17:01:49Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T18:02:29Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T19:01:55Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-02T20:01:53Z.md`

## Executive Summary

This report provides a comprehensive summary of malicious activities observed across our distributed honeypot network over the last 16 hours. During this period, over 160,000 malicious events were recorded, indicating a highly active and automated threat landscape. The vast majority of attacks were opportunistic, focusing on brute-force credential attacks against remote access services and the exploitation of well-known vulnerabilities.

The **Cowrie** (SSH) and **Suricata** (IDS) honeypots logged the highest volume of traffic, highlighting a significant focus on compromising SSH servers and widespread network scanning for vulnerabilities. The primary targets were services like SSH (Port 22), SMB (Port 445), and SIP (Port 5060).

Attack traffic was globally distributed, with OSINT on the most aggressive IP addresses, such as **179.108.56.80** (Brazil) and **203.130.24.42** (Pakistan), pointing to their use in persistent botnet activities. This aligns with observed attacker tactics, which consistently involved the deployment of multi-architecture malware loaders like `urbotnetisass`.

The Log4Shell vulnerability (**CVE-2021-44228**) continues to be a major target, with numerous attempts detected by our sensors. This demonstrates that threat actors continue to scan for and exploit this critical vulnerability, even years after its initial disclosure.

Post-exploitation activity was characterized by a clear, automated pattern: reconnaissance of the victim's system (`uname`, `lscpu`), followed by immediate attempts to establish persistence by overwriting SSH `authorized_keys`, and finally, the execution of malware payloads.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Attack Count |
|---|---|
| Cowrie | 70,891 |
| Suricata | 30,123 |
| Honeytrap | 24,510 |
| Ciscoasa | 17,451 |
| Dionaea | 5,420 |
| Sentrypeer | 2,123 |
| Mailoney | 1,845 |
| Other | 1,237 |

### Top Source Countries

| Country | Attack Count |
|---|---|
| *Data not available in logs* | |

### Top Attacking IPs

| IP Address | Attack Count | Notes |
|---|---|---|
| 179.108.56.80 | 3,122 | OSINT suggests persistent bot IP (Brazil) |
| 203.130.24.42 | 2,987 | OSINT suggests association with botnet activity (Pakistan) |
| 137.184.169.79 | 2,549 | High-volume scanning and brute-force |
| 121.52.153.77 | 1,492 | Linked to DoublePulsar backdoor scans |
| 8.218.160.83 | 1,220 | High-volume SSH brute-force |
| 103.190.200.2 | 1,336 | High-volume SMB probes |
| 86.54.42.238 | 821 | SMTP scanning |
| 39.107.106.103 | 1,270 | General scanning activity |
| 4.144.169.44 | 1,246 | SMB Probing |
| 168.187.86.35 | 1,476 | SMTP scanning |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count | Common Service |
|---|---|---|
| 22 (TCP) | 12,876 | SSH |
| 445 (TCP) | 9,862 | SMB |
| 5060 (UDP/TCP) | 2,123 | SIP (VoIP) |
| 8333 (TCP) | 1,056 | Bitcoin |
| 25 (TCP) | 1,845 | SMTP |
| 1433 (TCP) | 688 | MSSQL |
| 23 (TCP) | 612 | Telnet |
| 6379 (TCP) | 598 | Redis |
| 80 (TCP) | 543 | HTTP |
| 1080 (TCP) | 402 | SOCKS Proxy |

### Most Common CVEs

| CVE ID | Count | Description |
|---|---|---|
| CVE-2021-44228 | 345 | Apache Log4j RCE (Log4Shell) |
| CVE-2002-0013 / CVE-2002-0012 | 86 | SNMPv1 Vulnerabilities |
| CVE-2019-11500 | 54 | Pulse Secure VPN Info Disclosure |
| CVE-2021-3449 | 45 | OpenSSL Denial of Service |
| CVE-1999-0517 | 31 | Default SNMP Community Strings |
| CVE-2018-13379 | 12 | Fortinet FortiGate SSL VPN Path Traversal |
| CVE-2024-4577 | 10 | PHP-CGI Argument Injection |

### Commands Attempted by Attackers

| Command | Count | Purpose |
|---|---|---|
| `cd ~ && rm -rf .ssh && ... authorized_keys` | 245 | Persistence via SSH key injection |
| `uname -a` | 231 | System Reconnaissance |
| `lscpu | grep Model` | 210 | System Reconnaissance |
| `cd /data/local/tmp/; rm *; busybox wget ...` | 115 | Malware Download/Execution |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh` | 98 | Removal of competing malware |
| `whoami` | 225 | System Reconnaissance |
| `Enter new UNIX password:` | 156 | Attempted password change |
| `nohup bash -c "exec 6<>/dev/tcp/...` | 45 | Reverse Shell Execution |

### Signatures Triggered

| Signature | Count |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor | 4,242 |
| ET DROP Dshield Block Listed Source group 1 | 2,109 |
| ET SCAN NMAP -sS window 1024 | 1,567 |
| ET SCAN Potential SSH Scan | 843 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 512 |
| ET EXPLOIT Apache Obfuscated log4j RCE Attempt | 345 |

### Users / Login Attempts

| Username / Password | Attempts |
|---|---|
| `345gs5662d34` / `345gs5662d34` | 212 |
| `root` / `3245gs5662d34` | 154 |
| `root` / `nPSpP4PBW0` | 110 |
| `test` / `zhbjETuyMffoL8F` | 98 |
| `root` / `Passw0rd` | 88 |
| `root` / `LeitboGi0ro` | 81 |
| `foundry` / `foundry` | 65 |
| `sa` / ` ` | 55 |
| `root` / `Linux@123` | 51 |
| `minecraft` / `server` | 43 |

### Files Uploaded/Downloaded

| Filename | Count | Type |
|---|---|---|
| `arm.urbotnetisass` | 45 | ELF Binary (Botnet) |
| `w.sh`, `c.sh`, `wget.sh` | 38 | Shell Scripts (Malware Loaders) |
| `x86_32.urbotnetisass` | 31 | ELF Binary (Botnet) |
| `mips.urbotnetisass` | 29 | ELF Binary (Botnet) |
| `Mozi.m` | 15 | ELF Binary (Botnet) |

### HTTP User-Agents
*Data not available in logs.*

### SSH Clients and Servers
*Data not available in logs.*

### Top Attacker AS Organizations
*Data not available in logs.*

### Google Searches
- OSINT on IP address 179.108.56.80
- OSINT on IP address 203.130.24.42
- Threat report on CVE-2021-44228 Log4Shell

## Key Observations and Anomalies

1.  **Geographically-Distributed Botnet Activity**: The most aggressive IP addresses observed in this period have been linked via OSINT to persistent botnet activity. IPs from Brazil (`179.108.56.80`) and Pakistan (`203.130.24.42`) were responsible for thousands of connection attempts, indicating a widespread, automated campaign. This is corroborated by the frequent downloads of malware like `urbotnetisass` and `Mozi`, which are known botnet clients.

2.  **Persistent Exploitation of Log4Shell**: The high number of detected exploitation attempts for CVE-2021-44228 (Log4Shell) is a significant anomaly. It underscores that despite being a well-publicized vulnerability from 2021, attackers continue to find unpatched systems. This highlights a critical gap in patch management practices across the internet.

3.  **Standardized Attacker Playbook**: A clear and repetitive sequence of post-exploitation commands was observed across numerous successful intrusions. This playbook consists of:
    *   **System Reconnaissance**: Immediately running `uname -a`, `lscpu`, `whoami`, etc., to identify the environment.
    *   **Persistence**: Overwriting the `.ssh/authorized_keys` file to ensure continued access. The use of the comment "mdrfckr" in the injected SSH key is a recurring attacker signature.
    *   **Payload Execution**: Downloading and running shell scripts (`w.sh`, `c.sh`) which in turn fetch and execute binaries for multiple CPU architectures (ARM, MIPS, x86).

4.  **Widespread SMB Scanning for EternalBlue**: The Suricata IDS triggered the "DoublePulsar Backdoor" signature over 4,000 times, almost exclusively linked to traffic on port 445 (SMB). This indicates massive, ongoing scanning campaigns searching for systems still vulnerable to the EternalBlue exploit or similar SMB vulnerabilities.

5.  **Malware Cockroaching**: The observation of commands like `rm -rf /tmp/secure.sh; pkill -9 secure.sh` suggests that attackers are actively attempting to remove traces of competing malware from compromised systems. This behavior, often called "malware cockroaching," is common in botnet operations where control over an infected host is a valuable resource.
