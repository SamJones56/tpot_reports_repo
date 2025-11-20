# Honeypot Threat Report: Analysis of Coordinated Botnet Campaigns & Enterprise Exploitation

**Report Generation Time:** 2024-10-30T11:00:00Z
**Timeframe:** September 28, 2025 - October 29, 2025
**Files Used:**
*   Honeypot_Attack_Summary_Report_2025-10-12.md
*   Honeypot_Attack_Summary_Report_2025-10-19.md
*   Honeypot_Attack_Summary_Report_2025-10-25.md
*   Honeypot_Attack_Summary_Report_2025-10-29.md

---

## Executive Summary

This report provides a comprehensive analysis of malicious activities observed across our global honeypot network over the past month. The threat landscape was dominated by several large-scale, automated campaigns, each with distinct tactics, techniques, and procedures (TTPs). The primary objectives of these campaigns were botnet propagation for Distributed Denial-of-Service (DDoS) attacks, the establishment of persistent backdoors, illicit cryptocurrency mining, and the exploitation of high-value enterprise software.

Four major, concurrent botnet campaigns were identified, each distinguished by unique malware and signatures:

1.  **The "Outlaw" Group Campaign:** This financially motivated group continues its widespread campaign to gain persistent access to Linux servers. Their activity is easily identified by a unique SSH key signature (`mdrfckr`) and a specific set of commands designed to make their backdoor immutable for future cryptomining operations.

2.  **Mirai Variant Campaigns ("urbotnetisass" & "uhavenobotsxd"):** Two massive and distinct Mirai campaigns were observed targeting IoT and embedded devices. Attackers systematically downloaded payloads for various architectures (ARM, MIPS, x86) with the clear objective of enslaving devices for DDoS attacks. The use of taunting filenames like "uhavenobotsxd" suggests a brazen attitude within this segment of the threat landscape.

3.  **Mozi P2P Botnet:** The resilient Mozi botnet was actively spreading, identified by the download of its specific malware payloads (`Mozi.m`). This campaign targets IoT devices with weak Telnet credentials and known vulnerabilities, leveraging its decentralized P2P architecture to resist takedowns.

4.  **Prometei Cryptomining Botnet:** This sophisticated, multi-platform botnet was identified targeting both Linux and Windows systems. It leverages well-known exploits like EternalBlue (indicated by DoublePulsar alerts) to propagate and deploy a Monero (XMRig) miner.

In addition to these botnet activities, a notable volume of attacks targeted critical vulnerabilities in enterprise software, including **Apache Struts 2 (CVE-2018-11776)**, **Atlassian Confluence (CVE-2023-22527)**, and a recently disclosed flaw in **Vite (CVE-2025-30208)**. The rapid weaponization of the Vite vulnerability, despite its anomalous future-dated CVE identifier, highlights the speed at which threat actors are incorporating new exploits into their automated toolkits.

This report provides a detailed breakdown of each campaign, including specific Indicators of Compromise (IOCs) such as commands, SSH keys, malware filenames, and targeted CVEs for use in threat hunting and defensive posture improvement.

---

## Detailed Analysis

### Our IPs (Honeypot Network)
| Honeypot Name | Private IP | Public IP |
| :--- | :--- | :--- |
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

*(Note: Data on attacks by specific honeypots, top source countries, attacking IPs, targeted ports, user-agents, and AS organizations was not available in the provided summary logs and is omitted from this report.)*

### Most Common CVEs Targeted
| CVE ID | Software | Vulnerability Type | Threat Actor Objective |
| :--- | :--- | :--- | :--- |
| **CVE-2025-30208** | Vite | Arbitrary File Read | Access sensitive configuration files, source code, and credentials from exposed dev servers. |
| **CVE-2023-22527** | Atlassian Confluence | Template Injection (RCE) | Gain complete control of high-value enterprise collaboration servers for data theft or lateral movement. |
| **CVE-2018-11776** | Apache Struts 2 | Remote Code Execution (RCE) | Compromise public-facing web applications to deploy malware or establish a foothold in the network. |
| **MS17-010 (EternalBlue)** | Windows SMBv1 | Remote Code Execution (RCE) | Propagate worms (like Prometei) across networks by exploiting a critical vulnerability in the SMB protocol. |

### Commands Attempted by Attackers
| Command | Purpose |
| :--- | :--- |
| `uname -a` / `whoami` / `lscpu` | Basic system and user reconnaissance to identify the operating environment. |
| `cat /proc/cpuinfo | grep name | wc -l` | Count CPU cores, likely to assess suitability for cryptomining. |
| `free -m` / `df -h` | Check available memory and disk space. |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "..." >> .ssh/authorized_keys` | "Outlaw Group" command to wipe existing SSH keys and inject their own backdoor. |
| `chattr -ia .ssh` / `lockr -ia .ssh` | Attempt to make the attacker's SSH key directory immutable and difficult to remove. |
| `cd /data/local/tmp/` or `/tmp/` | Navigate to world-writable directories to download malware. |
| `busybox wget http://...` | Download malware payloads onto compromised IoT/embedded devices. |
| `chmod 777 <malware_file>` | Make the downloaded malware executable. |
| `./<malware_file>` | Execute the malware payload. |
| `pkill -9 <competing_malware>` | Terminate processes of competing malware to ensure resource monopolization. |

### Signatures Triggered
| Signature | Associated Threat | Type | Description |
| :--- | :--- | :--- | :--- |
| `mdrfckr` | Outlaw Group | SSH Key Comment | A unique comment in an injected SSH public key, serving as a definitive indicator of this group. |
| `urbotnetisass` | Mirai Variant | Malware Filename | A widespread Mirai variant targeting multiple CPU architectures for DDoS botnet propagation. |
| `uhavenobotsxd` | Mirai Variant | Malware Filename | A distinct Mirai variant, using a taunting filename, also used for DDoS botnet creation. |
| `Mozi.m` / `Mozi.a+varcron` | Mozi Botnet | Malware Filename | Payloads associated with the resilient Mozi P2P botnet. |
| `sora.sh` / `yukari.sh` | Mirai Variant | Dropper Script | Lightweight downloader scripts used to fetch and execute the main Mirai client. |
| `DoublePulsar Backdoor` | EternalBlue Exploit | IDS Alert | Indicates scanning or exploitation of the MS17-010 (EternalBlue) vulnerability, often linked to the Prometei botnet. |
| `k.php?a=x86_64` | Prometei Botnet | Download Pattern | A known IOC for the Prometei botnet delivering its ELF binary miner. |

### User / Login Attempts
| Username | Password | Significance |
| :--- | :--- | :--- |
| `345gs5662d34` | `345gs5662d34` | This credential pair, while not a factory default, is consistently used in brute-force dictionaries targeting Polycom IP telephones and other IoT devices. |

### Files Uploaded/Downloaded
| Filename / Pattern | Associated Threat | Purpose |
| :--- | :--- | :--- |
| `arm.urbotnetisass`, `mips.urbotnetisass`, etc. | Mirai Variant | Multi-architecture DDoS botnet client. |
| `arm.uhavenobotsxd`, `mips.uhavenobotsxd`, etc. | Mirai Variant | Multi-architecture DDoS botnet client from a separate campaign. |
| `Mozi.m`, `Mozi.a+varcron` | Mozi Botnet | P2P botnet client. |
| `sora.sh`, `yukari.sh` | Mirai Variant | Dropper scripts to download the main Mirai payload. |
| `w.sh` | Mirai Variant | Generic downloader script observed in multiple campaigns. |
| `k.php?a=x86_64...` | Prometei Botnet | Download pattern for the Prometei XMRig cryptominer. |

### SSH Clients and Servers
| Type | Finding |
| :--- | :--- |
| **Attacker SSH Key** | The "Outlaw Group" consistently deploys a specific RSA public key as a backdoor. Key fingerprint and comment (`mdrfckr`) are the primary indicators. |

---

## OSINT Investigation Summary

### OSINT on Commands Captured
| Command / TTP | OSINT Findings |
| :--- | :--- |
| `chattr` / `lockr` | `chattr` is a standard Linux utility to change file attributes. The command `lockr` appears to be a non-standard script or alias used by the Outlaw Group, likely leveraging `chattr` to make their injected SSH key immutable and evade cleanup scripts. |
| Reconnaissance Commands (`uname`, `lscpu`, etc.) | This is a standard, automated playbook for malware to fingerprint a system. The goal is to identify the architecture for correct payload delivery and to assess the system's resources (especially CPU cores) for cryptomining potential. |

### OSINT on High and Low-Frequency IPs
*(Specific IP analysis was not possible from the summary data, but C2 servers were identified.)*
| IP Address | Association | Status |
| :--- | :--- | :--- |
| `94.154.35.154` | C2 / Malware Host | Known distribution point for the "urbotnetisass" Mirai variant. |
| `141.98.10.66` | C2 / Malware Host | Known distribution point for Mirai variant payloads. |
| `213.209.143.62` | C2 / Malware Host | Known distribution point for Mirai variant downloader scripts (`w.sh`). |

### OSINT on CVEs
| CVE ID | OSINT Findings |
| :--- | :--- |
| **CVE-2025-30208** | This is a real, high-severity arbitrary file read vulnerability in the Vite development server. The "2025" identifier appears to be an error in public CVE trackers for a vulnerability disclosed in 2024. Its appearance in logs shows extremely rapid weaponization by threat actors. |
| **CVE-2023-22527** | A critical (CVSS 10.0) template injection vulnerability in Atlassian Confluence. It allows unauthenticated remote code execution and has been widely exploited by various threat actors, including nation-state groups and ransomware gangs, since its disclosure. |
| **CVE-2018-11776** | A critical remote code execution vulnerability in Apache Struts 2. Despite its age, it is still actively scanned for and exploited, as many public-facing web applications remain unpatched. It is a common entry point for cryptominers and other botnets. |

---

## Key Observations and Anomalies

1.  **Concurrent, Multi-Vector Campaigns:** The honeypot network observed at least four distinct, large-scale botnet campaigns operating simultaneously (Outlaw, Mirai variants, Mozi, Prometei). This indicates a highly active and crowded automated threat landscape where different actors compete for the same pool of vulnerable devices.

2.  **Rapid Weaponization of New Vulnerabilities:** The detection of exploits for **CVE-2025-30208 (Vite)** is a significant finding. It demonstrates that threat actors are monitoring vulnerability disclosures in real-time and integrating proof-of-concept exploits into their automated scanning and exploitation toolkits within days, if not hours.

3.  **Targeting Both Ends of the Value Spectrum:** Attackers are not discriminating in their targets. High-volume, low-effort campaigns continue to target ubiquitous, low-value IoT devices (Mirai, Mozi). Simultaneously, more targeted scans are aimed at high-value enterprise software (Confluence, Struts), where a single compromise can yield significant access or data.

4.  **The "Outlaw Group" Signature:** This group's TTPs are remarkably consistent and almost function as a signature. The `mdrfckr` SSH key and the specific one-line command to inject it serve as a reliable indicator of compromise, suggesting a highly automated and stable attack infrastructure.

5.  **Attacker "Signatures" and Taunts:** The use of explicit comments like `mdrfckr` and taunting filenames such as `uhavenobotsxd` suggests a subculture of brazenness among botnet operators. This can be useful for differentiating between campaigns that might otherwise appear technically similar.

6.  **Persistence of Legacy Exploits:** The high volume of alerts for the DoublePulsar backdoor, linked to the EternalBlue exploit (MS17-010), confirms that legacy, wormable vulnerabilities are still highly effective for propagation years after patches were released. This underscores the significant number of unpatched systems still connected to the internet.

---
