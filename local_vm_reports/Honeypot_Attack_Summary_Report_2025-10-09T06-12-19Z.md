# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T06:09:24Z
**Timeframe:** 2025-10-08T07:02:57Z to 2025-10-09T06:02:06Z

**Files Used:**
- `Honeypot_Attack_Summary_Report_2025-10-08T07:02:57Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T08:02:16Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T09:02:06Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T10:02:00Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T11:02:19Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T12:02:02Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T13:02:08Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T14:02:23Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T16:02:26Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T17:02:09Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T18:02:34Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T19:01:52Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T20:02:17Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T21:01:58Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T22:01:54Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T01:01:51Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T02:02:14Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T04:01:59Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T05:01:59Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T06:02:06Z.md`

## Executive Summary
This report provides a comprehensive analysis of 337,341 attacks recorded across our global honeypot network over the past 24 hours. The data reveals a persistent and high volume of automated threats, primarily targeting SSH, SMB, and VNC services. The **Cowrie** honeypot, simulating SSH and Telnet services, captured the highest number of events, indicating that credential-based attacks remain a primary vector for threat actors.

A significant portion of the observed activity was linked to botnets and automated scanning tools. Attackers consistently performed reconnaissance to identify system architecture before attempting to establish persistence. The most common method for achieving persistence was the injection of a malicious SSH public key into the `authorized_keys` file. This tactic was observed in thousands of instances, often accompanied by the taunt "mdrfckr" within the key's comment field.

The top attacking IP address, **177.126.132.44**, located in Brazil, was responsible for over 1,200 attacks, primarily targeting mail services. This, along with widespread scanning of port 25 (SMTP), suggests a continued focus on compromising email infrastructure for spam or phishing campaigns. Another notable trend was the massive number of scans for port 5900 (VNC) from the IP address **188.253.1.20**, indicating a large-scale search for exposed remote desktop services.

Exploitation of known vulnerabilities remains a key tactic. The network experienced thousands of attempts to leverage the **DoublePulsar backdoor**, associated with the EternalBlue exploit (SMBv1), highlighting that many systems remain unpatched against this critical vulnerability. Other targeted CVEs include older, well-documented vulnerabilities, as well as more recent ones like the Log4j vulnerability (CVE-2021-44228).

Overall, the threat landscape is dominated by automated, opportunistic attacks seeking to expand botnet infrastructures and compromise servers for various malicious purposes, including spam relays and persistent access.

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
| Cowrie | 129,584 |
| Suricata | 47,816 |
| Honeytrap | 46,710 |
| Dionaea | 20,495 |
| Ciscoasa | 28,126 |
| Mailoney | 13,840 |
| Heralding | 4,895 |
| Sentrypeer | 3,362 |
| ConPot | 851 |
| H0neytr4p | 1,023 |
| Tanner | 599 |
| Redishoneypot | 499 |
| Adbhoney | 284 |
| Miniprint | 258 |
| ElasticPot | 148 |
| Honeyaml | 239 |
| ssh-rsa | 96 |
| Dicompot | 48 |
| Wordpot | 9 |
| Ipphoney | 24 |
| Medpot | 3 |

### Top Source Countries
*Due to limitations in the provided logs, country-level data was not consistently available.*

### Top Attacking IPs
| IP Address | Attack Count |
|---|---|
| 116.205.121.146 | 7,725 |
| 188.253.1.20 | 4,192 |
| 5.44.172.76 | 2,376 |
| 190.35.66.46 | 1,849 |
| 201.190.168.218 | 1,771 |
| 165.232.105.167 | 1,500 |
| 178.128.41.154 | 1,494 |
| 111.68.111.216 | 1,430 |
| 161.35.44.220 | 1,419 |
| 170.64.142.60 | 1,342 |
| 136.114.75.193 | 1,252 |
| 45.78.192.92 | 1,247 |
| 177.126.132.44 | 1,239 |
| 5.167.79.4 | 1,251 |
| 81.16.14.2 | 1,477 |
| 209.38.91.18 | 1,533 |
| 20.164.21.26 | 1,253 |
| 23.94.26.58 | 1,694 |
| 103.75.54.141 | 1,529 |
| 188.246.224.87 | 3,289 |

### Top Targeted Ports/Protocols
| Port/Protocol | Attack Count |
|---|---|
| TCP/445 | 11,632 |
| 22 | 14,837 |
| 25 | 12,126 |
| 445 | 15,223 |
| TCP/1080 | 8,067 |
| vnc/5900 | 4,192 |
| 5060 | 3,697 |
| 5903 | 2,272 |
| 8333 | 1,595 |
| TCP/5900 | 1,189 |

### Most Common CVEs
| CVE | Description |
|---|---|
| CVE-2002-0012 / CVE-2002-0013 | Microsoft IIS 5.0 WebDAV Buffer Overflow vulnerabilities |
| CVE-1999-0517 | RPC portmapper remote command execution |
| CVE-2021-3449 | Microsoft Exchange Server Remote Code Execution Vulnerability |
| CVE-2019-11500 | Pulse Secure VPN Unauthenticated File Read |
| CVE-2021-44228 | Apache Log4j Remote Code Execution (Log4Shell) |
| CVE-2022-27255 | Realtek eCos RSDK/MSDK Stack-based Buffer Overflow |
| CVE-2018-11776 | Apache Struts 2 Remote Code Execution |
| CVE-2023-26801 | Zyxel Firewall Command Injection |
| CVE-2005-4050 | Multiple vendor FTP server quote command buffer overflow |
| CVE-2016-20016 | D-Link DIR-645 getcfg.php Unauthenticated Command Execution |
| CVE-2001-0414 | Multiple FTP server NLST command buffer overflow |
| CVE-2024-40891 | (Details not widely published, likely recent) |
| CVE-2020-2551 | Oracle WebLogic Server Unspecified Vulnerability (WLS Core Components) |
| CVE-2018-10561 / CVE-2018-10562 | Dasan GPON Routers Authentication Bypass & Command Injection |

### Commands Attempted by Attackers
| Command | Count |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && ...` | > 500 |
| `uname -a` | > 450 |
| `whoami` | > 450 |
| `cat /proc/cpuinfo | grep name | wc -l` | > 450 |
| `crontab -l` | > 450 |
| `w` | > 450 |
| `top` | > 450 |
| `lscpu | grep Model` | > 450 |
| `df -h | ...` | > 450 |
| `free -m | ...` | > 450 |
| `cd /data/local/tmp; ...; ./boatnet.arm7 arm7; ...` | > 10 |
| `tftp; wget; /bin/busybox ...` | > 10 |
| `rm -rf /data/local/tmp; ...; wget ...; sh w.sh; ...` | > 5 |

### Signatures Triggered
| Signature | Description |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | Attempt to install the DoublePulsar backdoor via SMBv1. |
| ET DROP Dshield Block Listed Source group 1 | Traffic from an IP on the Dshield Top 20 blocklist. |
| ET SCAN NMAP -sS window 1024 | Nmap TCP SYN scan detected. |
| GPL INFO SOCKS Proxy attempt | Attempt to use the server as a SOCKS proxy. |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | RDP traffic on a non-standard port. |
| ET INFO VNC Authentication Failure | Failed VNC login attempt. |
| ET HUNTING RDP Authentication Bypass Attempt | Potential attempt to bypass RDP authentication. |
| ET SCAN Sipsak SIP scan | Scanning for SIP (VoIP) services. |
| ET INFO Python aiohttp User-Agent Observed Inbound | Traffic from a common Python HTTP library, often used in automated tools. |
| ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt | Exploitation attempt against Realtek devices. |

### Users / Login Attempts
| Username / Password |
|---|
| 345gs5662d34 / 345gs5662d34 |
| root / (various common passwords) |
| admin / (various common passwords) |
| sysadmin / sysadmin@1 |
| supervisor / (various common passwords) |
| ubuntu / 3245gs5662d34 |
| guest / (various common passwords) |
| appuser / (empty password) |
| vpn / vpn! |
| support / (various common passwords) |

### Files Uploaded/Downloaded
| Filename | Type |
|---|---|
| `wget.sh` | Shell Script (Downloader) |
| `w.sh` | Shell Script (Downloader) |
| `c.sh` | Shell Script (Downloader) |
| `Mozi.a+varcron` | Botnet Binary (Mozi) |
| `boatnet.arm7` | Botnet Binary (Boatnet) |
| `mips`, `parm`, `px86_64`, etc. | Malware binaries for different architectures |
| Various `.php` files | Webshells / Exploits |

### HTTP User-Agents
*No significant or consistent HTTP User-Agents were recorded, indicating that most attacks were not web-based or used non-standard clients.*

### SSH Clients and Servers
*No specific SSH client or server versions were logged, suggesting the use of custom or non-standard SSH libraries by attackers.*

### Top Attacker AS Organizations
*Due to limitations in the log data, AS organization information was not available.*

### OSINT Information
| Item | OSINT Findings |
|---|---|
| **177.126.132.44** | Registered to "Net Aki Internet Ltda" in Brazil (AS262343). Multiple abuse reports on AbuseIPDB for brute-force attacks against SSH (port 22). Flagged as a malicious IP and "exploited host". |

## Key Observations and Anomalies

1.  **The "mdrfckr" SSH Key Campaign:** A highly aggressive and widespread campaign was observed where attackers, after gaining initial access, would execute a one-liner command to delete the existing `.ssh` directory and replace it with a new one containing their public SSH key. The key consistently included the comment "mdrfckr". This indicates a large, coordinated effort to build a persistent botnet.

2.  **Massive VNC Scanning:** The IP address **188.253.1.20** was responsible for over 4,000 VNC authentication failures in a short period. This represents a massive, automated scan for exposed VNC servers, which are often poorly secured and can provide direct remote control of a system.

3.  **Prevalence of DoublePulsar:** Despite being patched years ago, the EternalBlue vulnerability (exploited by DoublePulsar) remains a top target. Thousands of events were logged attempting to use this exploit, highlighting a significant number of unpatched legacy systems still connected to the internet.

4.  **Botnet Recruitment via Script Downloads:** Attackers frequently used `wget`, `curl`, and `tftp` to download and execute shell scripts. These scripts often acted as droppers for multi-architecture malware payloads (e.g., for ARM, MIPS, x86), a clear sign of botnet propagation targeting a wide range of devices, including IoT.

5.  **Targeted Application Credentials:** While many login attempts used generic defaults, there were also specific attempts targeting applications like `minecraft`, `erpnext`, `jenkins`, and `bitwarden`. This suggests that some attackers are using more targeted credential lists based on known software stacks.

6.  **SOCKS Proxy Scanning:** A massive scan for open SOCKS proxies on TCP port 1080 was initiated by **116.205.121.146**. Compromised SOCKS proxies are valuable to attackers for anonymizing their traffic and launching further attacks.

This concludes the Honeypot Attack Summary Report.
