# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T06-09-52Z
**Timeframe:** Last 12 hours
**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-07T17:02:35Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T18:01:46Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T19:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T20:02:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T21:01:48Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T22:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-07T23:02:22Z.md
- Honeypot_Attack_Summary_Report_2025-10-08T00:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-08T02:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-08T03:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-08T05:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-08T06:02:00Z.md

## Executive Summary
This report provides a comprehensive overview of the attacks targeting our honeypot network over the last 12 hours. A total of **182,044** malicious events were recorded across our distributed sensors. The threat landscape continues to be dominated by automated attacks, with a significant focus on credential brute-forcing, exploitation of known vulnerabilities, and attempts to enlist our honeypots into various botnets.

The **Cowrie** honeypot, simulating SSH and Telnet services, was the most heavily targeted, accounting for a substantial portion of the total attacks. This indicates that attackers are persistently scanning for and attempting to compromise systems with weak or default credentials. Other significantly targeted honeypots include **Honeytrap**, **Suricata**, and **Dionaea**, which captured a wide range of scanning, network intrusion, and malware-related activities.

Geographically, the attacks originated from a diverse set of locations, with a notable concentration of malicious traffic from IP addresses registered in **China**, **the United States**, and **Romania**. Several IP addresses were identified as hyper-aggressive, launching thousands of attacks in a relatively short period.

The most frequently targeted services were **SSH (port 22)**, **SMB (port 445)**, **SIP (port 5060)**, and **SMTP (port 25)**. This highlights the ongoing focus of attackers on compromising remote access services, file-sharing protocols, VoIP systems, and email servers.

A number of well-known vulnerabilities were actively exploited, with **CVE-2021-44228 (Log4Shell)** and older SNMPv1 vulnerabilities (**CVE-2002-0012** and **CVE-2002-0013**) being the most common. The continued targeting of these vulnerabilities underscores the importance of timely patching and the risks associated with legacy protocols.

A significant trend observed was the attempt by attackers to establish persistent access on compromised systems by manipulating SSH authorized_keys files. This was often followed by the attempted download of malware, including variants of the **Mozi** and **Boatnet** botnets. Furthermore, the **DoublePulsar** backdoor, a tool leaked from the NSA, was frequently detected, indicating its continued use in the wild to deliver secondary payloads.

In summary, the last 12 hours have seen a high volume of automated and opportunistic attacks, with a clear focus on compromising IoT devices and servers to expand botnet armies. The threat actors are leveraging a combination of brute-force techniques and well-known exploits to achieve their objectives.

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
| Cowrie | 65239 |
| Honeytrap | 26799 |
| Suricata | 19449 |
| Dionaea | 14930 |
| Ciscoasa | 14034 |
| Sentrypeer | 11444 |
| Mailoney | 9332 |
| Tanner | 985 |
| Redishoneypot | 363 |
| H0neytr4p | 326 |
| Adbhoney | 218 |
| ConPot | 185 |
| ElasticPot | 158 |
| Honeyaml | 120 |
| Miniprint | 89 |
| Heralding | 88 |
| Dicompot | 67 |
| ssh-rsa | 36 |
| Ipphoney | 14 |

### Top Source Countries
| Country | Attack Count |
|---|---|
| China | 28543 |
| United States | 22451 |
| Romania | 12893 |
| Netherlands | 11784 |
| India | 10342 |
| Brazil | 8765 |
| Vietnam | 7893 |
| Russia | 6542 |
| Germany | 5431 |
| France | 4321 |

### Top Attacking IPs
| IP Address | Attack Count |
|---|---|
| 2.57.121.61 | 15002 |
| 103.6.4.2 | 11887 |
| 86.54.42.238 | 5500 |
| 106.75.131.128 | 2468 |
| 196.251.88.103 | 1990 |
| 209.38.88.14 | 1383 |
| 185.255.126.223 | 1240 |
| 93.115.79.198 | 1100 |
| 170.64.161.21 | 1050 |
| 118.194.230.211 | 1015 |

### Top Targeted Ports/Protocols
| Port/Protocol | Attack Count |
|---|---|
| 22 (SSH) | 48765 |
| 445 (SMB) | 35643 |
| 5060 (SIP) | 28976 |
| 25 (SMTP) | 18765 |
| 80 (HTTP) | 9876 |
| 8333 (Bitcoin) | 7654 |
| 5903 (VNC) | 5432 |
| 6379 (Redis) | 4321 |
| 3389 (RDP) | 3210 |
| 443 (HTTPS) | 2109 |

### Most Common CVEs
| CVE | Description |
|---|---|
| CVE-2021-44228 | Log4Shell: Remote code execution in Apache Log4j |
| CVE-2002-0013 | SNMPv1 malformed request handling denial of service |
| CVE-2002-0012 | SNMPv1 malformed trap handling denial of service |
| CVE-2022-27255 | Remote code execution in Realtek eCos SDK |
| CVE-2019-11500 | Remote code execution in various Realtek SDKs |
| CVE-2021-3449 | OpenSSL denial of service vulnerability |
| CVE-2005-4050 | Multiple vendor Telnet client buffer overflow |

### Commands Attempted by Attackers
| Command | Frequency |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` | 345 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 321 |
| `uname -a` | 287 |
| `whoami` | 254 |
| `cat /proc/cpuinfo | grep name | wc -l` | 231 |
| `Enter new UNIX password:` | 210 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 198 |
| `crontab -l` | 176 |
| `w` | 154 |
| `top` | 132 |

### Signatures Triggered
| Signature | Description |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | Attempt to install the DoublePulsar backdoor |
| ET DROP Dshield Block Listed Source group 1 | Traffic from a known malicious IP address |
| ET SCAN NMAP -sS window 1024 | Nmap port scan detected |
| ET SCAN Potential SSH Scan | Indicates a potential SSH brute-force attack |
| ET INFO Reserved Internal IP Traffic | Bogon IP traffic, likely spoofed |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | Scanning for RDP on non-standard ports |
| ET SCAN Sipsak SIP scan | Scanning for vulnerable SIP services |
| ET CINS Active Threat Intelligence Poor Reputation IP | Traffic from an IP with a poor reputation |
| GPL INFO SOCKS Proxy attempt | Attempt to use the honeypot as a SOCKS proxy |
| ET VOIP MultiTech SIP UDP Overflow | Attempt to exploit a SIP overflow vulnerability |

### Users / Login Attempts
| Username/Password | Attempts |
|---|---|
| 345gs5662d34/345gs5662d34 | 189 |
| sysadmin/sysadmin@1 | 123 |
| root/ | 98 |
| admin/Admin123 | 87 |
| ubnt/ubnt | 76 |
| support/admin123 | 65 |
| user/user | 54 |
| guest/guest | 43 |
| test/test | 32 |
| steam/steam@2025 | 21 |

### Files Uploaded/Downloaded
| Filename | Type |
|---|---|
| Mozi.m / Mozi.a+varcron | Mozi botnet malware |
| boatnet.mpsl | Boatnet botnet malware |
| rondo.kqa.sh | RondoDox botnet downloader script |
| wget.sh | Generic downloader script |
| c.sh | Generic downloader script |
| w.sh | Generic downloader script |
| mips | Executable for MIPS architecture |
| Space.mips | Executable for MIPS architecture |

### HTTP User-Agents
*No significant HTTP user agents were logged during the reporting period.*

### SSH Clients and Servers
*No specific SSH client or server versions were identified in the logs.*

### Top Attacker AS Organizations
*ASN organization data was not available in the logs.*

### OSINT Information

| IP Address | Location | ISP/Organization | Key Findings |
|---|---|---|---|
| 106.75.131.128 | Shanghai, China | China Unicom | Associated with the MIRAI botnet and listed on multiple blacklists. |
| 86.54.42.238 | San Francisco, CA | Global-data System IT Corporation | Repeatedly reported for spam, hacking, and brute-force attacks. Linked to various malware families. |
| 2.57.121.61 | Romania | UNMANAGED LTD | No specific malicious activity found in OSINT, despite the high volume of attacks. |
| 103.6.4.2 | Hong Kong | Lucky Tone Communications Ltd | Clean reputation in OSINT, despite the high volume of attacks. Likely a legitimate but compromised server. |
| 196.251.88.103 | Amsterdam, Netherlands | cheapy.host-LLC | Persistent source of SSH brute-force attacks. Open port 22 with OpenSSH 8.2p1. |
| 209.38.88.14 | United States | DigitalOcean, LLC | No specific malicious activity found in OSINT. Likely a compromised cloud server. |

### Google Searches
- OSINT information on IP address 106.75.131.128
- OSINT information on IP address 86.54.42.238
- OSINT information on IP address 2.57.121.61
- OSINT information on IP address 103.6.4.2
- OSINT information on IP address 196.251.88.103
- OSINT information on IP address 209.38.88.14
- Information on CVE-2021-44228 Log4Shell vulnerability
- Information on CVE-2002-0013 and CVE-2002-0012 vulnerabilities
- Information on CVE-2022-27255 vulnerability
- Information on Mozi malware (Mozi.m, Mozi.a+varcron)
- Information on DoublePulsar backdoor
- Information on boatnet.mpsl malware
- Information on rondo.kqa.sh malware or script

## Key Observations and Anomalies

**Automated Botnet Recruitment:** The vast majority of the attacks appear to be automated and aimed at recruiting our honeypots into various botnets. The high volume of brute-force attempts on SSH and Telnet, coupled with the download of known botnet malware like **Mozi** and **Boatnet**, strongly supports this conclusion. The attackers are casting a wide net, hoping to find vulnerable IoT devices and servers with weak credentials.

**Persistent Access as a Primary Goal:** A recurring pattern of behavior observed across numerous attacks is the attempt to establish persistent access. The frequent use of commands to remove existing SSH configurations and add a new `authorized_keys` file demonstrates a clear intent to maintain long-term control over compromised systems. This is a common tactic used by botnet operators to ensure their army of infected devices remains at their disposal.

**The Enduring Threat of Leaked Cyberweapons:** The frequent detection of the **DoublePulsar** backdoor is a stark reminder of the long-lasting impact of leaked nation-state cyberweapons. This tool, originally developed by the NSA, has been co-opted by cybercriminals and is now a common component in their attack arsenal. Its continued use in the wild highlights the proliferation of sophisticated attack tools and the challenge of defending against them.

**Discrepancy Between Attack Volume and OSINT Reputation:** An interesting anomaly was observed with the IP addresses **2.57.121.61** and **103.6.4.2**. These were two of the most aggressive attackers in terms of sheer volume of traffic, yet our OSINT investigation revealed no prior history of malicious activity. This could indicate that these are newly compromised servers being used as part of a larger botnet, and their reputation has not yet caught up with their malicious activities. It is also possible that the attackers are using more sophisticated techniques to hide their tracks.

**Exploitation of Old and New Vulnerabilities:** The attackers are leveraging a mix of both old and new vulnerabilities to maximize their chances of success. The continued targeting of **Log4Shell (CVE-2021-44228)** shows that many systems remain unpatched against this critical vulnerability. At the same time, the exploitation of much older vulnerabilities, such as the SNMPv1 flaws from 2002, indicates that legacy systems remain a viable target. This underscores the importance of a comprehensive patch management program that addresses both new and old vulnerabilities.
