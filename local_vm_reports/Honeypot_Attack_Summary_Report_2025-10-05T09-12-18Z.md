# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T09-11-37Z
**Timeframe:** 2025-10-03T21:01:57Z to 2025-10-05T08:02:30Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-03T21:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T22:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T23:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T00:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T01:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T02:02:17Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T03:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T04:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T05:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T09:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T10:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T11:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T12:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T13:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T14:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T15:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T16:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T18:02:11Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T19:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T20:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T21:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-04T23:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T00:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T01:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T02:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T03:02:32Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T04:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T05:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T06:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T08:02:30Z.md

### Executive Summary
This report provides a comprehensive summary of malicious activities recorded by the honeypot network over a 38-hour period. A total of **334,166** events were analyzed. The overwhelming majority of attacks were automated, focusing on common vulnerabilities and weak credentials. The Cowrie honeypot, simulating SSH and Telnet services, captured the most traffic, highlighting the relentless nature of brute-force and credential-stuffing attacks. Other significantly targeted services included SMB (Dionaea), mail protocols (Mailoney), and Cisco ASA firewalls (Ciscoasa).

Attack patterns reveal a consistent methodology: broad scanning for open ports, followed by attempts to exploit known vulnerabilities and brute-force credentials. Upon gaining initial access, attackers frequently executed a series of reconnaissance commands to profile the system. A recurring and highly concerning tactic was the attempt to install persistent backdoors by adding a specific SSH public key to the `authorized_keys` file. Furthermore, multiple attackers attempted to download and execute malicious scripts and binaries, including variants of the Mirai botnet, Mozi, and payloads delivered via the DoublePulsar backdoor.

The top attacking IP addresses originate from a diverse range of countries, with several IPs exhibiting extremely aggressive behavior, suggesting they are part of botnets or dedicated attack infrastructure. The most targeted vulnerabilities were often older, indicating that many systems remain unpatched against well-known exploits.

### Detailed Analysis

#### Our IPs
| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

#### Attacks by Honeypot
| Honeypot | Attack Count |
|---|---|
| Cowrie | 148,897 |
| Suricata | 35,422 |
| Dionaea | 33,267 |
| Ciscoasa | 47,816 |
| Mailoney | 41,200 |
| Honeytrap | 22,236 |
| Sentrypeer | 9,996 |
| Tanner | 2,126 |
| H0neytr4p | 1,515 |
| Adbhoney | 1,023 |
| Redishoneypot | 794 |
| ConPot | 652 |
| Heralding | 549 |
| Miniprint | 425 |
| Honeyaml | 382 |
| Dicompot | 258 |
| ElasticPot | 204 |
| Ipphoney | 54 |
| ssh-rsa | 68 |
| Wordpot | 4 |
| Medpot | 6 |

#### Top Source Countries
*Due to the nature of the logs, country information was not available.*

#### Top Attacking IPs
| IP Address | Attack Count |
|---|---|
| 176.65.141.117 | 15,390 |
| 86.54.42.238 | 10,733 |
| 15.235.131.242 | 6,854 |
| 45.234.176.18 | 6,707 |
| 170.64.185.131 | 5,166 |
| 113.187.69.246 | 4,605 |
| 83.168.107.46 | 3,938 |
| 62.176.70.101 | 3,747 |
| 172.86.95.98 | 3,551 |
| 81.4.194.194 | 3,046 |

#### Top Targeted Ports/Protocols
| Port/Protocol | Attack Count |
|---|---|
| 22 (SSH) | 71,833 |
| 25 (SMTP) | 41,194 |
| 445 (SMB) | 36,959 |
| 5060 (SIP) | 9,996 |
| 443 (HTTPS) | 2,897 |
| 80 (HTTP) | 2,347 |
| 3306 (MySQL) | 1,185 |
| 6379 (Redis) | 794 |
| 23 (Telnet) | 1,162 |
| 1433 (MSSQL) | 599 |

#### Most Common CVEs
| CVE | Description |
|---|---|
| CVE-2005-4050 | Buffer overflow in multiple Multi-Tech Systems MultiVOIP devices. |
| CVE-2002-0013 | Vulnerabilities in SNMPv1 request handling. |
| CVE-2002-0012 | Vulnerabilities in SNMPv1 trap handling. |
| CVE-2019-11500 | Out-of-bounds heap memory write in Dovecot and Pigeonhole. |
| CVE-2021-3449 | Denial of service vulnerability in OpenSSL. |
| CVE-2024-3721 | OS command injection vulnerability in TBK DVR devices. |
| CVE-2006-2369 | Authentication bypass vulnerability in RealVNC. |
| CVE-2016-5696 | TCP vulnerability in the Linux kernel. |

#### Commands Attempted by Attackers
| Command | Frequency |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` | 808 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 808 |
| `lockr -ia .ssh` | 808 |
| `uname -a` | 694 |
| `whoami` | 679 |
| `cat /proc/cpuinfo | grep name | wc -l` | 664 |
| `Enter new UNIX password:` | 509 |
| `crontab -l` | 634 |
| `w` | 620 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 609 |

#### Signatures Triggered
| Signature | Frequency |
|---|---|
| ET DROP Dshield Block Listed Source group 1 | 9,963 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 8,004 |
| ET SCAN NMAP -sS window 1024 | 2,884 |
| ET INFO Reserved Internal IP Traffic | 1,173 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 926 |
| ET VOIP MultiTech SIP UDP Overflow | 411 |
| ET SCAN Potential SSH Scan | 352 |
| ET CINS Active Threat Intelligence Poor Reputation IP (various groups) | 988 |
| ET DROP Spamhaus DROP Listed Traffic Inbound (various groups) | 681 |
| GPL INFO SOCKS Proxy attempt | 451 |

#### Users / Login Attempts
| Username/Password |
|---|
| 345gs5662d34/345gs5662d34 |
| root/nPSpP4PBW0 |
| root/3245gs5662d34 |
| a2billinguser/ |
| test/zhbjETuyMffoL8F |
| root/LeitboGi0ro |
| root/2glehe5t24th1issZs |
| superadmin/admin123 |
| novinhost/novinhost.org |
| admin/admin |

#### Files Uploaded/Downloaded
| Filename |
|---|
| wget.sh |
| w.sh |
| c.sh |
| arm.urbotnetisass |
| arm5.urbotnetisass |
| arm6.urbotnetisass |
| arm7.urbotnetisass |
| x86_32.urbotnetisass |
| mips.urbotnetisass |
| mipsel.urbotnetisass |
| boatnet.mpsl |
| Mozi.a+varcron |
| UnHAnaAW.mpsl |

#### HTTP User-Agents
*No significant user agents were logged during this period.*

#### SSH Clients and Servers
*No significant SSH clients or servers were logged during this period.*

#### Top Attacker AS Organizations
*Due to the nature of the logs, AS organization information was not available.*

### Google Searches

#### Top Attacking IPs
- **38.34.18.221:** No specific information available.
- **176.65.141.117:** Associated with Optibounce, LLC (US), reported for brute-force attacks.
- **86.54.42.238:** Global-Data System IT Corporation (Switzerland), high confidence of abuse, linked to RDP attacks and malware.
- **113.187.69.246:** No public information on malicious activity.
- **81.4.194.194:** No public information on malicious activity.
- **62.176.70.101:** BTC Broadband Services (Bulgaria).
- **45.234.176.18:** MAFREDINE TELECOMUNICACOES EIR (Brazil), extensively reported for various malicious activities including SSH brute-force, DDoS, phishing, and spam.
- **159.223.50.114:** Data center/web hosting service (Singapore), recently reported for malicious activity.
- **15.235.131.242:** Associated with hostnames `olivia.cocks.lab.go4labs.net` and `leonard.flowers.lab.go4labs.net`.
- **20.2.136.52:** Microsoft Corporation, very high number of abuse reports (626) with 100% confidence of abuse.

#### Most Common CVEs
- **CVE-2002-0013 & CVE-2002-0012:** Vulnerabilities in SNMPv1 that can lead to denial of service or privilege escalation.
- **CVE-2019-11500:** A flaw in Dovecot that can lead to remote code execution.
- **CVE-2021-3449:** A denial of service vulnerability in OpenSSL.
- **CVE-2024-3721:** A critical OS command injection vulnerability in TBK DVR devices.
- **CVE-2006-2369:** An authentication bypass vulnerability in RealVNC.
- **CVE-2016-5696:** A flaw in the Linux kernel's TCP implementation that can be used to hijack TCP sessions.
- **CVE-2005-4050:** A buffer overflow vulnerability in multiple Multi-Tech Systems MultiVOIP devices.

#### Malware and Botnets
- **urbotnetisass:** A variant of the Mirai botnet, a Trojan that targets Linux-based systems.
- **boatnet:** A newer botnet family that incorporates source code from Mirai.
- **Mozi:** A resilient peer-to-peer (P2P) botnet that primarily targets IoT devices.
- **DoublePulsar:** A sophisticated backdoor implant tool developed by the NSA and leaked to the public. It was used in the WannaCry ransomware attack.

### Key Observations and Anomalies

- **Aggressive and Persistent Attackers:** A small number of IP addresses were responsible for a disproportionately large number of attacks, indicating either highly motivated attackers or compromised systems being used as part of a botnet.
- **Automated Attack Campaigns:** The repetition of identical commands across multiple sessions and from different IP addresses strongly suggests the use of automated scripts for reconnaissance, exploitation, and post-exploitation activities.
- **Focus on Persistence:** The most common post-exploitation tactic was the attempt to add a specific SSH public key to the `authorized_keys` file. This is a clear indication that attackers are prioritizing long-term access to compromised systems.
- **Malware Deployment:** A variety of malware was observed being downloaded and executed, including variants of the Mirai botnet and Mozi. The detection of the DoublePulsar backdoor signature is particularly concerning, as it indicates attempts to exploit a powerful, government-developed cyber-weapon.
- **Exploitation of Old Vulnerabilities:** The continued targeting of older CVEs highlights the fact that many systems remain unpatched and vulnerable to well-known exploits.
- **Lack of Sophistication (in some areas):** The absence of unique HTTP User-Agents and SSH client information suggests that many of the attacks are low-effort, automated scans that do not bother to spoof these values.
- **Targeting of Critical Infrastructure:** The high volume of attacks on mail servers, firewalls, and VoIP services demonstrates the potential for disruption to critical business and communication systems.
- **Microsoft IP with High Abuse Reports:** The IP address 20.2.136.52, belonging to Microsoft Corporation, had an extremely high number of abuse reports. This is likely a compromised Azure instance being used for malicious activities.
