# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T06-17-10Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-10-08T06:02:00Z

**Files Used to Generate Report:**
- All `Honeypot_Attack_Summary_Report_*.md` files generated and provided between 2025-09-28 and 2025-10-08.

## Executive Summary
This report provides a comprehensive analysis of malicious activities recorded across our distributed honeypot network over the specified timeframe. A total of over **1.5 million** malicious events were captured, revealing a relentless and highly automated threat landscape dominated by globally distributed botnets. The primary objectives of these attackers were clear: credential harvesting, botnet propagation for DDoS attacks and cryptomining, and establishing persistent backdoors for future exploitation.

The vast majority of attacks targeted remote access services, with the **Cowrie** (SSH/Telnet) honeypot absorbing the highest volume of traffic. This indicates a persistent, industrial-scale campaign of brute-force and credential-stuffing attacks. Network scanning and exploit attempts were also rampant, with **Honeytrap**, **Suricata**, and **Dionaea** honeypots collectively recording hundreds of thousands of events.

The analysis identified several major, concurrent attack campaigns:
1.  **"Outlaw" Group Brute-Force Campaign:** A significant portion of successful SSH breaches were followed by a clear post-exploitation playbook attributed to the "Outlaw" hacking group. This was identified by its unique signature: the injection of an SSH key with the comment **"mdrfckr"** and the use of a custom `lockr` command to establish immutable persistence.
2.  **IoT Botnet Propagation (Mirai, Mozi, Rondo):** Multiple distinct campaigns were observed attempting to infect the honeypots with IoT-focused malware. The most prominent was the **`urbotnetisass`** malware, a variant of the **Mirai botnet**, which was consistently downloaded from a dedicated command-and-control server. Payloads for various architectures (ARM, MIPS, x86) were deployed, alongside droppers for the **Mozi** and **RondoDox** botnets, confirming a broad effort to compromise a diverse range of devices.
3.  **Pervasive SMB Worm Activity:** A massive volume of traffic continuously targeted port 445 (SMB). Intrusion detection signatures frequently identified these attacks as attempts to install the **DoublePulsar backdoor**, indicating that automated worms are still actively scanning the internet for systems vulnerable to the **EternalBlue** (MS17-010) exploit.
4.  **Prometei Cryptomining Botnet:** A sophisticated, multi-stage botnet was identified through the download of a file named `k.php`. This is a known TTP of the Prometei botnet, which aims to install the XMRig Monero miner and steal credentials.

The threat landscape showed a dual focus on vulnerabilities. Attackers relentlessly scanned for modern, high-impact vulnerabilities like **Log4Shell (CVE-2021-44228)**, while also achieving success by exploiting legacy CVEs, some dating back to 1999, against unpatched systems. In summary, the honeypot network is under constant, automated assault from organized botnet campaigns focused on resource hijacking and propagation.

## Detailed Analysis

### Our IPs (table)
| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by honeypot (table)
| Honeypot | Total Attack Count (Approx.) |
|---|---|
| Cowrie | 750,000+ |
| Honeytrap | 250,000+ |
| Suricata | 200,000+ |
| Dionaea | 150,000+ |
| Ciscoasa | 150,000+ |
| Sentrypeer | 100,000+ |
| Mailoney | 100,000+ |
| Tanner | 10,000+ |
| H0neytr4p | 5,000+ |
| Adbhoney | 5,000+ |
| Other | 20,000+ |

### Top source countries (table)
| Country |
|---|
| United States |
| China |
| Russia |
| Germany |
| Netherlands |
| Vietnam |
| Brazil |
| Indonesia |
| India |
| France |
| United Kingdom|
| South Africa |

### Top attacking IPs (table)
| IP Address | Notes / Associated Activity |
|---|---|
| 162.244.80.233 | Minecraft Server (USA), extremely high volume scanning. |
| 176.65.141.117 | Optibounce LLC (Germany), linked to Mirai botnet activity. |
| 86.54.42.238 | Global-Data System (Seychelles), on Spamhaus blacklist. |
| 39.107.106.103 | Alibaba Cloud (China), known for spam, brute-force, DDoS. |
| 160.25.118.10 | Indonesia, extremely aggressive SSH brute-force attacks. |
| 137.184.169.79 | DigitalOcean (Canada), linked to phishing. |
| 147.182.150.164 | DigitalOcean (USA), blacklisted for SSH abuse. |
| 20.2.136.52 | Microsoft Azure (Hong Kong), extremely high abuse reports. |
| 45.234.176.18 | Mafredine Telecom (Brazil), reported for SSH brute-force. |
| 92.205.59.208 | Host Europe GmbH (France), massive volume of SIP scanning. |

### Top targeted ports/protocols (table)
| Port/Protocol | Service | Primary Threat |
|---|---|---|
| 22 (TCP) | SSH | Brute-Force, Credential Stuffing, Botnet Propagation |
| 445 (TCP) | SMB | EternalBlue/DoublePulsar Exploitation, Worm Propagation |
| 5060 (TCP/UDP) | SIP | VoIP Scanning, Exploitation of CVE-2005-4050 |
| 25 (TCP) | SMTP | Spam Relay Abuse, Credential Harvesting |
| 8333 (TCP) | Bitcoin | Probing for vulnerable Bitcoin nodes |
| 23 (TCP) | Telnet | Brute-Force attacks on IoT/Network devices |
| 80 (TCP) | HTTP | Web Scanning, Log4Shell, Webshell deployment |
| 6379 (TCP) | Redis | Probing for exposed, unauthenticated Redis instances |
| 1433 (TCP) | MSSQL | Brute-Force, SQL Injection |
| 443 (TCP) | HTTPS | Web Scanning, Firewall/VPN Exploits (e.g., CVE-2018-13379) |

### Most common CVEs (table)
| CVE | Description |
|---|---|
| CVE-2021-44228 | Log4Shell: Remote Code Execution in Apache Log4j |
| CVE-2017-0144 | EternalBlue: RCE in Microsoft SMB, used to deliver DoublePulsar |
| CVE-2005-4050 | Buffer overflow in Multi-Tech VoIP devices |
| CVE-2022-27255 | Remote Code Execution in Realtek SDK for IoT devices |
| CVE-2002-0012 / 13 | Legacy vulnerabilities in SNMPv1 request handling |
| CVE-1999-0517 | Use of default community strings in SNMP |
| CVE-2018-13379 | Fortinet FortiGate SSL VPN Path Traversal |
| CVE-2019-11500 | Vulnerability in Dovecot email server |
| CVE-2024-3721 | Command Injection in TBK DVR devices |
| CVE-2024-4577 | PHP-CGI Argument Injection |

### Commands attempted by attackers (table)
| Command | Purpose / TTP |
|---|---|
| `cd ~ && rm -rf .ssh && ... authorized_keys` | Persistence via SSH key injection (Outlaw "mdrfckr" signature) |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | Defense Evasion: Making SSH key immutable (Outlaw TTP) |
| `cd /data/local/tmp/; rm *; busybox wget ...` | Payload Delivery: Downloading Mirai/Mozi variants on IoT devices |
| `uname -a`, `whoami`, `lscpu`, `crontab -l` | Discovery: System and environment reconnaissance |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh` | Defense Evasion: Removing competing malware ("Malware Cockroaching")|
| `Enter new UNIX password:` | Privilege Escalation attempt |
| `nohup bash -c "exec 6<>/dev/tcp/...` | Execution: Establishing a reverse shell |
| `pm install /data/local/tmp/ufo.apk` | Execution: Installing Android cryptominer |

### Signatures triggered (table)
| Signature | Associated Threat |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation | EternalBlue (MS17-010) exploit attempt |
| ET DROP Dshield Block Listed Source group 1 | Traffic from known malicious IPs |
| ET SCAN NMAP -sS window 1024 | Active network port scanning |
| ET EXPLOIT Apache Obfuscated log4j RCE Attempt | Log4Shell (CVE-2021-44228) exploit attempt |
| ET SCAN Potential SSH Scan | SSH brute-force or credential stuffing activity |
| ET VOIP REGISTER Message Flood / Sipsak SIP scan | Scanning for vulnerable VoIP systems |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | Scanning for exposed RDP services |

### Users / login attempts (table)
| Username/Password | Significance |
|---|---|
| `345gs5662d34` / `345gs5662d34` | Default credentials for Polycom CX600 IP phones |
| `root` / `nPSpP4PBW0` | Common brute-force pair from automated toolkits |
| `test` / `zhbjETuyMffoL8F` | Common brute-force pair from automated toolkits |
| `foundry` / `foundry` | Default credentials for Foundry VTT software |
| `seekcy` / `Joysuch@Locate2024` | Known credential pair used in automated SSH attacks |
| `root` / `3245gs5662d34` | Common brute-force pair, re-using a known password string |
| `sa` / `(blank)` | Attempt to access MSSQL with a blank `sa` password |
| `admin` / `admin` | Common default credentials |
| `root` / `123456` | Common weak password |
| `pi` / `raspberry` | Default credentials for Raspberry Pi devices |

### Files uploaded/downloaded (table)
| Filename | Type / Associated Threat |
|---|---|
| `arm.urbotnetisass` (and variants) | Mirai Botnet ELF Binary for ARM architecture |
| `mips.urbotnetisass` (and variants) | Mirai Botnet ELF Binary for MIPS architecture |
| `x86_32.urbotnetisass` | Mirai Botnet ELF Binary for x86 architecture |
| `Mozi.m` / `Mozi.a+varcron` | Mozi P2P Botnet ELF Binary |
| `boatnet.mpsl` | Boatnet (Mirai/Gafgyt variant) ELF Binary |
| `rondo.*.sh` | RondoDox Botnet Dropper Script |
| `k.php?a=x86_64...` | Prometei Botnet ELF Binary (Cryptominer) |
| `w.sh`, `c.sh`, `wget.sh` | Generic Malware Dropper Scripts |
| `catgirls;` | Unknown/Anomalous command or payload |
| `ufo.apk` | Android Cryptocurrency Miner |

### HTTP User-Agents (table)
| User-Agent | Notes |
|---|---|
| zgrab/0.x | Go-based application security scanner. |
| python-requests/2.x | Common library used in many scanning/attack scripts. |
| masscan/1.x | High-speed port scanner. |
| Nmap Scripting Engine | Nmap's NSE, used for advanced scanning and vulnerability checks.|

### SSH clients and servers (two tables)
*No consistent or significant data was recorded for specific SSH client or server versions across the observed period.*

### Top attacker AS organizations (table)
| AS Organization | Associated Activity / Notes |
|---|---|
| AS14061 (DigitalOcean, LLC) | Major source of malicious traffic from rented/compromised VPS. |
| AS16276 (OVH SAS) | Major hosting provider frequently abused by threat actors. |
| AS396982 (Google LLC) | Google Cloud Platform, often used for scanning and attacks. |
| AS16509 (AMAZON-02) | Amazon Web Services, abused for malicious hosting. |
| AS45102 (Alibaba Cloud) | Alibaba Cloud infrastructure used for attacks. |
| AS36352 (HostPapa) | Hosting provider linked to high-volume scanning. |

### OSINT Information (table)

| IP Address | Location | ISP/Organization | Key Findings |
|---|---|---|---|
| 176.65.141.117 | Germany | Optibounce, LLC | Associated with the MIRAI botnet and listed on multiple blacklists. |
| 86.54.42.238 | Seychelles | Global-data System | On Spamhaus SBL/XBL for spam and exploits. Reverse DNS suggests a compromised RDP server. |
| 20.2.136.52 | Hong Kong | Microsoft Azure | Extremely high abuse history (626+ reports) for port scanning and brute-force attacks. |
| 45.234.176.18 | Brazil | Mafredine Telecom | Extensively reported for SSH brute-force, DDoS, phishing, and spam. |
| 172.86.95.98 | USA | FranTech Solutions | Conflicting profile: associated with a cybersecurity company (UM-Labs) but also on malicious IP blocklists. Highly anomalous. |
| 103.179.56.29 | Indonesia | PT Cloud Hosting | Directly listed on a blocklist associated with the MIRAI botnet. |

## Key Observations and Anomalies

**1. "Outlaw" Botnet Campaign Signature:** A significant cluster of activity is attributed to the "Outlaw" hacking group. Their TTPs are highly consistent and easily identifiable: gaining access via SSH brute-force, then immediately executing a one-line command to delete the existing `.ssh` directory and inject a new `authorized_keys` file. This key is tagged with the unique comment **"mdrfckr"**. The script then uses a custom `lockr` command to make the key immutable. This is a clear, reliable signature of this threat actor, whose primary motivation is deploying cryptominers.

**2. Multi-Botnet Infection Attempts:** Attackers are deploying a wide range of botnet malware, often in competition. The consistent downloads of **`urbotnetisass` (Mirai)**, **`Mozi.m`**, **`rondo.sh` (RondoDox)**, and **`k.php` (Prometei)** indicate that our honeypots are being targeted by multiple, distinct campaigns simultaneously. Some scripts even include commands to kill processes of rival malware, a behavior known as "malware cockroaching."

**3. Anomalous High-Volume Scanners:** Several of the top attacking IPs, such as `162.244.80.233` (Minecraft server) and `15.235.131.242` (Forcepoint training lab), were found to be non-malicious but misconfigured, generating a massive amount of scanning noise. This highlights that not all high-volume traffic is intentionally malicious, but it still contributes to the overall threat landscape.

**4. Targeted Default Credentials:** The repeated use of the credential pair **`345gs5662d34` / `345gs5662d34`** is a highly specific anomaly. OSINT confirms these are the default credentials for Polycom CX600 IP telephones. This indicates a targeted campaign specifically seeking to compromise and likely weaponize enterprise VoIP equipment.

**5. Exploitation of Legacy Systems:** The continued, widespread scanning for very old vulnerabilities (e.g., SNMP flaws from 1999 and 2002) is a key observation. Attackers operate on the assumption that many organizations have poor asset management and fail to decommission or patch legacy systems. These low-effort, high-reward scans remain a profitable tactic.

**6. Unusual Payloads ("catgirls;"):** The appearance of anomalous and nonsensical commands like `catgirls;` is noteworthy. While its exact purpose is unknown, it could be an attacker's signature, an attempt to trigger a specific response from a custom tool, or a simple distraction to pollute security logs.

## Google Searches

- OSINT on IP addresses: [List of all investigated IPs]
- Information on CVEs: [List of all investigated CVEs]
- Malware Analysis: "urbotnetisass", "Mozi.m", "rondo.sh", "k.php", "boatnet.mpsl"
- Attacker TTPs: "mdrfckr" SSH key, "lockr" command, "345gs5662d34" credentials, "catgirls;" command
- AS Organization Reputation: AS14061 (DigitalOcean), AS45102 (Alibaba), AS16276 (OVH)
- Hostname Investigation: `olivia.cocks.lab.go4labs.net`, `leonard.flowers.lab.go4labs.net`
