# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T09:06:20Z
**Timeframe:** 2025-10-11T09:06:20Z to 2025-10-12T09:06:20Z

**Files Used to Generate this Report:**
- Honeypot_Attack_Summary_Report_2025-10-11T10:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T11:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T12:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T13:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T14:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T15:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T16:02:06Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T17:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T19:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T20:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T21:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T22:02:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T23:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T00:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T01:01:47Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T02:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T03:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T04:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T05:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T06:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T07:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T08:01:47Z.md
- Honeypot_Attack_Summary_Report_2025-10-12T09:01:55Z.md

### Executive Summary

This report provides a comprehensive overview of malicious activities targeting our honeypot network over the past 24 hours. A total of **478,211** events were recorded and analyzed. The threat landscape continues to be dominated by automated, opportunistic attacks, with a significant focus on exploiting common vulnerabilities and weak credentials.

The most heavily targeted services were **SSH (port 22)** and **SMB (port 445)**, indicating a sustained effort by attackers to gain remote control of systems and exploit file-sharing vulnerabilities. The **Cowrie** honeypot, simulating SSH and Telnet services, recorded the highest number of interactions, closely followed by **Dionaea**, which emulates SMB and other services.

A small number of IP addresses were responsible for a disproportionately large volume of attacks, with **185.144.27.63** and **122.121.74.82** being the most persistent offenders. These IPs, along with several others, are associated with known malicious activities, including botnet operations and hacking attempts.

Attackers were observed employing a consistent set of tactics, techniques, and procedures (TTPs). A primary goal appears to be establishing persistent access, as evidenced by the repeated attempts to manipulate the `.ssh/authorized_keys` file. Following a successful compromise, attackers frequently performed reconnaissance to identify the system's architecture and then attempted to download and execute various malware payloads. The most common malware families observed were **Urbotnet** and **Mozi**, both of which are known for creating botnets of compromised IoT devices and servers.

The majority of exploited vulnerabilities were older, well-known CVEs, highlighting the ongoing threat posed by unpatched systems. The most frequently triggered IDS signature was related to the **DoublePulsar backdoor**, indicating continued attempts to exploit the EternalBlue vulnerability.

In summary, the honeypot network is facing a high volume of automated threats from a global network of attackers. The primary goals of these attackers appear to be expanding their botnets and gaining persistent access to vulnerable systems for future use.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 175,000+ |
| Dionaea | 75,000+ |
| Honeytrap | 60,000+ |
| Suricata | 40,000+ |
| Ciscoasa | 35,000+ |
| Sentrypeer | 5,000+ |
| Redishoneypot | 5,000+ |
| Tanner | 1,000+ |
| Mailoney | 1,000+ |
| H0neytr4p | 500+ |
| Adbhoney | 500+ |
| ConPot | 500+ |
| Honeyaml | 250+ |
| Heralding | 250+ |
| ElasticPot | 100+ |
| Ipphoney | 50+ |
| Miniprint | 50+ |
| Dicompot | 50+ |
| Wordpot | 10+ |

**Top Source Countries**

| Country | Attack Count |
|---|---|
| United States | 50,000+ |
| China | 40,000+ |
| India | 30,000+ |
| Russia | 25,000+ |
| Vietnam | 20,000+ |
| Brazil | 15,000+ |
| Germany | 10,000+ |
| Netherlands | 10,000+ |
| United Kingdom | 5,000+ |
| France | 5,000+ |

**Top Attacking IPs**

| IP Address | Attack Count |
|---|---|
| 185.144.27.63 | 40,000+ |
| 122.121.74.82 | 30,000+ |
| 103.136.5.30 | 10,000+ |
| 47.180.61.210 | 5,000+ |
| 103.91.45.100 | 1,600+ |
| 209.38.37.15 | 1,000+ |
| 102.222.184.4 | 1,800+ |
| 113.182.202.61 | 3,100+ |
| 41.38.10.88 | 2,500+ |
| 110.44.99.182 | 2,300+ |

**Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---|---|
| 445 (SMB) | 100,000+ |
| 22 (SSH) | 75,000+ |
| 5038 | 10,000+ |
| 5060 (SIP) | 5,000+ |
| 6379 (Redis) | 5,000+ |
| 5900 (VNC) | 2,500+ |
| 5903 | 2,000+ |
| 80 (HTTP) | 1,500+ |
| 443 (HTTPS) | 1,000+ |
| 25 (SMTP) | 1,000+ |

**Most Common CVEs**

| CVE | Count |
|---|---|
| CVE-2002-0013 | 100+ |
| CVE-2002-0012 | 100+ |
| CVE-1999-0517 | 50+ |
| CVE-2019-11500 | 20+ |
| CVE-2021-3449 | 15+ |
| CVE-2022-27255 | 10+ |
| CVE-2005-4050 | 5+ |
| CVE-2016-20016 | 5+ |
| CVE-2024-4577 | 5+ |
| CVE-2002-0953 | 5+ |

**Commands Attempted by Attackers**

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 500+ |
| `lockr -ia .ssh` | 500+ |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` | 500+ |
| `cat /proc/cpuinfo | grep name | wc -l` | 400+ |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 400+ |
| `uname -a` | 400+ |
| `whoami` | 400+ |
| `crontab -l` | 400+ |
| `w` | 400+ |
| `top` | 400+ |

**Signatures Triggered**

| Signature | Count |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 10,000+ |
| ET DROP Dshield Block Listed Source group 1 | 5,000+ |
| ET SCAN NMAP -sS window 1024 | 2,000+ |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,500+ |
| ET INFO Reserved Internal IP Traffic | 1,000+ |
| ET HUNTING RDP Authentication Bypass Attempt | 500+ |
| ET SCAN Potential SSH Scan | 500+ |
| ET DROP Spamhaus DROP Listed Traffic Inbound | 500+ |
| ET INFO VNC Authentication Failure | 500+ |
| ET CINS Active Threat Intelligence Poor Reputation IP | 250+ |

**Users / Login Attempts**

| Username/Password | Count |
|---|---|
| 345gs5662d34/345gs5662d34 | 500+ |
| root/3245gs5662d34 | 100+ |
| root/Ahgf3487@rtjhskl854hd47893@#a4nC | 100+ |
| root/nPSpP4PBW0 | 100+ |
| root/LeitboGi0ro | 50+ |
| admin/admin | 50+ |
| pi/raspberry | 25+ |
| ubnt/ubnt | 25+ |
| test/test | 25+ |
| user/user | 25+ |

**Files Uploaded/Downloaded**

| Filename | Count |
|---|---|
| arm.urbotnetisass | 20+ |
| mips.urbotnetisass | 20+ |
| x86_32.urbotnetisass | 20+ |
| Mozi.m | 10+ |
| wget.sh | 10+ |
| sh | 10+ |
| c.sh | 5+ |
| w.sh | 5+ |
| boatnet.x86 | 5+ |
| ohshit.sh | 5+ |

**HTTP User-Agents**

| User-Agent | Count |
|---|---|
| *No significant user agents were recorded in this period.* | - |

**SSH Clients and Servers**

| Client/Server | Version | Count |
|---|---|---|
| *No specific SSH clients or servers were identified in this timeframe.* | - | - |

**Top Attacker AS Organizations**

| AS Organization | Attack Count |
|---|---|
| *No AS organization data was available in this timeframe.* | - |

### OSINT All Commands Captured

| Command | Tactic | Objective |
|---|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | Defense Evasion | Prepare SSH directory for modification |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` | Persistence | Install persistent SSH access |
| `cat /proc/cpuinfo`, `uname -a`, `lscpu` | Discovery | Gather system hardware information |
| `free -m`, `df -h` | Discovery | Gather system memory and disk information |
| `whoami`, `w`, `crontab -l` | Discovery | Gather user and system configuration information |
| `cd /data/local/tmp/; rm *; busybox wget ...` | Execution | Download and execute malware on Android-based systems |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh` | Defense Evasion | Remove competing malware or security scripts |
| `nohup bash -c "exec 6<>/dev/tcp/..."` | Execution | Download and execute malware |
| `tftp; wget; /bin/busybox YZNGS` | Execution | Download and execute malware |
| `echo -e "...|passwd|bash` | Privilege Escalation | Change user password |

### OSINT High Frequency IPs and Low Frequency IPs Captured

| IP Address | Frequency | OSINT Notes |
|---|---|---|
| 185.144.27.63 | High | Flagged on multiple lists for being suspicious and directly involved in attacks. Associated with malware distribution. |
| 122.121.74.82 | High | No specific threat intelligence, but responsible for a massive volume of SMB scans. Likely a compromised machine or part of a botnet. |
| 83.168.107.46 | High | Long and well-documented history of malicious activity, including hacking attempts, web application attacks, and SSH brute-force attacks. |
| 47.180.61.210 | High | Identified as a source of SSH brute-force attacks. |
| 95.170.68.246 | High | Present on malware blocklists. |
| 173.239.216.40 | High | Linked to suspicious activity, including scanning for SIP services. |
| 8.138.186.69 | High | Listed on blocklists for participating in a range of malicious activities, including DDoS attacks and spamming. |
| 103.136.5.30 | High | No specific threat intelligence, but responsible for a large volume of SMB scans. |
| 41.38.10.88 | High | No specific threat intelligence, but observed in multiple attack campaigns. |
| 110.44.99.182 | High | No specific threat intelligence, but observed in multiple attack campaigns. |
| 213.130.93.177 | Low | No specific threat intelligence. |
| 157.245.101.239 | Low | No specific threat intelligence. |
| 103.91.45.100 | Low | No specific threat intelligence. |
| 209.38.37.15 | Low | No specific threat intelligence. |
| 102.222.184.4 | Low | No specific threat intelligence. |
| 113.182.202.61 | Low | No specific threat intelligence. |

### OSINT on CVE's

| CVE | Description |
|---|---|
| CVE-2002-0013 | Multiple vulnerabilities in SNMPv1 implementations allowing for denial of service and privilege escalation. |
| CVE-2002-0012 | Multiple vulnerabilities in SNMPv1 implementations allowing for denial of service and privilege escalation. |
| CVE-1999-0517 | A vulnerability in the `rpc.statd` service that can be exploited to gain root privileges. |
| CVE-2021-3449 | An OpenSSL TLS server using TLSv1.2 with renegotiation enabled could crash due to a null pointer dereference, leading to a denial of service. |
| CVE-2019-11500 | A critical vulnerability in Dovecot that allows for remote code execution due to mishandling of null bytes. |
| CVE-2022-27255 | A stack-based buffer overflow vulnerability in the SIP ALG function of the Realtek eCos SDK, allowing for remote code execution. |
| CVE-2024-4577 | Information on this CVE was not available. |
| CVE-2002-0953 | A buffer overflow in the `resolv.c` library used by many applications, which can be exploited to execute arbitrary code. |
| CVE-2021-41773 | A path traversal vulnerability in Apache HTTP Server version 2.4.49 that could lead to remote code execution. |
| CVE-2021-42013 | An incomplete fix for CVE-2021-41773 in Apache HTTP Server version 2.4.50. |
| CVE-1999-0183 | A vulnerability in the `imapd` service that can be exploited to gain root privileges. |
| CVE-2005-4050 | A vulnerability in the `ncompress` utility that can be exploited to execute arbitrary code. |
| CVE-2016-20016 | Information on this CVE was not available. |
| CVE-2023-49103 | A critical information disclosure vulnerability in ownCloud's graphapi extension. |
| CVE-2001-0414 | A buffer overflow vulnerability in `ntpd` that can be exploited to cause a denial of service and potentially execute arbitrary commands. |
| CVE-2020-11910 | A vulnerability in Apache OpenOffice that can be exploited to execute arbitrary code. |
| CVE-2018-11776 | A remote code execution vulnerability in Apache Struts. |
| CVE-2021-35394 | A vulnerability in Realtek's SDK for UPnP that can be exploited to execute arbitrary code. |
| CVE-2018-2893 | A critical remote code execution vulnerability in the WLS Core Components of Oracle WebLogic Server. |
| CVE-2016-6563 | A vulnerability in OpenSSH that can be exploited to cause a denial of service. |
| CVE-2002-1149 | A vulnerability in the `pppd` daemon that can be exploited to gain root privileges. |
| CVE-2006-3602 | A vulnerability in the `unzip` utility that can be exploited to execute arbitrary code. |
| CVE-2006-4458 | A vulnerability in the `unzip` utility that can be exploited to execute arbitrary code. |
| CVE-2006-4542 | Multiple vulnerabilities in Webmin and Usermin that can be exploited to perform cross-site scripting, read CGI source code, and potentially execute programs. |

### Key Observations and Anomalies

- **Hyper-Aggressive IP Addresses:** A small number of IP addresses, particularly **185.144.27.63** and **122.121.74.82**, are responsible for a massive volume of the total attack traffic. This suggests that these IPs are either part of a large botnet or are dedicated attack servers.
- **Attacker "Signature":** The consistent use of the comment "mdrfckr" in the injected SSH key is a clear and taunting signature of a specific attacker or group.
- **Targeting of Android-based Systems:** The command `cd /data/local/tmp/; rm *; busybox wget ...` indicates a specific focus on compromising Android-based devices, which is a less common but growing trend.
- **Multi-Architecture Malware:** The widespread use of the **Urbotnet** malware, with variants for ARM, MIPS, and x86, demonstrates a sophisticated and broad approach to compromising a wide range of devices, from servers to IoT gadgets.
- **Unusual Credentials:** The username/password combination **345gs5662d34/345gs5662d34** was observed with unusually high frequency, suggesting it may be a hardcoded credential in a specific piece of malware or a default credential for a particular device that is being heavily targeted.
- **Focus on Older Vulnerabilities:** The continued exploitation of very old CVEs (e.g., from 1999 and 2002) highlights the fact that many systems remain unpatched and vulnerable to these known exploits.
- **Lack of Sophisticated Payloads:** While the methods for gaining access and persistence are effective, the final payloads observed (Urbotnet, Mozi) are common, off-the-shelf botnet clients rather than custom, advanced malware. This suggests that the attackers are focused on quantity over quality, aiming to build large botnets for DDoS attacks or other commodity cybercrime activities.

This concludes the Honeypot Attack Summary Report.
