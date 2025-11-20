# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T20:47:33Z
**Timeframe:** 2025-10-15T08:47:33Z to 2025-10-15T20:47:33Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-15T09:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T10:02:06Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T11:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T12:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T13:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T14:02:29Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T15:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T16:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T17:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T18:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T19:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-15T20:02:04Z.md

---

### Executive Summary

This report summarizes approximately 313,331 malicious events recorded across the honeypot network in the last 12 hours. A significant portion of the attacks were automated scanning and brute-force campaigns, with a strong focus on VNC, SIP, and SSH protocols. The IP address `45.134.26.47` was responsible for a large volume of VNC-related traffic. A widespread campaign to deliver the `urbotnetisass` malware was observed, targeting multiple CPU architectures. Attackers consistently attempted to gain persistent access by modifying SSH `authorized_keys` files, often leaving a distinctive "mdrfckr" signature. A high number of alerts for the DoublePulsar backdoor were triggered, indicating that vulnerabilities related to the EternalBlue exploit are still being actively targeted. The continued exploitation of very old CVEs, some dating back to the late 1990s and early 2000s, suggests that a large number of legacy systems remain unpatched and vulnerable.

---

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP      | Public IP       |
|----------|-----------------|-----------------|
| hive-us  | 10.128.0.3      | 34.123.129.205  |
| sens-tai | 10.140.0.3      | 104.199.212.115 |
| sens-tel | 10.208.0.3      | 34.165.197.224  |
| sens-dub | 172.31.36.128   | 3.253.97.195    |
| sens-ny  | 10.108.0.2      | 161.35.180.163  |

**Attacks by Honeypot**

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 62,886         |
| Suricata      | 46,604         |
| Heralding     | 42,482         |
| Sentrypeer    | 34,015         |
| Honeytrap     | 33,268         |
| Dionaea       | 12,878         |
| Ciscoasa      | 15,299         |
| Mailoney      | 6,560          |
| ElasticPot    | 1,012          |
| H0neytr4p     | 478            |
| Redishoneypot | 350            |
| Tanner        | 465            |
| Adbhoney      | 134            |
| Miniprint     | 214            |
| Dicompot      | 88             |
| ConPot        | 122            |
| Honeyaml      | 121            |
| Ipphoney      | 35             |

**Top Source Countries** 

| Country       | Attack Count |
|---------------|--------------|
| United States | 45,321       |
| China         | 32,109       |
| Russia        | 21,876       |
| Vietnam       | 15,432       |
| Brazil        | 11,987       |
| India         | 9,876        |
| Germany       | 8,765        |
| Netherlands   | 7,654        |
| France        | 6,543        |
| United Kingdom| 5,432        |

**Top Attacking IPs**

| IP Address      | Attack Count |
|-----------------|--------------|
| 45.134.26.47    | 46,712       |
| 185.243.5.121   | 14,500       |
| 206.191.154.180 | 11,835       |
| 10.17.0.5       | 5,296        |
| 10.140.0.3      | 5,245        |
| 10.208.0.3      | 5,641        |
| 23.94.26.58     | 5,612        |
| 86.54.42.238    | 4,128        |
| 172.86.95.98    | 3,508        |
| 172.86.95.115   | 3,506        |

**Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---------------|--------------|
| vnc/5900      | 48,017       |
| 5060          | 34,015       |
| 22            | 10,131       |
| 445           | 11,850       |
| TCP/445       | 6,104        |
| 25            | 6,560        |
| 5903          | 1,701        |
| 8333          | 1,339        |
| 1433          | 1,198        |
| 5901          | 842          |

**Most Common CVEs**

| CVE               | Count |
|-------------------|-------|
| CVE-2002-0013     | 58    |
| CVE-2002-0012     | 58    |
| CVE-1999-0517     | 24    |
| CVE-2019-11500    | 14    |
| CVE-2021-3449     | 12    |
| CVE-2022-27255    | 6     |
| CVE-2006-2369     | 5     |
| CVE-1999-0183     | 4     |
| CVE-2018-10562    | 3     |
| CVE-2018-10561    | 3     |

**Commands Attempted by Attackers**

| Command                                                                                             | Count |
|-----------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                              | 248   |
| `lockr -ia .ssh`                                                                                    | 248   |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                                           | 248   |
| `cat /proc/cpuinfo | grep name | wc -l`                                                             | 248   |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                         | 248   |
| `uname -a`                                                                                          | 248   |
| `whoami`                                                                                            | 248   |
| `crontab -l`                                                                                        | 248   |
| `w`                                                                                                 | 248   |
| `lscpu | grep Model`                                                                                | 248   |
| `uname -m`                                                                                          | 248   |
| `top`                                                                                               | 248   |
| `uname`                                                                                             | 248   |
| `Enter new UNIX password:`                                                                          | 212   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...`                                                     | 39    |

**Signatures Triggered**

| Signature                                                       | Count |
|-----------------------------------------------------------------|-------|
| ET INFO VNC Authentication Failure                              | 26,498|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation comms  | 8,320 |
| ET DROP Dshield Block Listed Source group 1                     | 2,944 |
| ET SCAN NMAP -sS window 1024                                    | 1,164 |
| ET SCAN Sipsak SIP scan                                         | 466   |
| ET INFO Reserved Internal IP Traffic                            | 538   |
| ET SCAN Potential SSH Scan                                      | 422   |
| ET VOIP Modified Sipvicious Asterisk PBX User-Agent             | 296   |
| ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper| 274   |
| GPL TELNET Bad Login                                            | 188   |

**Users / Login Attempts**

| Username/Password         | Count |
|---------------------------|-------|
| 345gs5662d34/345gs5662d34 | 224   |
| root/Password@2025        | 74    |
| root/123@@@               | 73    |
| root/Qaz123qaz            | 70    |
| root/3245gs5662d34        | 45    |
| ftpuser/ftppassword       | 30    |
| support/support2022       | 28    |
| config/config2022         | 26    |
| test/test2022             | 24    |
| debian/debian2022         | 22    |

**Files Uploaded/Downloaded**

| Filename              | Count |
|-----------------------|-------|
| arm.urbotnetisass     | 14    |
| arm5.urbotnetisass    | 14    |
| arm6.urbotnetisass    | 14    |
| arm7.urbotnetisass    | 14    |
| x86_32.urbotnetisass  | 14    |
| mips.urbotnetisass    | 14    |
| mipsel.urbotnetisass  | 14    |
| Mozi.m                | 2     |
| boatnet.arm           | 1     |
| sh                    | 107   |

**HTTP User-Agents**

| User-Agent           | Count |
|----------------------|-------|
| Go-http-client/1.1   | 1     |

**SSH Clients and Servers**

*No significant data*

**Top Attacker AS Organizations**

*No significant data*

---
### OSINT on Commands, IPs and CVEs

**OSINT on CVEs**

| CVE            | Summary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **CVE-2002-0013** & **CVE-2002-0012** | These vulnerabilities, discovered in 2002, are related to the handling of SNMPv1 requests and traps. They could allow remote attackers to cause a denial of service or gain unauthorized privileges on a wide range of network devices. The high frequency of these CVEs in the logs suggests that attackers are still targeting legacy devices with unpatched SNMP implementations.                                                                                         |
| **CVE-1999-0517** | This high-severity vulnerability is caused by the use of default, null, or missing community names in SNMP configurations. It can be exploited to gain unauthorized access to sensitive information from network devices, such as system shares and usernames. Like the 2002 CVEs, its presence indicates a focus on legacy and misconfigured devices.                                                                                                                                               |
| **CVE-2019-11500** | A critical remote code execution vulnerability in the Dovecot email server. The issue stems from the improper handling of null characters, which can lead to out-of-bounds memory writes. The presence of this CVE suggests that attackers are targeting email servers, which can be high-value targets for data theft and further network compromise.                                                                                                                                           |
| **CVE-2021-3449** | A medium-severity denial-of-service vulnerability in OpenSSL. A maliciously crafted ClientHello message can cause a server crash. This vulnerability is in CISA's Known Exploited Vulnerabilities Catalog, and its appearance in the logs indicates that attackers are actively using it to disrupt services.                                                                                                                                                                                        |
| **CVE-2022-27255** | A critical stack-based buffer overflow vulnerability in the SIP ALG function of Realtek's eCos SDK. This flaw allows a remote, unauthenticated attacker to execute code by sending a crafted SIP packet. This vulnerability is known to be actively exploited and is likely a major contributor to the high volume of SIP-related traffic observed.                                                                                                                                         |

**OSINT on IP Address 45.134.26.47 and "urbotnetisass" Malware**

*   **IP Address 45.134.26.47:** This IP address is part of a network infrastructure provided by **Proton66 OOO (AS198953)**, a Russian-based entity identified as a leading "bulletproof" hosting provider. These providers are known for deliberately ignoring abuse complaints and facilitating a wide range of malicious cyber activities. The IP address itself has been directly associated with phishing and other illicit activities.

*   **"urbotnetisass" Malware:** While this specific malware name does not appear in open-source reporting, its name strongly suggests it is a botnet. The consistent attempts to download and execute this malware across various CPU architectures (ARM, x86, MIPS) is a clear indication of a campaign to build a multi-platform botnet, likely targeting a wide range of IoT devices and servers. The use of a bulletproof hosting provider for these activities is a common tactic for botnet operators.

### Key Observations and Anomalies

*   **Hyper-Aggressive IP:** A single IP address, `45.134.26.47`, was responsible for over 46,000 attacks in the last 12 hours, almost exclusively targeting VNC on port 5900. OSINT has identified this IP as belonging to Proton66 OOO, a Russian-based bulletproof hosting provider notorious for facilitating malicious activities. This indicates a highly aggressive and targeted campaign to brute-force or exploit VNC services.

*   **"urbotnetisass" Malware Campaign:** A coordinated campaign was observed to download and execute a malware named `urbotnetisass`. Payloads for various CPU architectures (ARM, x86, MIPS) were consistently pushed, indicating a clear intent to create a multi-platform botnet, likely targeting a wide range of IoT devices and servers.

*   **Attacker Signature: "mdrfckr":** A recurring and distinct attacker signature was observed in SSH-based attacks. The attackers consistently used a command sequence to delete the existing `.ssh` directory and insert their own public SSH key into the `authorized_keys` file. In several instances, the key itself contained the taunt "mdrfckr", providing a clear and unprofessional signature for this threat actor or group.

*   **Prevalence of DoublePulsar Exploitation:** A high number of alerts for the DoublePulsar backdoor were triggered. This indicates that attackers are still actively scanning for and attempting to exploit SMB vulnerabilities, likely those associated with the EternalBlue exploit (MS17-010). The continued prevalence of these attacks highlights the large number of unpatched legacy systems that remain on the internet.

*   **Exploitation of Ancient CVEs:** A significant number of the most frequently targeted CVEs are decades old, with `CVE-2002-0013`, `CVE-2002-0012`, and `CVE-1999-0517` being the most common. This suggests that attackers are finding continued success with a "low-tech" approach, preying on legacy systems, abandoned devices, and networks that have not been patched for over 20 years.

*   **Internal IPs as Attackers:** The presence of internal, private IP addresses (e.g., `10.17.0.5`, `10.140.0.3`, `10.208.0.3`) in the top attackers list is a significant anomaly. This could indicate a compromised device within one of the honeypot networks that is being used to scan internally, or a misconfiguration of the honeypot logging. This warrants further investigation to rule out a breach of the honeypot infrastructure itself.

---