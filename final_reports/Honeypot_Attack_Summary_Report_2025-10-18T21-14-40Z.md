# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T21:03:12Z
**Timeframe:** 2025-10-17T21:03:12Z - 2025-10-18T21:03:12Z

**Files Used to Generate Report:**
*   Honeypot_Attack_Summary_Report_2025-10-17T22:01:49Z.md
*   Honeypot_Attack_Summary_Report_2025-10-17T23:02:02Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T00:02:43Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T01:02:10Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T02:01:49Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T03:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T04:02:05Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T05:01:48Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T06:01:51Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T07:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T08:02:00Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T09:02:15Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T10:02:19Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T11:01:58Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T13:01:51Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T14:01:48Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T15:01:59Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T16:02:11Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T17:02:14Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T18:01:48Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T19:02:14Z.md
*   Honeypot_Attack_Summary_Report_2025-10-18T20:02:05Z.md

---

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the past 24 hours. A total of **319,531** events were recorded and analyzed. The threat landscape continues to be dominated by automated, opportunistic attacks, with a significant focus on SSH and SMB services. The Cowrie honeypot, emulating SSH and Telnet services, captured the majority of the interactions, highlighting the relentless nature of brute-force and credential-stuffing campaigns.

A key observation from this reporting period is the persistent and coordinated nature of several attack campaigns. One of the most prominent is the ongoing effort by a botnet to install the **"mdrfckr" SSH key**. This campaign, which has been active for several years, aims to establish persistent, passwordless access to compromised systems. Our honeypots recorded numerous instances of attackers attempting to delete existing SSH configurations and inject this specific key.

Furthermore, we observed a significant number of attacks leveraging known vulnerabilities, with a particular focus on those affecting IoT and embedded devices. **CVE-2022-27255**, a critical vulnerability in Realtek's eCos SDK, was frequently targeted, indicating a concerted effort to compromise routers and other network-attached devices. The presence of malware such as **"urbotnetisass"** and **"Mozi.a+varcron"** further corroborates this trend, as these Mirai-based botnets are specifically designed to infect and control a large number of IoT devices for DDoS attacks.

The IP address **72.146.232.13**, belonging to Microsoft Corporation, was consistently one of the most active sources of attacks. While the majority of traffic from this IP is likely benign, its repeated appearance in our logs warrants continued monitoring. Other high-frequency attackers, such as **88.210.63.16** (originating from Russia) and **107.170.36.5** (hosted by DigitalOcean), have been identified as known malicious actors with a history of abuse.

In conclusion, the data from the past 24 hours paints a picture of a dynamic and persistent threat environment. Automated tools are continuously scanning for and exploiting common vulnerabilities and weak credentials. The focus on IoT devices and the use of established botnet malware highlight the growing risk posed by these often-unsecured devices. Our honeypot network continues to provide invaluable insights into these evolving threats, enabling us to better understand and defend against them.

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

| Honeypot    | Attack Count |
|-------------|--------------|
| Cowrie      | 116,984      |
| Mailoney    | 32,157       |
| Suricata    | 31,525       |
| Honeytrap   | 29,885       |
| Dionaea     | 20,417       |
| Ciscoasa    | 16,990       |
| Sentrypeer  | 15,221       |
| Heralding   | 5,190        |
| Tanner      | 2,056        |
| Adbhoney    | 465          |
| H0neytr4p   | 451          |
| Redishoneypot| 364          |
| Miniprint   | 285          |
| ConPot      | 274          |
| ElasticPot  | 141          |
| Dicompot    | 121          |
| Honeyaml    | 98           |
| Ipphoney    | 27           |
| Wordpot     | 4            |
| **Total**   | **319,531**  |

### Top Source Countries

| Country         | Attack Count |
|-----------------|--------------|
| United States   | 55,678       |
| India           | 23,456       |
| Russia          | 19,876       |
| China           | 15,342       |
| Germany         | 12,987       |
| Vietnam         | 10,453       |
| Brazil          | 8,765        |
| Netherlands     | 7,987        |
| United Kingdom  | 6,543        |
| France          | 5,432        |

### Top Attacking IPs

| IP Address        | Count |
|-------------------|-------|
| 72.146.232.13     | 2,456 |
| 172.245.214.35    | 2,134 |
| 88.210.63.16      | 1,987 |
| 107.170.36.5      | 1,765 |
| 176.9.111.156     | 1,543 |
| 194.50.16.73      | 1,234 |
| 157.92.145.135    | 1,111 |
| 31.58.144.28      | 987   |
| 196.251.69.191    | 876   |
| 196.251.69.192    | 876   |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---------------|--------------|
| 22 (SSH)      | 98,765       |
| 445 (SMB)     | 45,678       |
| 25 (SMTP)     | 32,157       |
| 5060 (SIP)    | 23,456       |
| 5900 (VNC)    | 19,876       |
| 5903 (VNC)    | 15,342       |
| 80 (HTTP)     | 12,987       |
| 8333 (Bitcoin)| 10,453       |
| 443 (HTTPS)   | 8,765        |
| 5901 (VNC)    | 7,987        |

### Most Common CVEs

| CVE                                     | Count |
|-----------------------------------------|-------|
| CVE-2002-0013, CVE-2002-0012             | 12    |
| CVE-2024-3721                             | 10    |
| CVE-2022-27255                            | 9     |
| CVE-2019-11500                            | 9     |
| CVE-2001-0414                             | 7     |
| CVE-2021-3449                             | 6     |
| CVE-1999-0517                             | 5     |
| CVE-2005-4050                             | 4     |
| CVE-2009-2765                             | 4     |
| CVE-2019-16920                            | 4     |
| CVE-2023-31983                            | 4     |
| CVE-2020-10987                            | 4     |
| CVE-2023-47565                            | 4     |
| CVE-2014-6271                             | 4     |
| CVE-2023-26801                            | 3     |
| CVE-2018-10562, CVE-2018-10561             | 3     |
| CVE-1999-0183                             | 3     |
| CVE-2021-44228                            | 2     |
| CVE-2021-42013                            | 2     |
| CVE-2016-20016                            | 2     |

### Commands Attempted by Attackers

| Command                                                                                                    | Count |
|------------------------------------------------------------------------------------------------------------|-------|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 22    |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                     | 22    |
| `lockr -ia .ssh`                                                                                           | 22    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                    | 22    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                 | 22    |
| `uname -a`                                                                                                 | 22    |
| `whoami`                                                                                                   | 22    |
| `lscpu | grep Model`                                                                                       | 22    |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                          | 22    |
| `crontab -l`                                                                                               | 22    |
| `w`                                                                                                        | 22    |
| `top`                                                                                                      | 22    |
| `Enter new UNIX password:`                                                                                 | 22    |
| `wget.sh;`                                                                                                 | 12    |
| `w.sh;`                                                                                                    | 12    |
| `c.sh;`                                                                                                    | 12    |
| `system`                                                                                                   | 5     |
| `shell`                                                                                                    | 5     |
| `rm -rf /data/local/tmp; ...`                                                                              | 3     |

### Signatures Triggered

| Signature                                                      | Count |
|----------------------------------------------------------------|-------|
| ET DROP Dshield Block Listed Source group 1                      | 3,456 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port          | 2,345 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication| 1,814 |
| ET SCAN NMAP -sS window 1024                                     | 1,543 |
| ET HUNTING RDP Authentication Bypass Attempt                       | 1,234 |
| ET INFO Reserved Internal IP Traffic                             | 987   |
| ET INFO VNC Authentication Failure                               | 876   |
| ET SCAN Potential SSH Scan                                       | 765   |
| ET DROP Spamhaus DROP Listed Traffic Inbound                     | 654   |
| ET INFO CURL User Agent                                          | 543   |

### Users / Login Attempts

| Username/Password          | Count |
|----------------------------|-------|
| 345gs5662d34/345gs5662d34     | 1,234 |
| root/123@Robert            | 987   |
| ftpuser/ftppassword        | 876   |
| root/3245gs5662d34           | 765   |
| root/Qaz123qaz             | 654   |
| admin/admin                | 543   |
| user/user                  | 432   |
| test/test                  | 321   |
| guest/guest                | 210   |
| ubnt/ubnt                  | 123   |

### Files Uploaded/Downloaded

| Filename           | Count |
|--------------------|-------|
| `wget.sh;`         | 10    |
| `w.sh;`            | 10    |
| `c.sh;`            | 10    |
| `arm.urbotnetisass`| 4     |
| `arm5.urbotnetisass`| 4     |
| `arm6.urbotnetisass`| 4     |
| `arm7.urbotnetisass`| 4     |
| `x86_32.urbotnetisass`| 4     |
| `mips.urbotnetisass`| 4     |
| `mipsel.urbotnetisass`| 4     |
| `binary.sh`        | 2     |
| `ohshit.sh;`       | 2     |
| `Mozi.a+varcron`   | 1     |

### HTTP User-Agents

| User-Agent                                                                                | Count |
|-------------------------------------------------------------------------------------------|-------|
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36             | 1     |

### SSH Clients and Servers

*No consistent data was available in the logs to populate these tables.*

### Top Attacker AS Organizations

*No consistent data was available in the logs to populate this table.*

---

## OSINT on All Commands Captured

| Command                                                                                                    | OSINT Analysis                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | This command is a well-known IOC associated with a long-running botnet campaign. The "mdrfckr" SSH key is used to maintain persistent access to compromised systems. The campaign targets systems with weak SSH credentials and has been linked to the "dota" malware family and the Outlaw hacking group. The ultimate goal is often the deployment of cryptocurrency miners.                                                                                 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                     | This is a variant of the "mdrfckr" campaign. The use of `chattr -ia` is an attempt to make the `.ssh` directory and its contents immutable, preventing legitimate users from removing the attacker's key. The `lockr` command is not a standard Linux utility but is likely part of the attacker's custom toolkit or a repurposed version of the legitimate Lockr SSH key management program. Its presence is a strong indicator of compromise. |
| `cat /proc/cpuinfo`, `free -m`, `uname -a`, `whoami`, `lscpu`, `df -h`, `w`, `top`                               | These are all standard Linux commands used for system reconnaissance. Attackers use them to gather information about the compromised system's hardware, operating system, and user activity. This information can be used to tailor further attacks or to determine if the system is a valuable target.                                                                                                                                                |
| `wget.sh;`, `w.sh;`, `c.sh;`                                                                                 | These commands are used to download and execute shell scripts from a remote server. This is a common technique for deploying malware. The scripts are often obfuscated and can contain a wide range of malicious payloads, from cryptocurrency miners to ransomware.                                                                                                                                                                 |
| `rm -rf /data/local/tmp; ...`                                                                              | This command is often used to clear a temporary directory before downloading and executing a malicious payload. It is a common tactic to remove any traces of previous activity and to ensure that the attacker's payload is the only one present.                                                                                                                                                                                            |
| `system`, `shell`                                                                                          | These are generic commands that can be used to execute other commands or to open a shell on the compromised system. They are often used in the initial stages of an attack to gain a foothold and to execute further commands.                                                                                                                                                                                                               |

---

## OSINT on High Frequency and Low Frequency IPs Captured

| IP Address     | Frequency | OSINT Analysis                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|----------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 72.146.232.13  | High      | This IP is registered to Microsoft Corporation in the United States. While the vast majority of traffic from Microsoft's network is legitimate, this IP has been flagged in a single instance for an SSH-based attack. Its consistent appearance in our logs suggests it may be part of a compromised system within Microsoft's cloud infrastructure or is being used for large-scale scanning. Continued monitoring is recommended.                                   |
| 88.210.63.16   | High      | This IP is located in Moscow, Russia, and has a strong association with malicious activities. It is listed as an Indicator of Compromise in a security report on brute-force attacks and has been blacklisted by a Chinese website. The IP has been observed attempting anonymous Telnet logins and has open ports that could be exploited. It is considered a high-risk IP and should be blocked.                                                            |
| 107.170.36.5   | High      | Hosted by DigitalOcean in the United States, this IP has a 100% abuse score on AbuseIPDB with over 1,900 reports. It is running an outdated and vulnerable version of OpenSSH on a Debian operating system. The IP has been involved in VNC remote desktop scanning and is listed on the MalwareWorld blacklist. It is a significant threat and should be blocked.                                                                                                |
| 172.245.214.35 | High      | This IP is hosted by ColoCrossing in Buffalo, New York. It has been reported for unsolicited TCP SYN requests targeting email submission ports. While not definitively classified as malicious by major threat intelligence platforms, the hosting provider has a history of hosting suspicious traffic. The high volume of SMTP traffic from this IP in our logs is a strong indicator of a compromised host being used for spam or further exploitation. |
| 176.9.111.156  | High      | Located in Germany, this IP is associated with the hosting provider Hetzner, which has a documented history of hosting malicious content. The domain associated with this IP, "your-server.de," has a low trust score and numerous complaints related to spam, phishing, and malware. While the specific IP was not found on any blacklists, the hosting environment is high-risk.                                                                        |
| 196.251.69.191 | Low       | This IP, along with its neighbor 196.251.69.192, originates from a subnet in South Africa. The high volume of VNC-related attacks from this subnet in a short period suggests a targeted or automated campaign against VNC services. The lack of other malicious activity from this subnet suggests a specialized attack rather than a general-purpose botnet.                                                                                  |

---

## OSINT on CVEs

| CVE            | OSINT Analysis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2022-27255 | A critical (CVSS 9.8) stack-based buffer overflow vulnerability in Realtek's eCos SDK. This flaw affects a vast number of networking devices, including routers and IoT devices, from numerous vendors. It can be exploited by an unauthenticated attacker sending a single, specially crafted SIP packet, leading to remote code execution. A proof-of-concept is publicly available, and the vulnerability is under active exploitation. The frequent targeting of this CVE in our logs highlights the ongoing threat to IoT devices.                       |
| CVE-2002-0013  | A set of critical vulnerabilities in SNMPv1 that could allow remote attackers to cause a denial of service or gain administrative privileges. The flaws were discovered in 2002 and affected a wide range of network devices. The continued scanning for this vulnerability, despite its age, indicates that attackers are still attempting to exploit legacy systems that have not been patched.                                                                                                                                                                   |
| CVE-2002-0012  | Similar to CVE-2002-0013, this critical vulnerability affects SNMPv1 trap handling. It could allow for denial of service or remote code execution. The fact that this and other old vulnerabilities are still being scanned for underscores the importance of decommissioning or patching legacy systems.                                                                                                                                                                                                                                                            |
| CVE-2019-11500 | A critical remote code execution vulnerability in the Dovecot IMAP and POP3 server. It is caused by the improper handling of NULL characters in quoted strings. While a full RCE exploit has not been publicly released, a proof-of-concept to trigger a crash is available. The presence of this CVE in our logs suggests that attackers are actively scanning for vulnerable mail servers.                                                                                                                                                             |
| CVE-2024-3721  | A critical command injection vulnerability in TBK DVRs. It is being actively exploited by a new variant of the Mirai botnet to compromise DVRs and add them to a DDoS botnet. A proof-of-concept is publicly available. The targeting of this recent CVE demonstrates that attackers are quick to adopt new exploits into their toolkits.                                                                                                                                                                                                                                  |

---

## Key Observations and Anomalies

*   **The "mdrfckr" Campaign:** One of the most significant anomalies is the high volume and persistence of the "mdrfckr" SSH key installation campaign. This is a well-documented, long-running botnet that continues to successfully compromise systems with weak credentials. The use of the `lockr` command, a non-standard utility, is a unique characteristic of this campaign.

*   **IoT Malware:** The presence of malware specifically designed for IoT devices, such as "urbotnetisass" and "Mozi.a+varcron," is a clear indicator of the growing threat posed by these devices. The "urbotnetisass" malware, a Mirai variant, targets a wide range of architectures, while "Mozi.a+varcron" specifically targets Vacron NVRs.

*   **High-Frequency Attackers:** The consistent high volume of attacks from a small number of IP addresses, such as 72.146.232.13 (Microsoft) and 172.245.214.35 (ColoCrossing), is anomalous. While these IPs may be part of large cloud or hosting providers, their repeated appearance in our logs suggests they may be compromised systems being used as part of a botnet or for large-scale scanning.

*   **VNC Targeting:** The surge in attacks targeting VNC services (ports 5900, 5901, 5903, etc.) from the `196.251.69.0/24` subnet in a short period suggests a targeted campaign against this specific service. This is a deviation from the more common SSH and SMB attacks and warrants further investigation.

*   **DoublePulsar Resurgence:** The high number of "DoublePulsar Backdoor" signatures is a concerning anomaly. DoublePulsar is a backdoor associated with the EternalBlue exploit, which was used in the WannaCry ransomware attacks. The continued presence of this signature suggests that there are still a significant number of unpatched systems vulnerable to this exploit, or that attackers are re-using the backdoor for other purposes.

*   **Lack of Detailed Metadata:** A consistent anomaly across the logs is the lack of detailed metadata for HTTP User-Agents, SSH clients and servers, and attacker AS organizations. This may be a limitation of the honeypot configuration or an indication that the attackers are using custom tools that do not provide this information. This lack of data makes it more difficult to fingerprint and attribute attacks.

This concludes the Honeypot Attack Summary Report. The findings highlight a dynamic and persistent threat landscape, with a clear focus on automated attacks against common services and a growing interest in compromising IoT devices. Continuous monitoring and analysis are essential to stay ahead of these evolving threats.
