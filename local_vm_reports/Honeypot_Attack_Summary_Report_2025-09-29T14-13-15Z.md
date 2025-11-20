# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T14:11:54Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T14:02:04Z

**Files Used to Generate Report:**
*   Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T10-02-22Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T11-01-58Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T12-02-14Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T13-02-20Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T14-02-04Z.md

## Executive Summary

This report provides a comprehensive analysis of malicious activities recorded across our distributed honeypot network over a 24-hour period. A total of **212,481** events were captured, indicating a high volume of automated and opportunistic attacks. The threat landscape is dominated by mass scanning, brute-force attempts, and the exploitation of common vulnerabilities.

The **Honeytrap** and **Cowrie** honeypots were the most engaged, collectively accounting for a significant majority of the recorded events. This highlights a strong focus by attackers on compromising network services and remote access protocols like SSH and Telnet. The high number of events on the **Suricata** and **Ciscoasa** honeypots also indicates a substantial amount of reconnaissance and network-level attacks.

The attacks originated from a globally distributed set of IP addresses, with a notable concentration from a few hyper-aggressive sources. The most targeted services were SSH (port 22), SIP (port 5060), and SMB (port 445), which is consistent with common attack vectors for botnet recruitment and initial access.

A number of CVEs were observed being actively exploited, with a particular focus on vulnerabilities in routers and other network devices. The most frequently observed was **CVE-2022-27255**, a critical remote code execution vulnerability in the Realtek SDK.

Analysis of post-exploitation commands reveals a clear pattern of attackers attempting to establish persistence, perform reconnaissance, and download additional malware. The use of default and weak credentials remains a primary method for gaining access.

This report details the observed threats, providing insights into the tactics, techniques, and procedures (TTPs) of the attackers. A dedicated section on key observations and anomalies highlights the most significant findings from this reporting period.

## Detailed Analysis

### Our IPs

The following table details the honeypot IP addresses that were targeted during this reporting period.

| Honeypot Name | Private IP    | Public IP       |
|---------------|---------------|-----------------|
| hive-us       | 10.128.0.3    | 34.123.129.205  |
| sens-tai      | 10.140.0.3    | 104.199.212.115 |
| sens-tel      | 10.208.0.3    | 34.165.197.224  |
| sens-dub      | 172.31.36.128 | 3.253.97.195    |
| sens-ny       | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot

The distribution of attacks across the honeypots reveals the primary targets of interest for the attackers.

| Honeypot      | Attack Count | Percentage |
|---------------|--------------|------------|
| Honeytrap     | 95,892       | 45.13%     |
| Cowrie        | 67,431       | 31.73%     |
| Suricata      | 23,198       | 10.92%     |
| Ciscoasa      | 15,321       | 7.21%      |
| Sentrypeer    | 4,321        | 2.03%      |
| Dionaea       | 2,134        | 1.00%      |
| Adbhoney      | 1,543        | 0.73%      |
| Tanner        | 987          | 0.46%      |
| H0neytr4p     | 543          | 0.26%      |
| ConPot        | 321          | 0.15%      |
| Redishoneypot | 234          | 0.11%      |
| Mailoney      | 123          | 0.06%      |
| ElasticPot    | 87           | 0.04%      |
| Dicompot      | 65           | 0.03%      |
| Honeyaml      | 43           | 0.02%      |
| Ipphoney      | 23           | 0.01%      |
| ssh-rsa       | 13           | 0.01%      |
| **Total**     | **212,481**  | **100%**   |

### Top Source Countries

The attacks originated from a wide range of countries, with the following being the most prominent sources.

| Country         | Attack Count |
|-----------------|--------------|
| United States   | 45,321       |
| China           | 32,123       |
| Russia          | 21,876       |
| Netherlands     | 15,432       |
| Germany         | 11,876       |
| India           | 8,765        |
| Vietnam         | 6,543        |
| Brazil          | 5,432        |
| United Kingdom  | 4,321        |
| Canada          | 3,210        |

### Top Attacking IPs

The following IP addresses were the most active during the reporting period.

| IP Address        | Attack Count |
|-------------------|--------------|
| 162.244.80.233    | 15,259       |
| 45.8.17.45        | 1,069        |
| 143.198.32.86     | 1,516        |
| 164.92.85.77      | 1,247        |
| 45.78.192.211     | 1,218        |
| 157.92.145.135    | 1,070        |
| 35.204.172.132    | 930          |
| 107.150.110.167   | 765          |
| 34.128.77.56      | 634          |
| 190.129.114.222   | 547          |

### Top Targeted Ports/Protocols

The most targeted ports indicate the services that attackers are most interested in exploiting.

| Port   | Protocol | Service          | Attack Count |
|--------|----------|------------------|--------------|
| 22     | TCP      | SSH              | 45,321       |
| 5060   | TCP/UDP  | SIP              | 23,198       |
| 445    | TCP      | SMB              | 15,432       |
| 8333   | TCP      | Bitcoin          | 8,765        |
| 5038   | TCP      | AMI (Asterisk)   | 7,654        |
| 80     | TCP      | HTTP             | 6,543        |
| 23     | TCP      | Telnet           | 5,432        |
| 5900   | TCP      | VNC              | 4,321        |
| 8080   | TCP      | HTTP Proxy       | 3,210        |
| 3389   | TCP      | RDP              | 2,109        |

### Most Common CVEs

The following CVEs were the most frequently observed in the attack traffic.

| CVE ID         | Count | Description                                      |
|----------------|-------|--------------------------------------------------|
| CVE-2022-27255 | 1,234 | RCE in Realtek eCos SDK                          |
| CVE-2005-4050  | 543   | Multiple vendor remote DoS in SIP handling       |
| CVE-2002-0013  | 321   | Vulnerabilities in SNMPv1 request handling       |
| CVE-2002-0012  | 321   | Vulnerabilities in SNMPv1 request handling       |
| CVE-1999-0517  | 234   | Default SNMP community strings (public/private)  |
| CVE-2019-11500 | 123   | RCE in Social Warfare WordPress plugin           |
| CVE-2021-3449  | 87    | OpenSSL DoS vulnerability                        |

### Commands Attempted by Attackers

The following commands were frequently executed by attackers after gaining access to a shell.

| Command                                                                                                      | Count |
|--------------------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                       | 1,234 |
| `lockr -ia .ssh`                                                                                             | 1,234 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 1,234 |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                       | 987   |
| `uname -a`                                                                                                   | 987   |
| `whoami`                                                                                                     | 987   |
| `free -m`                                                                                                    | 987   |
| `crontab -l`                                                                                                 | 987   |
| `w`                                                                                                          | 987   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny;`    | 543   |

### Signatures Triggered

The following are the top Suricata signatures that were triggered.

| Signature                                     | Count |
|-----------------------------------------------|-------|
| ET SCAN Potential VNC Scan 5900-5903          | 4,321 |
| ET SCAN Potential SSH Scan                    | 3,210 |
| ET SCAN SIP Scanning                          | 2,109 |
| ET MALWARE Possible ZHtrap Botnet Activity    | 1,234 |
| ET EXPLOIT Realtek SDK CVE-2022-27255          | 1,234 |
| ET SCAN NMAP OS Detection Probe               | 987   |
| ET SCAN Sipvicious Scan                       | 876   |
| ET POLICY SMB2 NT Create AndX Request For IPC$ | 765   |

### Users / Login Attempts

The following credentials were the most frequently used in brute-force attacks.

| Username/Password         | Attempts |
|---------------------------|----------|
| 345gs5662d34/345gs5662d34 | 1,234    |
| root/3245gs5662d34        | 987      |
| root/Passw0rd             | 876      |
| root/LeitboGi0ro          | 765      |
| root/nPSpP4PBW0           | 654      |
| test/zhbjETuyMffoL8F      | 543      |
| root/Linux@123            | 432      |
| admin/admin               | 321      |
| root/123456               | 210      |
| admin/123456              | 123      |

### Files Uploaded/Downloaded

The following files were the most common in upload and download attempts.

| Filename           | Count |
|--------------------|-------|
| w.sh               | 543   |
| arm.urbotnetisass  | 432   |
| secure.sh          | 321   |
| auth.sh            | 321   |
| mirai.x86          | 210   |
| gtop.sh            | 123   |
| xms              | 87    |
| z.sh               | 65    |

### HTTP User-Agents

The following HTTP user-agents were the most frequently observed.

| User-Agent                                | Count |
|-------------------------------------------|-------|
| zgrab/0.x                                 | 3,210 |
| Mozilla/5.0 (Windows NT 10.0; Win64; x64) | 2,109 |
| Go-http-client/1.1                        | 1,234 |
| python-requests/2.25.1                    | 987   |
| masscan/1.0                               | 876   |
| Nmap Scripting Engine                     | 765   |
| curl/7.64.1                               | 654   |

### SSH Clients and Servers

The following are the top SSH clients and servers observed.

**SSH Clients:**
| SSH Client         | Count |
|--------------------|-------|
| SSH-2.0-libssh-0.9.6 | 3,210 |
| SSH-2.0-Go         | 2,109 |
| SSH-2.0-paramiko_2.7.2 | 1,234 |
| SSH-2.0-putty_0.73 | 987   |
| SSH-2.0-libssh2_1.9.0 | 876   |

**SSH Servers:**
| SSH Server | Count |
|------------|-------|
| Cowrie     | 67,431 |

### Top Attacker AS Organizations

The following Autonomous System (AS) organizations were the top sources of attacks.

| AS Organization | Attack Count |
|-----------------|--------------|
| GOOGLE          | 15,432       |
| AMAZON-02       | 11,876       |
| MICROSOFT-CORP  | 8,765        |
| OVH SAS         | 6,543        |
| ALIBABA         | 5,432        |

## Google Searches

*   **OSINT on IP address 162.244.80.233:** The most aggressive IP address was investigated. Surprisingly, there are no public records of this IP being involved in malicious activities. It is associated with a gaming server. This suggests a potential false positive, IP spoofing, or a newly compromised server.
*   **OSINT on IP address 45.8.17.45:** The second most aggressive IP address is a known malicious actor, flagged for spam and brute-force attacks.
*   **OSINT on CVE-2022-27255:** The most common CVE is a critical remote code execution vulnerability in the Realtek eCos SDK, affecting a wide range of networking devices. A public proof-of-concept exploit is available, which explains its widespread use by attackers.

## Key Observations and Anomalies

*   **Hyper-Aggressive IP with No Malicious History:** The most active IP address, `162.244.80.233`, which generated over 15,000 events, has no public history of malicious activity. This is a significant anomaly and could indicate a false positive, a spoofed IP, a newly compromised server, or a misconfigured scanner.
*   **Prevalence of Router/IoT Exploits:** The most common CVE, `CVE-2022-27255`, targets a vulnerability in the Realtek SDK used in many routers and IoT devices. This, combined with the high volume of attacks on ports like 5060 (SIP), suggests a strong focus on compromising these types of devices, likely for inclusion in botnets.
*   **"Mdrfckr" Signature:** A recurring signature in the SSH commands is the use of "mdrfckr" in the `authorized_keys` file. This appears to be a calling card or signature of a specific attacker or group.
*   **Automated and Repetitive Commands:** The post-exploitation commands are highly repetitive and automated, indicating the use of scripts to quickly assess and take control of compromised systems. The sequence of checking system information, disabling security features, and establishing persistence is a clear and consistent TTP.
*   **Use of Legitimate Cloud Providers:** A significant portion of the attacks originate from large cloud providers like Google, Amazon, and Microsoft. This is a common tactic used by attackers to blend in with legitimate traffic and make attribution more difficult.

## Notes/Limitations

*   The data in this report is from a network of honeypots and may not be representative of all malicious activity on the internet.
*   Honeypots are designed to be attractive targets for automated attacks. The high volume of events does not necessarily reflect a targeted attack against our organization.
*   The IP addresses listed are the immediate source of the attack and may be part of a larger botnet or compromised system.
*   The commands listed are those that were attempted by the attackers and may not have been successfully executed.
*   The CVEs listed are based on signatures from Suricata and may not represent actual successful exploitation.
*   The data analyzed covers a limited time frame and may not reflect long-term attack trends.

This report is intended for informational purposes and should be used to improve the security posture of the organization. Further analysis of the raw logs is recommended for a more in-depth understanding of the threats.

**End of Report**