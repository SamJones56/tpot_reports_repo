# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T05:41:22Z
**Timeframe:** 2025-10-02T20:01:53Z to 2025-10-03T04:02:10Z
**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-02T20:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T21:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T22:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-02T23:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T00:01:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T01:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T02:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T03:01:54Z.md

## Executive Summary

This report provides a comprehensive analysis of attacks recorded by our honeypot network over the last 10 hours. A total of 109,141 malicious events were captured and analysed. The most active honeypots were Cowrie, Ciscoasa, and Suricata, indicating a high volume of SSH/Telnet brute-force attempts and network-level attacks.

The majority of attacks originated from a small number of highly aggressive IP addresses, with a significant concentration on ports associated with email (25), VoIP (5060), SSH (22), and SMB (445). Attackers were observed attempting to exploit a wide range of vulnerabilities, including both recent and older CVEs, suggesting a broad and opportunistic approach.

A consistent pattern of post-exploitation activity was observed, with attackers attempting to establish persistent access by adding their SSH keys to the `authorized_keys` file. Additionally, there were numerous attempts to download and execute malicious scripts, including those associated with botnets and cryptocurrency miners. OSINT analysis of the top attacking IPs revealed that several are known malicious actors, while others are hosted on infrastructure with a history of abuse.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
- sens-ny    | 10.108.0.2      | 161.35.180.163|

### Attacks by Honeypot

| Honeypot | Count |
|---|---|
| Cowrie | 33433 |
| Ciscoasa | 21341 |
| Suricata | 17176 |
| Sentrypeer | 12536 |
| Mailoney | 10041 |
| Dionaea | 3839 |
| Honeytrap | 2965 |
| Tanner | 761 |
| Adbhoney | 248 |
| H0neytr4p | 242 |
| ConPot | 189 |
| ElasticPot | 117 |
| Miniprint | 108 |
| Redishoneypot | 99 |
| Dicompot | 63 |
| Heralding | 25 |
| Honeyaml | 20 |
| Ipphoney | 2 |

### Top Attacking IPs

| IP Address | Count |
|---|---|
| 176.65.141.117 | 8200 |
| 23.175.48.211 | 6228 |
| 203.172.130.107 | 1460 |
| 178.128.232.91 | 1244 |
| 86.54.42.238 | 821 |
| 113.161.22.87 | 3147 |
| 40.134.34.145 | 1377 |
| 103.155.105.206 | 1436 |
| 49.207.240.113 | 444 |
| 123.58.213.52 | 442 |

### Top Targeted Ports/Protocols

| Port/Protocol | Count |
|---|---|
| 5060 | 12536 |
| 25 | 10041 |
| 22 | 4038 |
| TCP/445 | 2803 |
| 80 | 698 |
| 443 | 253 |
| 23 | 244 |
| 9200 | 83 |
| 6379 | 60 |
| 1433 | 59 |

### Most Common CVEs

| CVE |
|---|
| CVE-2022-27255 |
| CVE-2002-0013 |
| CVE-2002-0012 |
| CVE-1999-0517 |
| CVE-2019-11500 |
| CVE-2021-3449 |
| CVE-2021-35394 |
| CVE-2023-26801 |
| CVE-2006-2369 |
| CVE-1999-0183 |
| CVE-2016-6563 |
| CVE-2003-0825 |
| CVE-2019-12263 |
| CVE-2019-12261 |
| CVE-2019-12260 |
| CVE-2019-12255 |
| CVE-2009-2765 |
| CVE-2019-16920 |
| CVE-2023-31983 |
| CVE-2020-10987 |
| CVE-2023-47565 |
| CVE-2015-2051 |
| CVE-2024-33112 |
| CVE-2022-37056 |
| CVE-2019-10891 |
| CVE-2014-6271 |
| CVE-2024-4577 |
| CVE-2021-41773 |
| CVE-2021-42013 |
| CVE-2002-0953 |
| CVE-2020-2551 |

### Commands Attempted by Attackers

| Command |
|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `lockr -ia .ssh` |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` |
| `cat /proc/cpuinfo | grep name | wc -l` |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` |
| `uname -a` |
| `whoami` |
| `Enter new UNIX password:` |
| `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...` |
| `pm path com.ufo.miner` |
| `pm install /data/local/tmp/ufo.apk` |
| `rm -f /data/local/tmp/ufo.apk` |
| `am start -n com.ufo.miner/com.example.test.MainActivity` |

### Signatures Triggered

| Signature |
|---|
| ET SCAN Sipsak SIP scan |
| ET DROP Dshield Block Listed Source group 1 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET SCAN NMAP -sS window 1024 |
| ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255) |
| ET INFO Reserved Internal IP Traffic |
| ET INFO Login Credentials Possibly Passed in POST Data |
| ET SCAN Potential SSH Scan |
| ET CINS Active Threat Intelligence Poor Reputation IP group 49 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32 |
| ET INFO VNC Authentication Failure |

### Users / Login Attempts

| Username/Password |
|---|
| 345gs5662d34/345gs5662d34 |
| root/nPSpP4PBW0 |
| root/2glehe5t24th1issZs |
| foundry/foundry |
| test/zhbjETuyMffoL8F |
| seekcy/Joysuch@Locate2020 |
| root/marcel |
| ubuntu/test12345 |
| moderator/moderator |
| agent/agent |
| root/LeitboGi0ro |
| superadmin/admin123 |
| example/ |
| sa/ |
| root/ |
| mysql/mysql |
| tomcat/tomcat |
| developer/developer |
| demo/demo |
| ansible/test123 |

### Files Uploaded/Downloaded

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
| 11 |
| fonts.gstatic.com |
| css?family=Libre+Franklin... |
| ie8.css?ver=1.0 |
| html5.js?ver=3.7.3 |
| server.cgi... |
| busybox |
| rondo.qre.sh |
| rondo.sbx.sh |
| login_pic.asp |
| sh |
| a |
| Help:Contents |
| Mozi.m |
| soap-envelope |
| addressing |
| discovery |
| devprof |
| soap:Envelope |

### HTTP User-Agents

*No user agents were logged in this timeframe.*

### SSH Clients and Servers

*No specific SSH clients or servers were identified in the logs for this period.*

### Top Attacker AS Organizations

*No attacker AS organizations were identified in the logs for this period.*

## Google Searches

- Conducted OSINT on the following IP addresses: 176.65.141.117, 23.175.48.211, 203.172.130.107, 178.128.232.91, 86.54.42.238, 113.161.22.87, 40.134.34.145, 103.155.105.206, 49.207.240.113, 123.58.213.52

## Key Observations and Anomalies

1.  **High-Volume, Coordinated Attacks:** The sheer volume of attacks from a small number of IPs, such as 176.65.141.117 and 23.175.48.211, suggests the use of botnets or other automated attack infrastructure. The consistency of commands and targeted ports across different timeframes further supports this conclusion.

2.  **Persistent Access Attempts:** A recurring and prominent anomaly was the repeated attempt by attackers to add a specific SSH key to the `authorized_keys` file. This is a clear indication of a concerted effort to establish persistent, passwordless access to compromised systems.

3.  **Exploitation of Old and New Vulnerabilities:** The wide range of CVEs targeted highlights the fact that attackers are not just focusing on the latest vulnerabilities. The continued exploitation of older CVEs, such as CVE-2002-0013, suggests that many systems remain unpatched and vulnerable to well-known exploits.

4.  **Targeting of IoT and Network Devices:** The prevalence of attacks targeting CVE-2022-27255 (a Realtek SDK vulnerability) and the downloading of files like "Mozi.m" and "boatnet.mpsl" indicate a strong focus on compromising IoT devices and incorporating them into botnets.

5.  **Evidence of Cryptocurrency Mining:** The presence of commands related to "ufo.miner" suggests that some attackers are attempting to install cryptocurrency mining software on compromised devices, seeking to monetize their access.

6.  **OSINT on Top Attackers:** OSINT analysis of the top attacking IPs revealed that several are known malicious actors. For example, **123.58.213.52** and **86.54.42.238** have been flagged for spamming and port scanning. Others, such as **178.128.232.91** (DigitalOcean) and **40.134.34.145** (Google Cloud), are hosted on infrastructure with a known history of abuse, making it difficult to attribute the attacks to a specific individual or group.

7.  **DoublePulsar Resurgence:** The high number of "DoublePulsar Backdoor" signatures triggered, particularly from IP **203.172.130.107**, indicates that this malware, associated with the EternalBlue exploit, remains a significant threat. This suggests that many systems are still vulnerable to this well-known exploit.

This concludes the Honeypot Attack Summary Report. Continuous monitoring and analysis are recommended to track evolving threats and enhance our defensive posture.
