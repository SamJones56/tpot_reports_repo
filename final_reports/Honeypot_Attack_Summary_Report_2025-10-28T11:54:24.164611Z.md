Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T11:48:53.010302Z
**Timeframe:** 2025-09-28T00:00:00.000Z to 2025-10-05T23:59:59.999Z

### Executive Summary

This report summarizes the malicious activity observed on our honeypot network between September 28, 2025, and October 5, 2025. During this period, our honeypots registered a total of **2,373,530** attacks, originating from a diverse range of countries and autonomous systems. The majority of attacks were automated and indiscriminate, consisting of mass scanning for open ports and brute-force login attempts.

The most prominent attack vector was the exploitation of common vulnerabilities in VoIP and network management protocols, with **CVE-2005-4050** and **CVE-2002-0013** being the most frequently targeted. This suggests that a significant portion of the attack traffic is from legacy botnets or attackers using outdated exploit kits.

Login attempts were overwhelmingly targeted at the `root` user, with common passwords such as `123456` and `password` being the most frequently used. This is indicative of unsophisticated, dictionary-based brute-force attacks.

OSINT analysis of the top attacking IP addresses, `92.205.59.208` and `176.65.141.117`, reveals that they are part of hosting networks known for malicious activities, including distributing banking trojans, phishing, and brute-force attacks.

While the majority of the observed activity was unsophisticated, the sheer volume of attacks and the presence of IPs associated with more advanced threats highlight the persistent and evolving nature of the cyber threat landscape.

### Detailed Analysis

#### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

#### Attacks by Honeypot

| Honeypot | Attack Count |
|---|---|
| Cowrie | 1,011,561 |
| Honeytrap | 377,986 |
| Sentrypeer | 303,422 |
| Ciscoasa | 279,400 |
| Dionaea | 190,686 |
| Mailoney | 174,340 |
| Tanner | 8,840 |
| H0neytr4p | 6,733 |
| Adbhoney | 4,719 |
| Redishoneypot | 3,643 |

#### Top Source Countries

| Country | Attack Count |
|---|---|
| United States | 430,677 |
| France | 253,764 |
| Germany | 172,806 |
| Ukraine | 156,452 |
| Brazil | 142,893 |
| Vietnam | 134,727 |
| China | 119,079 |
| Indonesia | 113,415 |
| The Netherlands| 66,345 |
| Hong Kong | 58,569 |

#### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 92.205.59.208 | 231,492 |
| 176.65.141.117| 106,929 |
| 45.234.176.18 | 82,542 |
| 103.130.215.15| 67,501 |
| 160.25.118.10 | 52,416 |
| 86.54.42.238 | 46,023 |
| 161.35.152.121| 42,255 |
| 185.156.73.166| 42,246 |
| 45.187.123.146 | 41,481 |
| 92.63.197.55 | 38,298 |

#### Top Targeted Ports/Protocols

| Port | Protocol | Attack Count |
|---|---|---|
| 5060| - | 303,422 |
| 445 | smbd | 178,803 |
| 25 | - | 174,340 |
| 22 | - | 161,613 |
| 8333| - | 10,160 |
| 80 | - | 9,582 |
| 23 | - | 7,769 |
| 443 | - | 7,667 |
| 6379| - | 4,230 |
| 3306| mysqld | 3,163 |

#### Most Common CVEs

| CVE | Count |
|---|---|
| CVE-2005-4050 | 1,461 |
| CVE-2002-0013 CVE-2002-0012 | 1,292 |
| CVE-2006-2369 | 734 |
| CVE-2002-0013 CVE-2002-0012 CVE-1999-0517 | 712 |
| CVE-2021-44228 CVE-2021-44228 | 652 |
| CVE-2021-3449 CVE-2021-3449 | 618 |
| CVE-2019-11500 CVE-2019-11500 | 591 |
| CVE-2016-5696 | 381 |
| CVE-2022-27255 CVE-2022-27255 | 299 |
| CVE-1999-0265 | 107 |

#### Commands Attempted by Attackers

| Command | Count |
|---|---|
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 3,926 |
| lockr -ia .ssh | 3,926 |
| uname -a | 3,468 |
| cat /proc/cpuinfo | grep name | wc -l | 3,332 |
| cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}' | 2,379 |
| whoami | 2,158 |
| lscpu | grep Model | 2,152 |
| uname | 1,844 |
| top | 1,687 |
| ls -lh $(which ls) | 1,684 |

#### Signatures Triggered

| Signature ID | Signature | Count |
|---|---|---|
| 2100560 | GPL INFO VNC server response | 1,934,896 |
| 2100384 | GPL ICMP PING | 344,808 |
| 2210051 | SURICATA STREAM Packet with broken ack | 156,212 |
| 2210027 | SURICATA STREAM ESTABLISHED SYN resend with different seq | 99,848 |
| 2024766 | ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 97,244 |
| 2402000 | ET DROP Dshield Block Listed Source group 1 | 59,560 |
| 2210045 | SURICATA STREAM Packet with invalid ack | 40,612 |
| 2210029 | SURICATA STREAM ESTABLISHED invalid ack | 40,449 |
| 2210065 | SURICATA STREAM ESTABLISHED ack for ZWP data | 40,449 |
| 2200003 | SURICATA IPv4 truncated packet | 19,550 |

#### Users / Login Attempts

| Username | Count |
|---|---|
| root | 65,338 |
| admin | 5,482 |
| 345gs5662d34 | 3,687 |
| user | 3,303 |
| test | 2,600 |
| oracle | 1,816 |
| ubuntu | 1,466 |
| postgres | 1,443 |
| ftpuser | 987 |
| git | 932 |

| Password | Count |
|---|---|
| 123456 | 14,500 |
| 345gs5662d34 | 3,687 |
| 3245gs5662d34 | 3,679 |
| | 3,582 |
| 123 | 2,567 |
| password | 1,280 |
| 1234 | 1,228 |
| nPSpP4PBW0 | 1,094 |
| root | 833 |
| admin123 | 778 |

#### HTTP User-Agents

| User-Agent | Count |
|---|---|
| elastic/6.2.37 (linux-amd64) | 309 |
| Mozilla/5.0 zgrab/0.x | 230 |
| Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/) | 224 |
| Go-http-client/1.1 | 182 |
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36 | 122 |
| Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1 | 101 |
| Hello from Palo Alto Networks... | 91 |
| Mozilla/5.0 (compatible; Odin; https://docs.getodin.com/) | 88 |
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0)... | 69 |
| Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0 | 66 |

#### SSH Clients and Servers

No data available in logs.

#### Top Attacker AS Organizations

| ASN | AS Organization | Count |
|---|---|---|
| 21499 | Host Europe GmbH | 231,493 |
| 14061 | DIGITALOCEAN-ASN | 185,802 |
| 211736| FOP Dmytro Nedilskyi | 147,254 |
| 215540| Global Connectivity Solutions Llp | 132,808 |
| 214967| Optibounce, LLC | 106,949 |
| 396982| GOOGLE-CLOUD-PLATFORM | 87,217 |
| 267369| MAFREDINE TELECOMUNICACOES EIRELI | 82,542 |
| 135953| Vietnam Online Network Solution Joint Stock Compnay | 67,501 |
| 153096| PT High Speed Connection Network | 52,416 |
| 268546| RIOTELE-REAL INTERNET OPTICA TELECOMUNICACOES | 41,481 |

### OSINT on Commands, IPs, and CVEs

#### OSINT on High-Frequency IPs

*   **92.205.59.208:** This IP address is associated with Host Europe GmbH, a subsidiary of GoDaddy. It is flagged as malicious by multiple sources and is part of a hosting network known for distributing banking trojans, phishing, and other malware.
*   **176.65.141.117:** This IP is associated with SkyLink Data Center BV in the Netherlands and is listed on several threat intelligence blocklists. It has been identified as a source of brute-force attacks and SMTP abuse. The lack of an associated domain suggests its use in automated attacks or as part of a botnet.

#### OSINT on CVEs

*   **CVE-2005-4050:** This is a critical buffer overflow vulnerability in Multi-Tech VoIP devices. It allows for remote code execution via a specially crafted SIP INVITE message. While the vulnerability is severe, there is no public evidence of its active exploitation in the wild. Its prevalence in the honeypot logs suggests the continued operation of legacy botnets or attackers using outdated exploit kits.
*   **CVE-2002-0013:** This is a widespread vulnerability in SNMPv1 that affects a vast range of hardware and software. It allows for a denial-of-service and, in some cases, administrative privilege escalation. Like CVE-2005-4050, its continued presence in attack traffic points to the use of older, well-known exploits.

### Key Observations and Anomalies

*   **Prevalence of Legacy Exploits:** The most frequently observed CVEs are from 2005 and 2002. This indicates that a significant portion of the attack traffic is generated by older botnets or attackers using well-known, publicly available exploits. This is a common characteristic of "background noise" on the internet, but it also highlights the fact that many systems remain unpatched and vulnerable to these old exploits.
*   **Hosting Providers as a Source of Malicious Traffic:** The top attacking IPs and ASNs are predominantly associated with hosting providers. This is a common trend, as attackers often use compromised servers or cheap hosting services to launch their attacks.
*   **Unusual Usernames/Passwords:** The username/password combination `345gs5662d34` is of interest. While it could be a randomly generated string, its repeated use suggests it may be a default credential for a specific type of device or a hardcoded value in a particular malware strain. Further research into this string could reveal more information about the attackers' tools and methods.
*   **DoublePulsar Backdoor:** The presence of the "DoublePulsar Backdoor" signature is noteworthy. DoublePulsar is a backdoor associated with the EternalBlue exploit, which was famously used in the WannaCry ransomware attacks. While the volume is not as high as some of the other signatures, it indicates that attackers are still actively scanning for and attempting to exploit this vulnerability.

### Unusual Attacker Origins

The vast majority of attacks originate from a diverse range of countries and hosting providers, which is typical for a honeypot. There are no particular "unusual" origins in the traditional sense, as the observed traffic is consistent with the global nature of cybercrime. However, the concentration of attacks from a small number of hosting providers is a point of concern and warrants further investigation.
