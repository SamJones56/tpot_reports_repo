# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T20:23:01Z

**Timeframe:** 2025-10-10T08:20:01Z to 2025-10-10T20:00:01Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-10T09:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T10:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T11:01:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T12:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T13:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T14:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T16:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T17:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T18:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T19:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-10T20:02:10Z.md

---

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the past 12 hours. A total of **162,111 events** were aggregated and examined from 11 summary reports. The vast majority of these attacks were automated, focusing on brute-force attempts against SSH (port 22) and exploitation of SMB vulnerabilities (port 445).

The most targeted honeypot was **Cowrie**, which emulates SSH and Telnet services, indicating a strong focus by attackers on gaining shell access to vulnerable devices. A significant and recurring pattern of activity was observed: a highly automated script was used across a multitude of IP addresses to perform initial system reconnaissance (`uname`, `lscpu`, `free`, etc.) and then immediately attempt to install a persistent SSH key for backdoor access.

Several specific malware campaigns were identified through downloaded filenames, including the **Mozi and Mirai IoT botnets**, as well as the **RondoDoX loader**. These findings confirm that a substantial portion of the observed traffic is aimed at recruiting our honeypot devices into botnet armies. Additionally, a high volume of scans for the **DoublePulsar backdoor** indicates that attackers are still actively seeking to exploit the vulnerabilities associated with the EternalBlue exploit.

While OSINT investigations on the most aggressive attacking IPs did not reveal a consistently negative reputation on public blocklists, the sheer volume and coordinated nature of their attacks suggest they are either compromised systems or dedicated attack servers operating in a botnet.

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

### Attacks by Honeypot (Aggregated)
| Honeypot        | Event Count |
|-----------------|-------------|
| Cowrie          | 77,554      |
| Honeytrap       | 29,215      |
| Suricata        | 22,540      |
| Ciscoasa        | 17,582      |
| Dionaea         | 5,913       |
| Mailoney        | 4,680       |
| Sentrypeer      | 2,058       |
| ElasticPot      | 734         |
| Tanner          | 715         |
| H0neytr4p       | 401         |
| Redishoneypot   | 285         |
| Miniprint       | 166         |
| Adbhoney        | 123         |
| Heralding       | 133         |
| ssh-rsa         | 101         |
| Honeyaml        | 105         |
| ConPot          | 102         |
| Dicompot        | 54          |
| Wordpot         | 1           |
| Ipphoney        | 16          |
| Medpot          | 3           |

### Top Source Countries (Representative Sample)
*(Note: Full country data requires GeoIP lookup on all IPs, this is a sample from logs)*
- United States
- China
- Russia
- Vietnam
- Netherlands
- Germany
- India

### Top 20 Attacking IPs (Aggregated)
| IP Address        | Attack Count |
|-------------------|--------------|
| 167.250.224.25    | 8,367        |
| 51.89.1.86        | 2,496        |
| 109.237.71.198    | 2,200        |
| 176.65.141.117    | 2,000        |
| 50.6.225.98       | 1,569        |
| 196.188.109.42    | 1,497        |
| 49.145.98.224     | 1,400        |
| 113.182.51.157    | 1,362        |
| 51.89.1.87        | 1,250        |
| 88.210.63.16      | 1,200        |
| 39.34.90.61       | 1,090        |
| 85.208.84.144     | 1,017        |
| 85.208.84.142     | 1,009        |
| 134.199.195.1     | 999          |
| 103.122.61.254    | 945          |
| 51.250.65.61      | 789          |
| 143.44.164.80     | 767          |
| 1.53.140.58       | 725          |
| 36.85.250.177     | 644          |
| 154.92.109.196    | 605          |

### Top Targeted Ports/Protocols (Aggregated)
| Port/Protocol | Attack Count |
|---------------|--------------|
| 22 (SSH)      | 10,752       |
| 445 (SMB)     | 6,000+       |
| 25 (SMTP)     | 4,000+       |
| 5060 (SIP)    | 2,200+       |
| 5903 (VNC)    | 1,800+       |
| 1433 (MSSQL)  | 1,000+       |
| 8333 (Bitcoin)| 900+         |
| 80 (HTTP)     | 800+         |
| 9200 (Elastic)| 700+         |
| 21 (FTP)      | 600+         |
| 6379 (Redis)  | 300+         |
| 23 (Telnet)   | 250+         |

### Most Common CVEs (Aggregated)
- CVE-2002-0013, CVE-2002-0012 (IIS MDAC/RDS)
- CVE-2022-27255 (MitraStar)
- CVE-2019-11500 (ProFTPD)
- CVE-2021-3449
- CVE-1999-0183
- CVE-1999-0517 (Multiple Vendor RPC)
- CVE-2005-4050
- CVE-2024-3721
- CVE-2016-20016 (Cisco)
- CVE-2018-10561, CVE-2018-10562 (Dasan GPON)
- CVE-2024-4577 (PHP-CGI)
- CVE-2021-41773, CVE-2021-42013 (Apache HTTP Server)
- CVE-2006-2369
- CVE-2021-35394
- CVE-2002-1149

### Commands Attempted by Attackers (Aggregated & Unique)
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys`
- `uname -a`
- `whoami`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `crontab -l`
- `tftp; wget; /bin/busybox DYVDP`
- `cd /data/local/tmp; ...; ./boatnet.arm7 arm7`
- `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`
- `echo -ne ... >>./categumh`
- `rondo.kqa.sh|sh&echo`

### Signatures Triggered (Top 10 Aggregated)
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET FTP FTP PWD/CWD command attempt without login
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET SCAN Sipsak SIP scan

### Users / Login Attempts (Top 20 Sample)
- 345gs5662d34/345gs5662d34
- root/[numerous complex passwords]
- ubuntu/3245gs5662d34
- admin/[various common passwords]
- guest/guest13
- test/test1234567
- support/Support2016
- vpn/P@ssw0rd
- default/uploader
- supervisor/supervisor22
- debian/debian7
- github/githubgithub
- postgres/1234
- dockeruser/dockeruser!
- centos/centos10
- zabbix/zabbix
- minecraft/123minecraft
- teamspeak3/password1
- runner/runnerpass
- ali/ali!

### Files Uploaded/Downloaded (Notable Malware)
- `Mozi.a+varcron`
- `boatnet.mpsl`
- `boatnet.arm7`
- `rondo.kqa.sh`
- `rondo.qpu.sh`
- `wget.sh`, `w.sh`, `c.sh` (Generic script names used for staged downloads)
- `mips.nn` (Likely MIPS architecture malware)

### OSINT Information
| Indicator                               | OSINT Summary                                                                                                                                                                                                                         |
|-----------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **IP: 167.250.224.25**                  | No significant negative reputation on public threat intelligence platforms like AbuseIPDB or VirusTotal. The high volume of attacks suggests it is likely a compromised server or part of a botnet, evading public blocklists for now. |
| **IP: 51.89.1.86**                      | Similar to the above, this IP address has no widespread public threat intelligence indicating malicious activity, despite its high volume of attacks on our honeypots.                                                               |
| **IP: 39.34.90.61**                     | Associated in our logs with the DoublePulsar backdoor. Public OSINT does not yet link this specific IP to DoublePulsar, suggesting our honeypot may be an early detector of this IP's malicious activity.                             |
| **Malware: Mozi.a+varcron**             | This is a known command used by the **Mozi botnet** to infect IoT devices, specifically Vacron NVRs. The Mozi botnet is a P2P botnet known for DDoS attacks, data exfiltration, and payload execution.                               |
| **Malware: rondo.kqa.sh**               | This script is linked to the **RondoDoX malware loader**, which is used to distribute payloads for the **Mirai botnet**. This confirms that attackers are attempting to recruit our honeypots into a Mirai variant botnet.              |
| **Exploit: DoublePulsar**               | This is a backdoor developed by the NSA and leaked by the Shadow Brokers. It was famously used with the EternalBlue exploit in the WannaCry ransomware attacks. Its continued presence indicates that many systems remain unpatched.       |

---

## Key Observations and Anomalies

1.  **Industrial-Scale Automation:** The attacks are not random; they are part of a massive, automated campaign. The exact same sequence of reconnaissance commands followed by an attempt to install an SSH key was observed from hundreds of different IP addresses, confirming the use of a sophisticated script or botnet.

2.  **Targeting IoT and Embedded Devices:** The identification of malware such as **Mozi**, **Mirai (via RondoDoX)**, and payloads for ARM/MIPS architectures (`boatnet.arm7`, `mips.nn`) demonstrates a clear focus on compromising IoT devices (like routers, DVRs, NVRs) to expand botnet armies.

3.  **Attacker "Signature" / Taunt:** A recurring SSH key installation command included the string `"mdrfckr"` in the public key. This serves as a taunt or a signature, providing a unique marker for this specific attacker or campaign.

4.  **DoublePulsar Still a Threat:** The high number of Suricata alerts for the DoublePulsar backdoor is a stark reminder that vulnerabilities from the EternalBlue exploit (patched in 2017) are still being actively and widely exploited by attackers.

5.  **Suspicious File Payloads:** The use of commands like `echo -ne ... >> ./[filename]` and the downloading of generic shell scripts (`w.sh`, `c.sh`, `wget.sh`) are classic techniques for staging malware. The scripts download and execute the main payload in stages to evade simple detection.

6.  **Discrepancy in IP Reputation:** A key anomaly is the lack of negative reputation for some of the most aggressive attacking IPs in public databases. This could mean these are newly compromised machines or that the attackers are using infrastructure that is not yet widely reported. Our honeypot network is acting as an early warning system for these threats.

---
