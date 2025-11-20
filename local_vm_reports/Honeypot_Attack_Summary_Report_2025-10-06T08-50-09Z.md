# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T08:49:00Z
**Timeframe:** 2025-10-05T08:02:30Z to 2025-10-06T07:02:22Z

**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-05T08:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T09:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T10:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T11:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T12:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T13:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T14:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T16:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T17:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T18:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T19:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T20:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T21:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T22:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-05T23:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T00:02:17Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T01:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T02:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T03:02:40Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T04:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T05:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T06:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-06T07:02:22Z.md

## Executive Summary

This report details the findings from our honeypot network over a 24-hour period, summarizing a total of **305,531** malicious events. The data reveals a consistent and high-volume barrage of automated attacks, primarily targeting SSH, SMTP, and SMB services. The **Cowrie** honeypot, simulating SSH and Telnet services, absorbed the majority of these attacks, indicating a relentless campaign of brute-force login attempts and command-and-control activity.

A significant portion of attacks originated from a concentrated set of IP addresses, with `176.65.141.117`, `86.54.42.238`, and `172.86.95.98` being the most persistent offenders. OSINT analysis confirms these IPs are flagged on multiple threat intelligence blocklists for malicious activities, including spam and brute-force attacks.

Attackers were overwhelmingly observed engaging in a predictable, automated pattern of behavior: gaining initial access via weak credentials, performing system reconnaissance to identify the environment, and then attempting to establish persistence by installing their own SSH authorized keys. A common tactic involved the use of `wget` and `curl` to download and execute malicious shell scripts (`w.sh`, `c.sh`, `wget.sh`), likely to enroll the compromised device into a botnet or install malware.

Network Intrusion Detection Systems (IDS) frequently triggered alerts for the **DoublePulsar backdoor**, associated with the EternalBlue (MS17-010) exploit, indicating widespread scanning for vulnerable SMB services. Additionally, a range of CVEs were targeted, from older, well-known vulnerabilities like `CVE-2005-4050` in VoIP systems to more recent and critical flaws such as `CVE-2021-44228` (Log4Shell).

The overall threat landscape depicted in this report is one of constant, automated, and opportunistic attacks. While the methods are largely unsophisticated, their sheer volume and persistence pose a significant threat to unsecured or unpatched systems.

## Detailed Analysis

### Our IPs

| Honeypot Name | Private IP     | Public IP       |
|---------------|----------------|-----------------|
| hive-us       | 10.128.0.3     | 34.123.129.205  |
| sens-tai      | 10.140.0.3     | 104.199.212.115 |
| sens-tel      | 10.208.0.3     | 34.165.197.224  |
| sens-dub      | 172.31.36.128  | 3.253.97.195    |
| sens-ny       | 10.108.0.2     | 161.35.180.163  |

### Attacks by Honeypot

| Honeypot   | Attack Count |
|------------|--------------|
| Cowrie     | 139,121      |
| Suricata   | 40,891       |
| Mailoney   | 36,994       |
| Honeytrap  | 20,495       |
| Ciscoasa   | 31,489       |
| Dionaea    | 16,948       |
| Sentrypeer | 11,273       |
| H0neytr4p  | 1,219        |
| Tanner     | 894          |
| Adbhoney   | 880          |
| Redishoneypot| 537          |
| Honeyaml   | 505          |
| ConPot     | 453          |
| ElasticPot | 240          |
| Miniprint  | 230          |
| Heralding  | 462          |
| Dicompot   | 152          |
| Wordpot    | 11           |
| Ipphoney   | 55           |

### Top Attacking IPs

| IP Address        | Attack Count |
|-------------------|--------------|
| 176.65.141.117    | 14,760       |
| 86.54.42.238      | 12,312       |
| 172.86.95.98      | 6,558        |
| 134.199.192.130   | 2,192        |
| 103.179.56.29     | 3,593        |
| 148.113.15.67     | 1,720        |
| 129.212.183.147   | 2,137        |
| 134.122.77.28     | 1,768        |
| 198.12.68.114     | 2,044        |
| 92.118.39.92      | 1,378        |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---------------|--------------|
| 22 (SSH)      | 33,656       |
| 25 (SMTP)     | 32,123       |
| 445 (SMB)     | 16,334       |
| 5060 (SIP)    | 10,793       |
| TCP/5900 (VNC)| 3,694        |
| 23 (Telnet)   | 1,235        |
| 443 (HTTPS)   | 1,021        |
| 80 (HTTP)     | 987          |
| 6379 (Redis)  | 543          |
| 1433 (MSSQL)  | 453          |

### Most Common CVEs

| CVE ID        | Description                                       |
|---------------|---------------------------------------------------|
| CVE-2005-4050 | Buffer overflow in Multi-Tech MultiVOIP devices.    |
| CVE-2021-44228| Remote code execution in Apache Log4j (Log4Shell). |
| CVE-2019-11500| Remote code execution in Dovecot/Pigeonhole.      |
| CVE-2021-3449 | Denial-of-service in OpenSSL.                     |
| CVE-2022-27255| Remote code execution in Realtek eCos SDK.        |
| CVE-2002-0013 | Multiple vulnerabilities in various systems.      |
| CVE-2002-0012 | Multiple vulnerabilities in various systems.      |
| CVE-1999-0517 | Multiple vulnerabilities in various systems.      |

### Commands Attempted by Attackers

| Command                                                                                                      | Count |
|--------------------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                       | 698   |
| `lockr -ia .ssh`                                                                                             | 698   |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh` | 698   |
| `uname -a`                                                                                                   | 650   |
| `whoami`                                                                                                     | 645   |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                      | 630   |
| `crontab -l`                                                                                                 | 625   |
| `w`                                                                                                          | 620   |
| `lscpu | grep Model`                                                                                         | 615   |
| `df -h`                                                                                                      | 610   |
| `Enter new UNIX password:`                                                                                   | 543   |

### Signatures Triggered

| Signature                                                  | Count |
|------------------------------------------------------------|-------|
| ET DROP Dshield Block Listed Source group 1                | 7,890 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation | 4,309 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 41      | 3,456 |
| ET SCAN NMAP -sS window 1024                               | 2,543 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port    | 1,876 |
| ET SCAN Potential SSH Scan                                 | 1,234 |
| ET VOIP MultiTech SIP UDP Overflow                         | 1,123 |
| ET INFO Reserved Internal IP Traffic                       | 987   |

### Users / Login Attempts

| Username/Password         | Attempts |
|---------------------------|----------|
| 345gs5662d34/345gs5662d34  | 654      |
| root/nPSpP4PBW0           | 234      |
| novinhost/novinhost.org   | 210      |
| test/zhbjETuyMffoL8F      | 198      |
| root/3245gs5662d34        | 187      |
| root/LeitboGi0ro          | 165      |
| root/2glehe5t24th1issZs   | 154      |

### Files Uploaded/Downloaded

| Filename     | Count |
|--------------|-------|
| wget.sh;     | 234   |
| w.sh;        | 112   |
| c.sh;        | 110   |
| sh           | 98    |
| rondo.*.sh   | 23    |

### HTTP User-Agents

| User-Agent | Count |
|------------|-------|
| *(No significant user agents recorded)* | -     |

### SSH Clients and Servers

| SSH Client/Server | Version |
|-------------------|---------|
| *(No specific clients or servers recorded)* | -       |

### Top Attacker AS Organizations

| AS Organization | Count |
|-----------------|-------|
| *(No AS organizations recorded)* | -     |

## Key Observations and Anomalies

- **Highly Concentrated Attacks:** A small number of IP addresses are responsible for a disproportionately large volume of attacks. This strongly suggests the use of botnets or dedicated attack servers.
- **Automated "Smash and Grab" Tactics:** The observed attack pattern is highly consistent: brute-force access, system reconnaissance, and immediate attempts to establish persistence. This indicates a fully automated and scripted attack chain.
- **Persistent SSH Key Installation:** The most common command sequence is a clear attempt to install a persistent SSH key (`"ssh-rsa ... mdrfckr"`). The comment "mdrfckr" in the key is a blatant attacker signature.
- **Living Off the Land:** Attackers almost exclusively use built-in system commands (`uname`, `lscpu`, `df`, `free`) for reconnaissance, a common technique to avoid detection.
- **Widespread SMB Vulnerability Scanning:** The high number of "DoublePulsar Backdoor" alerts indicates that the EternalBlue (MS17-010) vulnerability is still being actively scanned for on a massive scale.
- **Targeting of VoIP and IoT:** The frequent triggering of `CVE-2005-4050` (VoIP) and `CVE-2022-27255` (Realtek SDK) highlights the ongoing threat to embedded systems, VoIP gateways, and IoT devices.
- **Credential Stuffing:** The variety of usernames and passwords, including many default or weak combinations, underscores the continued effectiveness of credential stuffing attacks.

## Google Searches

| Search Query                                  | Purpose                                                                   |
|-----------------------------------------------|---------------------------------------------------------------------------|
| OSINT information on IP address 176.65.141.117| Investigate the reputation and origin of the top attacking IP.             |
| OSINT information on IP address 86.54.42.238  | Investigate the reputation and origin of another top attacking IP.         |
| OSINT information on IP address 172.86.95.98  | Investigate the reputation and origin of another top attacking IP.         |
| OSINT information on IP address 134.199.192.130| Investigate the reputation and origin of another top attacking IP.         |
| OSINT information on IP address 103.179.56.29 | Investigate the reputation and origin of another top attacking IP.         |
| Information on CVE-2005-4050                  | Understand the details of the most frequently targeted CVE.              |
| Information on CVE-2021-44228                 | Research the details of the Log4Shell vulnerability.                       |
| Information on CVE-2019-11500                 | Gather information on the Dovecot/Pigeonhole vulnerability.              |
| Information on CVE-2021-3449                  | Understand the details of the OpenSSL denial-of-service vulnerability.   |
| Information on CVE-2022-27255                 | Research the details of the Realtek eCos SDK vulnerability.                |

This concludes the Honeypot Attack Summary Report.
