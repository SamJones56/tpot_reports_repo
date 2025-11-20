# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T18-03-26Z
**Timeframe:** Last 12 hours
**Files Used:** 
*   Honeypot_Attack_Summary_Report_2025-10-07T17:02:35Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T16:01:58Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T15:02:02Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T14:02:48Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T13:01:54Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T11:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T10:02:03Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T09:02:14Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T08:01:59Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T07:01:59Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T06:02:10Z.md
*   Honeypot_Attack_Summary_Report_2025-10-07T05:02:10Z.md

## Executive Summary

This report provides a comprehensive analysis of the attack data collected from our honeypot network over the last 12 hours. A total of **186,119** events were recorded across multiple honeypots, with the Cowrie (SSH/Telnet) honeypot logging the highest number of interactions. This indicates a sustained and high volume of automated attacks targeting common and often exposed services.

The most prominent attack vectors observed were SSH brute-force attempts, SMTP relay abuse, and widespread scanning for SMB vulnerabilities. The high volume of traffic on port 22 (SSH) and port 25 (SMTP) suggests that attackers are actively seeking to compromise servers for spam campaigns, to gain initial access for further attacks, or to expand their botnets. A significant number of attacks also targeted port 445 (SMB), with the "DoublePulsar Backdoor" signature being frequently triggered. This highlights the continued threat of legacy vulnerabilities, such as the one exploited by the EternalBlue malware.

A recurring and notable anomaly was the consistent attempt by attackers to inject a specific SSH public key into the `authorized_keys` file. This indicates a large-scale, coordinated campaign to establish persistent access to compromised systems. The commands executed by attackers were primarily focused on system reconnaissance, with the intent of gathering information about the target environment for further exploitation.

The top attacking IP addresses were distributed globally, with a significant number originating from the United Kingdom, Egypt, the United States, and Russia. OSINT analysis of these IPs revealed their association with malicious activities, including spam, brute-force attacks, and inclusion on multiple threat intelligence blacklists.

In summary, the threat landscape over the past 12 hours has been characterized by high-volume, automated attacks targeting common services. The tactics employed by attackers suggest a focus on gaining persistent access and leveraging compromised systems for spam, botnet expansion, and further malicious activities.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP      | Public IP       |
|----------|-----------------|-----------------|
| hive-us  | 10.128.0.3      | 34.123.129.205  |
| sens-tai | 10.140.0.3      | 104.199.212.115 |
| sens-tel | 10.208.0.3      | 34.165.197.224  |
| sens-dub | 172.31.36.128   | 3.253.97.195    |
| sens-ny  | 10.108.0.2      | 161.35.180.163  |

### Attacks by Honeypot

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 83753        |
| Honeytrap     | 31413        |
| Suricata      | 24095        |
| Mailoney      | 12585        |
| Dionaea       | 11090        |
| Sentrypeer    | 9075         |
| Ciscoasa      | 5506         |
| H0neytr4p     | 1184         |
| Tanner        | 644          |
| Adbhoney      | 267          |
| ConPot        | 285          |
| Redishoneypot | 332          |
| Heralding     | 270          |
| Honeyaml      | 205          |
| ElasticPot    | 103          |
| Miniprint     | 141          |
| Dicompot      | 46           |
| Ipphoney      | 45           |
| ssh-rsa       | 26           |
| Wordpot       | 4            |
| Medpot        | 3            |

### Top Source Countries

| Country         |
|-----------------|
| United Kingdom  |
| Egypt           |
| United States   |
| Russia          |

*Note: Country data is derived from the OSINT analysis of the top attacking IPs and is not an exhaustive list.*

### Top Attacking IPs

| IP Address      | Attack Count |
|-----------------|--------------|
| 86.54.42.238    | 9904         |
| 41.33.199.217   | 4463         |
| 172.86.95.98    | 4209         |
| 176.65.141.117  | 4060         |
| 45.140.17.52    | 3118         |
| 185.255.126.223 | 2822         |
| 23.94.26.58     | 2579         |
| 42.118.158.88   | 1853         |
| 170.64.145.101  | 1602         |
| 125.163.36.47   | 1579         |
| 116.68.77.169   | 1533         |
| 182.10.97.48    | 1518         |
| 41.38.14.67     | 1338         |
| 209.38.88.14    | 1383         |
| 147.45.193.115  | 1252         |
| 50.6.225.98     | 1246         |
| 114.217.32.132  | 1154         |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---------------|--------------|
| 22 (SSH)      | 11094        |
| 25 (SMTP)     | 12585        |
| 445 (SMB)     | 10828        |
| 5060 (SIP)    | 9075         |
| 8333 (Bitcoin)| 1415         |
| 5903 (VNC)    | 940          |
| 443 (HTTPS)   | 1342         |
| 80 (HTTP)     | 698          |
| 6379 (Redis)  | 332          |
| 23 (Telnet)   | 633          |

### Most Common CVEs

| CVE                                                                 |
|---------------------------------------------------------------------|
| CVE-2021-44228 (Log4Shell)                                          |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517                          |
| CVE-2019-11500                                                      |
| CVE-2021-3449                                                       |
| CVE-1999-0265                                                       |
| CVE-2023-26801                                                      |
| CVE-2002-1149                                                       |
| CVE-2006-2369                                                       |
| CVE-2024-4577, CVE-2002-0953                                         |
| CVE-2021-41773, CVE-2021-42013, CVE-2021-35394                       |
| CVE-2003-0825                                                       |
| CVE-1999-0183, CVE-2005-4050                                         |
| CVE-2006-3602, CVE-2006-4458, CVE-2006-4542                          |
| CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255      |
| CVE-2001-0414, CVE-2016-20016, CVE-2022-0543                         |

### Commands Attempted by Attackers

| Command                                                                                                      |
|--------------------------------------------------------------------------------------------------------------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                       |
| `lockr -ia .ssh`                                                                                             |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                       |
| `Enter new UNIX password:`                                                                                    |
| `uname -a`                                                                                                   |
| `whoami`                                                                                                     |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                  |
| `lscpu | grep Model`                                                                                         |
| `w`                                                                                                          |
| `crontab -l`                                                                                                 |
| `top`                                                                                                        |
| `uname -m`                                                                                                   |
| `ls -lh $(which ls)`                                                                                         |
| `which ls`                                                                                                   |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                             |

### Signatures Triggered

| Signature                                                       |
|-----------------------------------------------------------------|
| ET SCAN MS Terminal Server Traffic on Non-standard Port         |
| ET DROP Dshield Block Listed Source group 1                     |
| ET SCAN NMAP -sS window 1024                                    |
| ET INFO Reserved Internal IP Traffic                            |
| ET SCAN Potential SSH Scan                                      |
| ET CINS Active Threat Intelligence Poor Reputation IP           |
| ET DROP Spamhaus DROP Listed Traffic Inbound                    |
| ET EXPLOIT Apache Obfuscated log4j RCE Attempt (CVE-2021-44228) |
| ET SCAN Suspicious inbound to PostgreSQL port 5432              |
| ET SCAN Suspicious inbound to MSSQL port 1433                   |
| ET INFO CURL User Agent                                         |
| GPL ICMP redirect host                                          |
| GPL INFO SOCKS Proxy attempt                                    |
| GPL SNMP request udp / public access udp                        |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET HUNTING RDP Authentication Bypass Attempt                    |
| ET INFO Incoming Basic Auth Base64 HTTP Password detected unencrypted |
| ET TOR Known Tor Relay/Router/Exit Node Traffic                 |
| GPL TELNET Bad Login                                            |
| ET INFO VNC Authentication Failure                              |

### Users / Login Attempts

| Username / Password                 |
|-------------------------------------|
| 345gs5662d34/345gs5662d34           |
| sysadmin/sysadmin@1                 |
| ubuntu/3245gs5662d34                |
| developer/developer                 |
| root/Password1                      |
| admin/admin123                      |
| postgres/postgres                   |
| elasticsearch/elasticsearch         |
| guest/guest                         |
| pi/pi                               |

*Note: This is a small sample of the most common login attempts. Many other combinations were observed.*

### Files Uploaded/Downloaded

| Filename                                                                                             |
|------------------------------------------------------------------------------------------------------|
| wget.sh, w.sh, c.sh                                                                                  |
| mips, Mozi.m, Space.mips                                                                             |
| bot.html, get?src=cl1ckh0use                                                                         |
| cmd.txt, boatnet.mpsl                                                                                |
| config.all.php, config.php, Xiii.php, phpversions.php, PBX.php, pannels_main.php, woa3z.php            |
| soap-envelope, soap-encoding, addressing, discovery                                                  |
| &currentsetting.htm=1                                                                                |
| ?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine                 |
| xhtml1-transitional.dtd, xhtml, fbml                                                                 |

### HTTP User-Agents

No user agents were logged in this timeframe.

### SSH Clients and Servers

No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations

No attacker AS organizations were logged in this timeframe.

### OSINT Information

| IP Address      | Location          | ISP/Hosting Provider | Summary of Findings                                                                                                                                                                                                                         |
|-----------------|-------------------|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 86.54.42.238    | United Kingdom    | KCOM Group PLC       | Associated with malicious activity, including spam and potential exploits. Blacklisted by multiple threat intelligence platforms. The hostname "rdp-mwkejlli" suggests a possible compromised remote desktop server.                                 |
| 41.33.199.217   | Cairo, Egypt      | AfriNIC              | No direct association with malicious activities found in public OSINT sources. This IP appears to have a low public threat profile, despite its high volume of attacks on our honeypot.                                                        |
| 172.86.95.98    | San Francisco, US | FranTech Solutions   | Included on at least one threat intelligence blacklist. Associated with "sipquery" activity, suggesting scanning of VoIP systems. The hosting provider, FranTech Solutions, is rated as a "potentially medium fraud risk."                   |
| 176.65.141.117  | United States     | Optibounce, LLC      | Associated with malicious activities, including brute-force attacks and suspicious SMTP traffic. Appears on at least one blacklist. No publicly identifiable domains are hosted on this IP, suggesting it may be a dedicated attack server. |
| 45.140.17.52    | St. Petersburg, RU| Proton66 LLC         | Flagged for widespread malicious activity with a 100% confidence score on AbuseIPDB. Thousands of abuse reports, including hacking attempts and information leaks. Listed on multiple blocklists.                                          |

## Key Observations and Anomalies

1.  **High-Volume, Coordinated SSH Key Injection:** The most significant anomaly is the repeated and widespread attempt to inject the same SSH public key (`ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr`) into the `authorized_keys` file. This indicates a large-scale, automated campaign to gain persistent access to compromised servers. The uniformity of the key and the associated commands suggests a single actor or group is behind this campaign.

2.  **Prevalence of Legacy Exploits:** The high number of signatures for the "DoublePulsar Backdoor" and the continued attempts to exploit Log4Shell (CVE-2021-44228) highlight that attackers are still finding success with older, well-known vulnerabilities. This underscores the importance of timely patching and security updates.

3.  **Surge in SMTP and SMB Traffic:** The significant volume of attacks targeting port 25 (SMTP) and port 445 (SMB) suggests a focus on exploiting email servers for spam/phishing and leveraging SMB vulnerabilities for initial access and lateral movement. The SMB traffic, in particular, points to the continued threat of wormable exploits.

4.  **Scripted and Automated Attacks:** The commands executed by attackers are highly scripted and focus on system enumeration (`uname`, `lscpu`, `free`, etc.). This, combined with the high volume of attacks, indicates the use of automated tools and botnets to carry out these campaigns.

5.  **Discrepancy in OSINT Findings:** While most of the top attacking IPs have a clear history of malicious activity, the IP address `41.33.199.217` from Egypt, which was responsible for a high volume of attacks, has a low public threat profile. This could indicate a newly compromised system or a new addition to a botnet that has not yet been widely reported.

6.  **Focus on Credential Stuffing:** The wide variety of usernames and passwords attempted, ranging from default credentials to common and previously breached passwords, demonstrates the continued effectiveness of brute-force and credential stuffing attacks. This highlights the importance of strong, unique passwords and multi-factor authentication.
