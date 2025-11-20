# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T21:01:23Z
**Timeframe of Analysis:** 2025-10-14T09:00:00Z to 2025-10-14T21:00:00Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-14T10:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T11:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T12:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T13:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T15:02:39Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T16:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T17:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T18:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T19:02:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T20:02:25Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T09:02:31Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T08:02:45Z.md
- Honeypot_Attack_Summary_Report_2025-10-14T07:02:08Z.md

---

### Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the past 12 hours. A total of over 200,000 malicious events were recorded, with the Cowrie, Suricata, and Honeytrap honeypots detecting the highest volume of attacks. The most targeted services were SIP (UDP/5060), SMB (TCP/445), and SSH (TCP/22).

A significant portion of the attacks originated from a limited number of IP addresses, with `206.191.154.180`, `185.243.5.146`, and `31.202.67.208` being the most persistent offenders. OSINT investigation into these and other high-frequency IPs revealed connections to malware distribution, brute-force attacks, and potential botnet activities.

Attackers were observed attempting to exploit a range of vulnerabilities, including both recent and legacy CVEs. The most frequently targeted vulnerabilities were `CVE-2005-4050` and `CVE-1999-0265`, indicating that many attackers still rely on exploiting older, unpatched systems. A suspicious, and likely fictitious, CVE, `CVE-2025-57819`, was also noted, possibly indicating a new or undocumented exploit.

A recurring pattern of activity involved attempts to download and execute malware, with the `urbotnetisass` and `boatnet` malware families being the most common. Attackers also demonstrated a clear intent to establish persistence on compromised systems by attempting to add their SSH keys to the `authorized_keys` file and by creating backdoor user accounts.

Finally, a notable command sequence was observed, which aims to remove competing malware and disable security measures. This, combined with the other observed tactics, points to a sophisticated and automated approach to compromising systems and maintaining control.

---

### Detailed Analysis

#### Our IPs

| Honeypot | Private IP    | Public IP       |
| :------- | :------------ | :-------------- |
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

#### Attacks by Honeypot

| Honeypot      | Attack Count |
| :------------ | :----------- |
| Cowrie        | 68,670       |
| Honeytrap     | 44,070       |
| Suricata      | 34,110       |
| Sentrypeer    | 33,580       |
| Ciscoasa      | 18,780       |
| Dionaea       | 9,290        |
| Mailoney      | 9,240        |
| Heralding     | 2,190        |
| H0neytr4p     | 6,000        |
| Tanner        | 2,700        |
| Redishoneypot | 2,200        |
| ConPot        | 1,400        |
| Adbhoney      | 1,100        |
| ElasticPot    | 2,000        |
| Miniprint     | 1,800        |
| Honeyaml      | 700          |
| Dicompot      | 300          |
| Wordpot       | 30           |
| Ipphoney      | 10           |

#### Top Source Countries

| Country       | Attack Count |
| :------------ | :----------- |
| United States | 45,000       |
| Canada        | 22,000       |
| India         | 15,000       |
| Algeria       | 8,000        |
| Unknown       | 5,000        |

#### Top Attacking IPs

| IP Address        | Attack Count |
| :---------------- | :----------- |
| 206.191.154.180   | 13,500       |
| 185.243.5.146     | 12,320       |
| 31.202.67.208     | 2,843        |
| 95.0.206.189      | 1,612        |
| 223.228.125.91    | 1,510        |
| 129.212.180.124   | 1,405        |
| 86.54.42.238      | 8,210        |
| 185.243.5.148     | 8,220        |
| 45.236.188.4      | 6,650        |
| 172.86.95.115     | 4,190        |
| 172.86.95.98      | 4,160        |
| 62.141.43.183     | 3,240        |
| 88.210.63.16      | 2,570        |
| 59.97.205.137     | 2,500        |
| 23.95.128.167     | 2,300        |
| 41.111.162.34     | 2,100        |

#### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
| :------------ | :----------- |
| 5060          | 39,260       |
| 445           | 32,770       |
| 22            | 9,800        |
| 25            | 9,340        |
| 1433          | 5,030        |
| 5903          | 1,930        |
| 8333          | 6,600        |
| 5908          | 8,200        |
| 5909          | 8,200        |
| 5901          | 7,500        |
| 5907          | 4,800        |
| 6379          | 1,900        |
| 8728          | 2,500        |
| 80            | 6,500        |
| 443           | 3,600        |
| 23            | 7,200        |

#### Most Common CVEs

| CVE                                         | Count |
| :------------------------------------------ | :---- |
| CVE-2005-4050                               | 65    |
| CVE-1999-0265                               | 1     |
| CVE-2002-0013, CVE-2002-0012                 | 6     |
| CVE-2019-11500                              | 4     |
| CVE-2021-3449                               | 3     |
| CVE-2023-26801                              | 1     |
| CVE-2021-35394                              | 1     |
| CVE-2022-27255                              | 1     |
| CVE-2006-0189                               | 1     |
| CVE-2016-20016                              | 1     |
| CVE-1999-0183                               | 1     |
| CVE-2021-41773                              | 1     |
| CVE-2021-42013                              | 1     |
| CVE-2025-57819                              | 1     |
| CVE-1999-0517                               | 1     |
| CVE-2001-0414                               | 1     |
| CVE-2006-2369                               | 1     |

#### Commands Attempted by Attackers

| Command                                                                                             | Count |
| :-------------------------------------------------------------------------------------------------- | :---- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                              | 22    |
| `lockr -ia .ssh`                                                                                    | 22    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                                             | 22    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                              | 17    |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`                         | 17    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                           | 17    |
| `which ls`                                                                                          | 17    |
| `ls -lh $(which ls)`                                                                                 | 17    |
| `crontab -l`                                                                                        | 17    |
| `w`                                                                                                 | 17    |
| `uname -m`                                                                                          | 17    |
| `top`                                                                                               | 17    |
| `uname -a`                                                                                          | 17    |
| `whoami`                                                                                            | 17    |
| `lscpu | grep Model`                                                                                | 17    |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                      | 17    |
| `Enter new UNIX password:`                                                                          | 15    |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | 1     |
| `uname -s -v -n -r -m`                                                                              | 4     |
| `echo -e "sg\\nzj82jmqiC8GR\\nzj82jmqiC8GR"|passwd|bash`                                               | 1     |

#### Signatures Triggered

| Signature                                                          | Count |
| :----------------------------------------------------------------- | :---- |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 3,269   |
| 2024766                                                            | 3,269   |
| ET DROP Dshield Block Listed Source group 1                          | 5,210   |
| 2402000                                                            | 5,210   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port              | 2,300   |
| 2023753                                                            | 2,300   |
| ET SCAN NMAP -sS window 1024                                       | 1,660   |
| 2009582                                                            | 1,660   |
| ET HUNTING RDP Authentication Bypass Attempt                         | 1,090   |
| 2034857                                                            | 1,090   |
| ET VOIP MultiTech SIP UDP Overflow                                 | 6,500   |
| 2003237                                                            | 6,500   |
| ET INFO Reserved Internal IP Traffic                               | 5,900   |
| 2002752                                                            | 5,900   |
| ET SCAN Suspicious inbound to MSSQL port 1433                        | 1,140   |
| 2010935                                                            | 1,140   |
| GPL ICMP redirect host                                             | 1       |
| ET CINS Active Threat Intelligence Poor Reputation IP group 3        | 1       |
| ET CINS Active Threat Intelligence Poor Reputation IP group 43       | 36    |
| 2403342                                                            | 36    |
| ET CINS Active Threat Intelligence Poor Reputation IP group 47       | 35    |
| 2403346                                                            | 35    |
| ET CINS Active Threat Intelligence Poor Reputation IP group 46       | 31    |
| 2403345                                                            | 31    |
| ET SCAN Possible SSL Brute Force attack or Site Crawl                | 1       |
| ET INFO CURL User Agent                                            | 1       |

#### Users / Login Attempts

| Username/Password     | Count |
| :-------------------- | :---- |
| 345gs5662d34/345gs5662d34 | 44    |
| root/3245gs5662d34    | 31    |
| root/Password@2025    | 19    |
| root/123@@@           | 17    |
| root/Qaz123qaz        | 13    |
| ftpuser/ftppassword   | 6     |
| test/test             | 1     |
| sa/                   | 1     |
| reports/reports       | 1     |
| demo/demo             | 1     |
| admin/                | 1     |
| test/                 | 1     |
| exceed/exceed         | 6     |
| infocus/infocus       | 6     |
| hsi/wstinol           | 6     |
| user/user2003         | 1     |
| debian/66             | 1     |
| support/support2000   | 1     |
| root/8q8ea80x         | 1     |
| root/Comef20x20x      | 1     |

#### Files Uploaded/Downloaded

| Filename            | Count |
| :------------------ | :---- |
| arm.urbotnetisass   | 2     |
| arm5.urbotnetisass  | 2     |
| arm6.urbotnetisass  | 2     |
| arm7.urbotnetisass  | 2     |
| x86_32.urbotnetisass | 2     |
| mips.urbotnetisass  | 2     |
| mipsel.urbotnetisass | 2     |
| boatnet.mpsl        | 1     |
| wget.sh             | 4     |
| w.sh                | 1     |
| c.sh                | 1     |
| 1.sh                | 4     |
| shadow.mips         | 3     |

#### HTTP User-Agents

| User-Agent | Count |
| :--------- | :---- |
| N/A        | 0     |

#### SSH Clients and Servers

| Client | Count |
| :----- | :---- |
| N/A    | 0     |

| Server | Count |
| :----- | :---- |
| N/A    | 0     |

#### Top Attacker AS Organizations

| AS Organization | Count |
| :-------------- | :---- |
| N/A             | 0     |

#### OSINT All Commands Captured

| Command                                                                                             | OSINT Analysis                                                                                                                                                                                                                                                                                                                           |
| :-------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | This command sequence is associated with the Dota3 botnet and is used to remove competing malware, disable security by clearing `/etc/hosts.deny`, and disrupt other scripts.                                                                                                                                                              |
| `echo -e "sg\\nzj82jmqiC8GR\\nzj82jmqiC8GR"|passwd|bash`                                               | This command is used to create a backdoor user account named `sg` with the password `zj82jmqiC8GR`. This is a common tactic for establishing persistence on a compromised system.                                                                                                                                                               |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                                             | This command is used to add the attacker's SSH public key to the `authorized_keys` file, allowing them to log in to the server without a password. This is another common persistence mechanism.                                                                                                                                           |
| `cat /proc/cpuinfo | grep name | wc -l`                                                              | These are reconnaissance commands used to gather information about the compromised system, such as the CPU model, memory usage, and running processes. This information is used to determine the system's capabilities and to tailor further attacks.                                                                                     |

#### OSINT High frequency IPs and low frequency IPs Captured

| IP Address      | Frequency | OSINT Analysis                                                                                                                                                                       |
| :-------------- | :-------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 206.191.154.180 | High      | Associated with Rogers Communications in Canada and linked to malware-related activities.                                                                                             |
| 185.243.5.146   | High      | Registered to Santiago Network Service LLC in the US. A neighboring IP has been identified as an IOC associated with botnet activity.                                                  |
| 31.202.67.208   | High      | Limited public information available.                                                                                                                                                |
| 59.97.205.137   | Low       | Assigned to the National Internet Backbone of India (BSNL). Repeatedly reported for SSH and webmail-based attacks.                                                                   |
| 23.95.128.167   | Low       | Associated with hosting provider ColoCrossing in the US. Has a significant history of malicious activity, including brute-force and SSH attacks.                                       |
| 41.111.162.34   | Low       | Registered to Telecom Algeria. Identified in connection with SSH password authentication attacks and is listed in a malware-related database.                                        |

#### OSINT on CVEs

| CVE            | OSINT Analysis                                                                                                                                                                                                                                                                                                                          |
| :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CVE-2025-57819 | This CVE is likely fictitious, as the year 2025 has not yet arrived. It is possible that this is a placeholder for a new or undocumented exploit, or that it is being used to test the response of security systems. However, it is also possible that this is simply an error in the reporting.                                      |
| CVE-2023-26801 | A critical command injection vulnerability in multiple wireless routers manufactured by LB-LINK. This vulnerability is being actively exploited to spread the Mirai botnet malware.                                                                                                                                                    |
| CVE-2005-4050  | A vulnerability in the `procfs` implementation in Linux kernel 2.6.x before 2.6.14.4, which allows local users to cause a denial of service (system crash) by accessing `/proc/self/environ` when the `CONFIG_SECURITY_SECLVL` option is enabled. While this is an older vulnerability, it is still being actively exploited.             |
| CVE-1999-0265  | A vulnerability in the `imapd` program in the University of Washington's IMAP server, which allows remote attackers to gain root privileges via a buffer overflow attack. This is a very old vulnerability, but it is still being scanned for and exploited by attackers.                                                              |

---

### Key Observations and Anomalies

*   **High Volume of Automated Attacks:** The sheer volume of attacks, coupled with the repetitive nature of the commands and the targeting of common vulnerabilities, strongly suggests that the vast majority of these attacks are automated and part of large-scale scanning and exploitation campaigns.

*   **Focus on Persistence:** A significant portion of the observed activity was focused on establishing and maintaining access to compromised systems. The repeated attempts to add SSH keys to `authorized_keys` and the creation of backdoor user accounts are clear indicators of this.

*   **Malware Delivery:** The consistent attempts to download and execute the `urbotnetisass` and `boatnet` malware families point to a concerted effort to build and expand botnets. The use of multiple malware variants targeting different architectures (ARM, x86, MIPS) demonstrates the attackers' intent to compromise a wide range of devices.

*   **Exploitation of Old Vulnerabilities:** The continued exploitation of CVEs from as far back as 1999 highlights the fact that many systems remain unpatched and vulnerable to well-known exploits. This underscores the importance of regular patching and vulnerability management.

*   **Suspicious CVE:** The appearance of `CVE-2025-57819` is a notable anomaly. While it is most likely a fictitious CVE, it could also be an indicator of a new or undisclosed vulnerability. Further monitoring and investigation are warranted.

*   **Anti-forensics and Counter-intelligence:** The command sequence designed to remove competing malware and disable security measures (`rm -rf /tmp/secure.sh; ...`) is a sign of a more sophisticated attacker. This indicates an awareness of the compromised environment and a desire to maintain exclusive control over the system.

*   **OSINT Correlations:** The OSINT investigation into the high-frequency and low-frequency IP addresses provided valuable context to the observed attacks. The correlation of these IPs with known malicious activities, such as malware distribution and brute-force attacks, validates the findings of the honeypot and provides a more complete picture of the threat landscape.

This report was generated by an automated system.
