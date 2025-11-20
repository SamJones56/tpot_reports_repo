Here is the Honeypot Attack Summary Report.
This report is based on the analysis of three aggregated log files: `agg_log_20250929T092002Z.json`, `agg_log_20250929T094001Z.json`, and `agg_log_20250929T100001Z.json`, capturing a total of 11,041 security events.

### Report Information
- **Report ID:** 42d1316b-88a3-4809-904b-f7e583a54b38
- **Date of Report:** 2025-09-29T10-01-19Z
- **Reporting Period:** 2025-09-29T09:20:02Z to 2025-09-29T10:00:01Z
- **Data Sources:** T-Pot Honeypot Network
- **Author:** Cybersecurity Analyst

### Executive Summary
This report summarizes the findings from the T-Pot honeypot network over a period of approximately 40 minutes. A total of 11,041 events were recorded across various honeypot services, indicating a high level of automated scanning and exploitation activity. The most targeted services were SSH (Cowrie), various TCP/UDP ports (Honeytrap), and enterprise network devices (Ciscoasa). A significant portion of the traffic originated from a limited number of IP addresses, suggesting coordinated campaigns.

Key findings include:
- **High Volume of Attacks:** The network observed over 11,000 events in a short period, demonstrating a persistent threat landscape.
- **Dominance of SSH and Web-based Attacks:** Cowrie and Honeytrap honeypots recorded the highest number of interactions, accounting for a combined total of 6,314 events.
- **Targeting of Known Vulnerabilities:** The detection of CVEs such as CVE-2021-44228 (Log4Shell) indicates that attackers are actively exploiting well-known vulnerabilities.
- **Prevalence of Credential Stuffing:** A wide variety of default and weak credentials were used in attempts to gain unauthorized access.
- **Automated Command Execution:** Successful logins were often followed by the execution of a series of commands to gather system information and prepare the host for inclusion in a botnet.

### Detailed Analysis

#### Attacks by Honeypot
The distribution of attacks across the different honeypot types provides insight into the most targeted protocols and services.

| Honeypot Type    | Event Count | Percentage of Total |
|------------------|-------------|---------------------|
| Cowrie           | 3,904       | 35.36%              |
| Honeytrap        | 2,410       | 21.83%              |
| Suricata         | 1,652       | 14.96%              |
| Ciscoasa         | 1,501       | 13.59%              |
| Sentrypeer       | 942         | 8.53%               |
| Dionaea          | 474         | 4.29%               |
| Other            | 158         | 1.43%               |
| **Total**        | **11,041**  | **100%**            |

- **Cowrie:** As is often the case, the SSH honeypot Cowrie was the most engaged, with 3,904 events. This indicates a high volume of automated SSH brute-force attacks.
- **Honeytrap:** This honeypot, which listens on a wide range of TCP ports, captured 2,410 events, showing that attackers are scanning for a variety of open services.
- **Suricata:** The Suricata IDS detected 1,652 events, many of which were related to the scanning and exploitation of known vulnerabilities.
- **Ciscoasa:** The Cisco ASA honeypot logged 1,501 events, demonstrating continued interest in exploiting vulnerabilities in network security devices.
- **Sentrypeer:** This VoIP honeypot recorded 942 events, indicating a focus on SIP and other VoIP-related protocols.
- **Dionaea:** The Dionaea honeypot, which emulates SMB/CIFS and other services, saw a spike in activity in the last log file, with 453 of its 474 total events occurring in that period.

#### Top 20 Attacking IP Addresses
A small number of IP addresses were responsible for a large portion of the observed activity. The top 20 attacking IPs are listed below.

| IP Address        | Total Events |
|-------------------|--------------|
| 46.32.178.94      | 1,251        |
| 208.109.190.200   | 910          |
| 81.215.207.182    | 399          |
| 61.190.114.203    | 304          |
| 37.189.196.88     | 291          |
| 185.156.73.166    | 377          |
| 185.156.73.167    | 370          |
| 92.63.197.55      | 364          |
| 92.63.197.59      | 344          |
| 128.199.33.46     | 226          |
| 65.75.222.182     | 300          |
| 113.193.234.210   | 221          |
| 124.205.213.98    | 306          |
| 113.196.185.120   | 178          |
| 84.247.183.114    | 147          |
| 172.245.163.134   | 102          |
| 45.140.17.52      | 237          |
| 129.13.189.202    | 48           |
| 129.13.189.204    | 24           |
| 188.246.224.87    | 63           |

The IP address `46.32.178.94` was particularly active, with 1,128 of its 1,251 events occurring in the last 20-minute window. This suggests the start of a new, high-volume attack campaign from this source.

#### Top 20 Targeted Ports
The most frequently targeted ports align with the services that are most commonly exposed to the internet.

| Port    | Protocol | Service          | Event Count |
|---------|----------|------------------|-------------|
| 5060    | TCP/UDP  | SIP              | 942         |
| 22      | TCP      | SSH              | 554         |
| 445     | TCP      | SMB              | 454         |
| 8333    | TCP      | Bitcoin          | 142         |
| 80      | TCP      | HTTP             | 65          |
| 6000    | TCP      | X11              | 25          |
| 6036    | TCP      |                  | 30          |
| 8085    | TCP      | HTTP             | 16          |
| 2078    | TCP      |                  | 20          |
| 7443    | TCP      |                  | 15          |
| 9999    | TCP      |                  | 13          |
| 30000   | TCP      |                  | 12          |
| 10001   | TCP      |                  | 12          |
| 5959    | TCP      |                  | 10          |
| 7777    | TCP      |                  | 10          |
| 443     | TCP      | HTTPS            | 29          |
| 8728    | TCP      | MikroTik RouterOS| 16          |
| 5601    | TCP      | Elasticsearch    | 7           |
| 25      | TCP      | SMTP             | 7           |
| 3387    | TCP      | RDP              | 6           |

The high number of events on port 5060 (SIP) corresponds to the activity seen by the Sentrypeer honeypot. The significant number of events on port 445 (SMB) is due to the Dionaea honeypot. Port 22 (SSH) remains a top target, consistent with the Cowrie data.

#### CVEs Detected
The Suricata IDS component of the T-Pot platform identified several CVEs being actively scanned for or exploited.

- **CVE-2021-44228 (Log4Shell):** This critical vulnerability in Apache Log4j was the most frequently detected, with a total of 44 events. This highlights the long tail of exploitation for critical, widespread vulnerabilities.
- **CVE-2021-3449:** A denial-of-service vulnerability in OpenSSL, detected 5 times.
- **CVE-2019-11500:** A remote command execution vulnerability, detected 5 times.
- **CVE-2002-0013, CVE-2002-0012, CVE-1999-0517:** Older vulnerabilities related to web servers and CGI scripts, with a combined 8 detections.
- **CVE-2006-2369:** A vulnerability in web applications, detected once.

The presence of these CVEs in the logs indicates that automated tools are continuously scanning the internet for unpatched systems.

#### Top 20 Credentials Used in Attacks
A large number of credential pairs were observed in brute-force attempts, primarily against the Cowrie (SSH) honeypot. The following are the top 20 most frequently used credentials.

| Username/Password          | Count |
|----------------------------|-------|
| 345gs5662d34/345gs5662d34  | 24    |
| root/3245gs5662d34         | 17    |
| root/Passw0rd              | 10    |
| root/Linux@123             | 6     |
| user/qweqwe                | 4     |
| nfsuser/nfsuser123         | 3     |
| test/zhbjETuyMffoL8F       | 5     |
| root/LeitboGi0ro           | 4     |
| soporte/soporte123         | 4     |
| user/test                  | 3     |
| tfj/tfj                    | 2     |
| ubuntu/qwertyui            | 2     |
| egor/egor123               | 2     |
| monitor/monitor@2024       | 2     |
| dms/dms123                 | 2     |
| moodle/12345               | 2     |
| dms/3245gs5662d34          | 2     |
| deposito/deposito          | 2     |
| hector/hector123           | 2     |
| sa/                        | 3     |

The credentials listed are a mix of default, weak, and previously breached passwords, which is typical of automated brute-force attacks.

#### Top 20 Commands Executed
Upon successful login, attackers executed a series of commands to profile the system and, in some cases, download additional malware.

| Command                                                                                                                                                                                                                                                                                                            | Count |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|
| `uname -a`                                                                                                                                                                                                                                                                                                         | 20    |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                                                                                                                                                                                                                              | 24    |
| `lockr -ia .ssh`                                                                                                                                                                                                                                                                                                     | 24    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`                                                                                                                                                                                                | 24    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                                                                                                                                                                                                                             | 17    |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`                                                                                                                                                                                                                                         | 17    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                                                                                                                                                                                                                           | 17    |
| `ls -lh $(which ls)`                                                                                                                                                                                                                                                                                                | 17    |
| `which ls`                                                                                                                                                                                                                                                                                                         | 17    |
| `crontab -l`                                                                                                                                                                                                                                                                                                       | 17    |
| `w`                                                                                                                                                                                                                                                                                                                | 17    |
| `uname -m`                                                                                                                                                                                                                                                                                                         | 17    |
| `cat /proc/cpuinfo | grep model | grep name | wc -l`                                                                                                                                                                                                                                                                 | 17    |
| `top`                                                                                                                                                                                                                                                                                                              | 17    |
| `uname`                                                                                                                                                                                                                                                                                                            | 17    |
| `whoami`                                                                                                                                                                                                                                                                                                           | 17    |
| `lscpu | grep Model`                                                                                                                                                                                                                                                                                                 | 17    |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                                                                                                                                                                                                                                      | 17    |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`                                                                                                                                                                                            | 11    |
| `Enter new UNIX password: `                                                                                                                                                                                                                                                                                          | 5     |

The most common commands are related to system enumeration (`uname`, `lscpu`, `free`, etc.) and establishing persistence by adding an SSH key to `authorized_keys`. The command to remove `secure.sh` and `auth.sh` suggests an attempt to remove competing malware from the compromised host.

### Notes & Limitations
- The data in this report is from a network of honeypots and represents unsolicited traffic from the internet. It is not necessarily indicative of a targeted attack against any specific organization.
- The IP addresses listed as sources of attacks are often compromised systems or proxy servers and may not be the true origin of the attack.
- The event counts represent individual interactions with the honeypots and do not always equate to a unique attack or attacker.
- This report is based on a limited time window and may not capture the full scope of ongoing campaigns.

This concludes the Honeypot Attack Summary Report.
