
# Honeypot Attack Summary Report

## 1. Report Information

- **Report ID:** T-Pot-Summary-20250929T040127Z
- **Generation Date:** 2025-09-29T04:01:27Z
- **Reporting Period:** 2025-09-29T03:20:01Z to 2025-09-29T04:00:01Z
- **Data Source:** T-Pot Honeypot Network
- **Analyst:** Cybersecurity Analyst Agent

## 2. Executive Summary

This report summarizes a total of 14,551 attacks recorded across a distributed honeypot network during the 40-minute period from 03:20 UTC to 04:00 UTC on September 29, 2025. The attacks targeted a variety of services, with the highest volume of malicious traffic captured by the Cowrie (SSH/Telnet), Honeytrap, and Ciscoasa honeypots.

Attackers predominantly originated from IP address `147.182.150.164`, which was responsible for 1,566 events. The most frequently targeted service was SSH on port 22. A significant number of attacks involved attempts to exploit known vulnerabilities, including Log4Shell (CVE-2021-44228). Analysis of captured commands reveals a consistent pattern of attackers attempting to download and execute malicious scripts, add SSH keys for persistence, and perform system reconnaissance.

## 3. Detailed Analysis

This section provides a comprehensive breakdown of the observed attack data, categorized by honeypot, source IP, destination port, exploited vulnerabilities, credentials, and executed commands.

### 3.1. Attacks by Honeypot

The honeypots recorded varying levels of activity, indicating the types of services attackers were targeting.

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 6,285        |
| Honeytrap     | 3,103        |
| Suricata      | 1,674        |
| Ciscoasa      | 1,480        |
| Mailoney      | 824          |
| Dionaea       | 667          |
| Tanner        | 131          |
| Honeyaml      | 106          |
| ElasticPot    | 101          |
| Sentrypeer    | 52           |
| H0neytr4p     | 47           |
| Adbhoney      | 38           |
| Redishoneypot | 21           |
| ConPot        | 15           |
| Heralding     | 3            |
| Dicompot      | 2            |
| Wordpot       | 1            |
| Ipphoney      | 1            |
| **Total**     | **14,551**   |

**Analysis:** The high number of hits on Cowrie indicates a strong focus on compromising SSH and Telnet services. Honeytrap's significant activity suggests broad, non-specific scanning and attacks against a wide range of ports. The activity on Mailoney is notable and can be attributed to a single IP engaging in a high-volume mailing campaign.

### 3.2. Top 10 Attacking IP Addresses

The following table lists the most active source IP addresses observed during the reporting period.

| IP Address          | Attack Count |
|---------------------|--------------|
| 147.182.150.164     | 1,566        |
| 5.182.209.68        | 1,324        |
| 115.190.54.120      | 945          |
| 160.25.81.48        | 830          |
| 86.54.42.238        | 821          |
| 124.235.224.202     | 480          |
| 4.144.169.44        | 399          |
| 116.193.191.100     | 380          |
| 185.156.73.166      | 380          |
| 217.182.77.148      | 378          |

**Analysis:** These IPs are the primary sources of automated attacks. `147.182.150.164` and `5.182.209.68` were exceptionally active, likely conducting large-scale scanning and brute-force campaigns. It is recommended to block these IPs at the network perimeter.

### 3.3. Top 10 Targeted Destination Ports

The table below shows the most frequently targeted TCP/UDP ports.

| Port | Service/Protocol | Attack Count |
|------|------------------|--------------|
| 22   | SSH              | 1,070        |
| 25   | SMTP             | 822          |
| 445  | SMB              | 530          |
| 80   | HTTP             | 138          |
| 9200 | Elasticsearch    | 101          |
| 4444 | Various/Trojan   | 99           |
| 3000 | Various/Web      | 100          |
| 1433 | MSSQL            | 80           |
| 8333 | Bitcoin          | 52           |
| 443  | HTTPS            | 57           |

**Analysis:** The targeting of port 22 (SSH) is consistent with the high volume of Cowrie events. The significant number of attacks on port 25 (SMTP) originated from a single source. Port 445 (SMB) remains a popular target for wormable malware. The variety of other ports indicates broad, opportunistic scanning for misconfigured services.

### 3.4. Observed CVEs

Attackers were observed attempting to exploit the following vulnerabilities:

| CVE ID          | Count | Description                                      |
|-----------------|-------|--------------------------------------------------|
| CVE-2021-44228  | 36    | Apache Log4j Remote Code Execution (Log4Shell)   |
| CVE-2019-11500  | 6     | Remote Code Execution Vulnerability              |
| CVE-2002-0013   | 5     | Multiple CGI Vulnerabilities                     |
| CVE-2002-0012   | 5     | Multiple CGI Vulnerabilities                     |
| CVE-2021-3449   | 5     | OpenSSL Denial of Service Vulnerability          |
| CVE-1999-0517   | 3     | CGI Program Information Disclosure               |
| CVE-1999-0183   | 2     | Mail Server Vulnerability                        |
| CVE-2024-12856  | 1     | (Details Pending)                                |
| CVE-2024-12885  | 1     | (Details Pending)                                |
| CVE-2025-3248   | 1     | (Details Pending - Fictional/Reserved)           |
| CVE-2006-2369   | 1     | Web Server Vulnerability                         |

**Analysis:** Log4Shell remains a prevalent attack vector. The presence of very old CVEs (e.g., from 1999 and 2002) indicates that many attackers use outdated scanning tools that check for legacy vulnerabilities in the hope of finding unpatched, legacy systems.

### 3.5. Top 10 Credentials Used in Attacks

The following username and password combinations were most frequently used in brute-force attempts.

| Username/Password     | Count |
|-----------------------|-------|
| cron/                 | 22    |
| 345gs5662d34/345gs5662d34| 14    |
| root/3245gs5662d34    | 5     |
| root/P@ssw0rd         | 5     |
| user/user             | 4     |
| nvidia/nvidia         | 3     |
| root/LeitboGi0ro      | 3     |
| test/zhbjETuyMffoL8F  | 3     |
| guest/qwertyuiop      | 3     |
| root/12131415         | 3     |

**Analysis:** The list is dominated by weak, common, or default credentials. The pair `345gs5662d34/345gs5662d34` appears to be specific to a particular botnet campaign.

### 3.6. Top 10 Commands Executed by Attackers

After gaining access, attackers attempted to execute the following commands.

| Command                                                                                                      | Count |
|--------------------------------------------------------------------------------------------------------------|-------|
| `uname -s -v -n -r -m`                                                                                       | 17    |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                       | 15    |
| `lockr -ia .ssh`                                                                                             | 15    |
| `cd ~ && rm -rf .ssh && ... >> .ssh/authorized_keys`                                                          | 15    |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                      | 14    |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`                                 | 14    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                  | 14    |
| `ls -lh $(which ls)`                                                                                         | 14    |
| `which ls`                                                                                                   | 14    |
| `crontab -l`                                                                                                 | 14    |

**Analysis:** The command patterns are highly indicative of automated scripts. Attackers consistently perform the following actions:
1.  **Reconnaissance:** Using `uname`, `lscpu`, `free`, and `df` to identify the system architecture and resources.
2.  **Persistence:** Attempting to remove existing SSH configurations and add their own public key to `authorized_keys`. This allows them passwordless access in the future.
3.  **Securing Access:** Using `chattr` and a tool named `lockr` to prevent their own access mechanisms from being easily removed.
4.  **Payload Download:** Commands involving `wget` and `curl` (seen in the "interesting" logs) are used to download and execute next-stage malware.

## 4. Notes and Limitations

- The data in this report is sourced exclusively from a network of honeypots. It represents attempted attacks and does not reflect successful compromises of production systems.
- The reported attack counts represent individual events logged by the system. A single sophisticated attack could consist of hundreds of such events.
- IP addresses can be spoofed or belong to compromised systems, so attribution should be made with caution. The source IPs are part of the attack infrastructure, not necessarily the location of the human attacker.
- CVEs are identified based on signatures in the attack traffic (e.g., specific URL patterns). This method is reliable but may not capture all exploitation attempts.
- This report covers a short, 40-minute timeframe and represents a snapshot of ongoing malicious activity on the internet.

***End of Report***
