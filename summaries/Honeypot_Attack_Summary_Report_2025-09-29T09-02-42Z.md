
# Honeypot Attack Summary Report

## 1. Report Information

- **Report ID:** T-Pot-Summary-20250929T090210Z
- **Generation Date:** 2025-09-29T09:02:10Z
- **Reporting Period:** 2025-09-29T08:20:01Z to 2025-09-29T09:00:01Z
- **Data Sources:**
    - `agg_log_20250929T082001Z.json`
    - `agg_log_20250929T084001Z.json`
    - `agg_log_20250929T090001Z.json`

## 2. Executive Summary

This report summarizes the findings from the T-Pot honeypot network over a 40-minute period on September 29, 2025. A total of 11,291 attacks were recorded across a variety of honeypot services. The most targeted services were SSH (Cowrie), various TCP/UDP ports (Honeytrap), and network security devices (Suricata and Ciscoasa).

Key findings include:
- A high volume of automated attacks, likely from botnets, targeting common vulnerabilities and default credentials.
- The majority of attacks originated from a diverse set of IP addresses, with the most persistent attackers coming from the United States, China, and Russia.
- The most frequently observed CVE was CVE-2021-44228 (Log4Shell), indicating continued exploitation of this vulnerability.
- A significant number of brute-force attempts were observed against SSH services, with a wide range of usernames and passwords being tested.
- Several malicious commands were executed on compromised systems, primarily aimed at downloading and executing malware, and establishing persistent access.

This report provides a detailed analysis of the attacks, including breakdowns by honeypot type, top attacking IP addresses, targeted ports, exploited CVEs, credentials used, and commands executed. The findings of this report are intended to provide situational awareness of the current threat landscape and inform defensive strategies.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The following table details the distribution of attacks across the different honeypot services. The Cowrie honeypot, which emulates an SSH server, recorded the highest number of attacks, indicating a strong focus on compromising SSH servers.

| Honeypot Service | Attack Count |
|---|---|
| Cowrie | 5231 |
| Honeytrap | 2356 |
| Suricata | 1624 |
| Ciscoasa | 1464 |
| Sentrypeer | 327 |
| Dionaea | 66 |
| Heralding | 50 |
| Redishoneypot | 34 |
| H0neytr4p | 25 |
| Tanner | 24 |
| Adbhoney | 15 |
| Dicompot | 18 |
| Mailoney | 19 |
| ConPot | 12 |
| ElasticPot | 4 |
| Honeyaml | 6 |
| Ipphoney | 3 |
| Miniprint | 6 |
| ssh-rsa | 4 |

### 3.2. Top 20 Attacking IP Addresses

The following table lists the top 20 IP addresses that were most active during the reporting period. These IPs are likely part of botnets or compromised systems used for malicious activities.

| IP Address | Attack Count |
|---|---|
| 161.35.177.74 | 894 |
| 146.59.95.254 | 513 |
| 186.96.151.198 | 443 |
| 113.193.234.210 | 349 |
| 27.128.170.160 | 300 |
| 185.156.73.166 | 384 |
| 185.156.73.167 | 380 |
| 92.63.197.55 | 361 |
| 92.63.197.59 | 344 |
| 210.231.185.234 | 390 |
| 128.199.33.46 | 222 |
| 37.189.196.88 | 222 |
| 61.190.114.203 | 216 |
| 65.75.222.182 | 212 |
| 27.155.77.43 | 278 |
| 14.241.254.5 | 243 |
| 208.109.190.200 | 183 |
| 150.109.244.181 | 173 |
| 219.92.8.22 | 149 |
| 103.187.162.235 | 113 |

### 3.3. Top 20 Attacked Ports

The following table shows the top 20 most targeted TCP and UDP ports. Port 22 (SSH) was the most frequently attacked, followed by port 5060 (SIP), which is commonly used for VoIP services.

| Port | Attack Count |
|---|---|
| 22 | 644 |
| 5060 | 327 |
| 8333 | 135 |
| TCP/445 | 71 |
| 23 | 52 |
| TCP/22 | 61 |
| vnc/5900 | 47 |
| 6379 | 31 |
| 8090 | 31 |
| 80 | 30 |
| 31337 | 26 |
| 5901 | 27 |
| TCP/1080 | 24 |
| 27017 | 19 |
| 17000 | 16 |
| 8200 | 18 |
| 51005 | 18 |
| 443 | 14 |
| TCP/443 | 13 |
| 8081 | 11 |

### 3.4. CVEs Exploited

The honeypots detected several attacks attempting to exploit known vulnerabilities. The following CVEs were identified in the attack traffic. The Log4Shell vulnerability (CVE-2021-44228) continues to be a popular target for attackers.

- **CVE-2021-44228**: Apache Log4j Remote Code Execution
- **CVE-2002-0013**: Multiple TCP/IP implementations sequence number generation vulnerability
- **CVE-2002-0012**: TCP implementations window size vulnerability
- **CVE-1999-0517**: Cisco IOS HTTP server vulnerability
- **CVE-2019-11500**: Pulse Secure VPN vulnerability
- **CVE-2021-3449**: OpenSSL Denial of Service vulnerability
- **CVE-1999-0183**: IMAP buffer overflow vulnerability
- **CVE-2006-2369**: Barracuda Spam Firewall command injection vulnerability
- **CVE-2018-13379**: Fortinet FortiGate SSL VPN path traversal vulnerability
- **CVE-2016-6563**: OpenSSH user enumeration vulnerability

### 3.5. Top 20 Credentials Used in Attacks

A large number of brute-force attacks were observed, with attackers attempting to gain access using common and default credentials. The following table lists the top 20 most frequently used username/password combinations.

| Username/Password | Count |
|---|---|
| 345gs5662d34/345gs5662d34 | 33 |
| root/3245gs5662d34 | 22 |
| root/nPSpP4PBW0 | 11 |
| root/Passw0rd | 8 |
| root/LeitboGi0ro | 7 |
| test/zhbjETuyMffoL8F | 7 |
| root/1234 | 5 |
| root/Linux@123 | 5 |
| root/ | 4 |
| root/Wc123456 | 4 |
| root/Darya123456 | 3 |
| root/test12 | 3 |
| dms/dms123 | 3 |
| mc/minecraft | 3 |
| node/node | 3 |
| pradeep/pradeep | 3 |
| appuser/1234 | 3 |
| root/kai | 3 |
| test/3245gs5662d34 | 3 |
| rico/rico123 | 3 |

### 3.6. Top 20 Commands Executed

Upon successful compromise, attackers executed a variety of commands. The following table lists the top 20 commands observed in the honeypots. Many of these commands are aimed at downloading and executing malware, gathering system information, and establishing persistence.

| Command | Count |
|---|---|
| `uname -a` | 35 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 34 |
| `lockr -ia .ssh` | 34 |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 34 |
| `cat /proc/cpuinfo | grep name | wc -l` | 33 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 33 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 33 |
| `ls -lh $(which ls)` | 33 |
| `which ls` | 33 |
| `crontab -l` | 33 |
| `w` | 33 |
| `uname -m` | 34 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 34 |
| `top` | 34 |
| `uname` | 34 |
| `whoami` | 34 |
| `lscpu | grep Model` | 34 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 34 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | 23 |
| `Enter new UNIX password: ` | 10 |

## 4. Notes and Limitations

- The data in this report is based on a high-interaction honeypot network (T-Pot) and represents a sample of malicious activity on the internet. It does not reflect all threats targeting the organization.
- The source IP addresses may be spoofed or belong to compromised systems, making attribution difficult.
- The CVEs listed are based on signatures and patterns observed in the attack traffic and may not always represent a successful exploit.
- The commands listed are those executed within the honeypot environment. The full extent of the attackers' capabilities may not be represented.
- The short time window of this report (40 minutes) provides a snapshot of the threat landscape but may not capture long-term trends.
- The data is presented as recorded by the honeypots and has been aggregated for this report. Some data may be incomplete or require further analysis for full context.

This report provides a valuable insight into the automated threats and attack techniques currently being used in the wild. It is recommended to use this information to bolster defenses, such as by blocking the top attacking IP addresses, patching the identified vulnerabilities, and implementing strong password policies.
