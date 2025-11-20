# Honeypot Attack Summary Report

- **Report Generation Time:** 2025-10-21T08:00:00Z
- **Timeframe:** 2025-10-20T19:45:41Z to 2025-10-21T07:45:41Z
- **Files Used:**
    - `Honeypot_Attack_Summary_Report_2025-10-20T20:01:59Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-20T21:02:12Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-20T22:02:02Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-20T23:02:05Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T00:02:02Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T01:01:46Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T02:01:54Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T03:01:54Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T04:02:12Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T05:01:46Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T06:02:02Z.md`
    - `Honeypot_Attack_Summary_Report_2025-10-21T07:02:11Z.md`

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the past 12 hours. A total of **120,440** events were recorded and analyzed. The threat landscape was dominated by automated attacks, primarily targeting SSH, SMB, and SIP services. The Cowrie honeypot, simulating an SSH server, recorded the highest number of interactions, highlighting the relentless nature of SSH brute-force and credential-stuffing attacks.

The most aggressive attacker, identified by the IP address **72.146.232.13**, was responsible for a significant portion of the attack traffic. OSINT analysis confirms this IP has a history of malicious SSH activity. A notable trend observed was the widespread attempt to deploy the **urbotnetisass** malware, a variant of the Mirai botnet, indicating a concerted effort to recruit our honeypot devices into a DDoS botnet.

Attackers demonstrated a clear pattern of post-exploitation behavior, focusing on system reconnaissance and establishing persistence. The use of the non-standard `lockr` command, in conjunction with `chattr`, to make the `.ssh` directory immutable, points to a sophisticated technique to maintain control over compromised systems.

A wide range of vulnerabilities were targeted, from recent CVEs like **CVE-2024-3721** to legacy vulnerabilities dating back to 2002. This suggests that attackers are employing a broad-spectrum approach, hoping to find unpatched systems regardless of their age.

Overall, the data from the last 12 hours paints a picture of a highly automated and opportunistic threat environment, with a strong focus on IoT/embedded device exploitation and botnet recruitment.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP      | Public IP       |
|----------|-----------------|-----------------|
| hive-us  | 10.128.0.3      | 34.123.129.205  |
| sens-tai | 10.140.0.3      | 104.199.212.115 |
| sens-tel | 10.208.0.3      | 34.165.197.224  |
| sens-dub | 172.31.36.128   | 3.253.97.195    |
| sens-ny  | 10.108.0.2      | 161.35.180.163  |

### Attacks by Honeypot (Aggregated)

| Honeypot        | Event Count |
|-----------------|-------------|
| Cowrie          | 67,225      |
| Honeytrap       | 31,254      |
| Suricata        | 14,408      |
| Dionaea         | 4,944       |
| Sentrypeer      | 4,004       |
| Mailoney        | 1,221       |
| Adbhoney        | 579         |
| Tanner          | 505         |
| Heralding       | 347         |
| Redishoneypot   | 255         |
| Ciscoasa        | 249         |
| H0neytr4p       | 240         |
| ElasticPot      | 160         |
| ConPot          | 144         |
| Dicompot        | 76          |
| Miniprint       | 124         |
| Ipphoney        | 52          |
| Honeyaml        | 64          |
| Wordpot         | 9           |

### Top Source Countries (Data not available in logs)

### Top Attacking IPs

| IP Address      | Event Count |
|-----------------|-------------|
| 72.146.232.13   | 10,240      |
| 186.89.3.142    | 1,297       |
| 5.167.79.4      | 1,251       |
| 81.19.135.103   | 1,100       |
| 134.199.207.7   | 1,001       |
| 196.251.88.103  | 1,001       |
| 129.212.189.131 | 997         |
| 66.116.196.243  | 799         |
| 129.212.187.82  | 740         |
| 152.42.203.0    | 400         |

### Top Targeted Ports/Protocols

| Port/Protocol | Event Count |
|---------------|-------------|
| 22 (SSH)      | 11,440      |
| 445 (SMB)     | 4,910       |
| 5060 (SIP)    | 3,821       |
| 5903          | 1,600       |
| 5901          | 1,200       |
| 8333          | 900         |
| 5905          | 800         |
| 5904          | 750         |
| 25 (SMTP)     | 1,150       |
| 80 (HTTP)     | 800         |

### Most Common CVEs

| CVE                 | Description                                                                                             |
|---------------------|---------------------------------------------------------------------------------------------------------|
| CVE-2022-27255      | A critical stack-based buffer overflow in Realtek's eCos SDK, exploitable via a crafted SIP packet.         |
| CVE-2019-11500      | An out-of-bounds memory write vulnerability in Dovecot/Pigeonhole due to improper handling of NUL characters. |
| CVE-2021-3449       | A denial-of-service vulnerability in OpenSSL, triggered by a malicious renegotiation ClientHello message.    |
| CVE-2024-3721       | A critical OS command injection vulnerability in TBK DVR devices.                                         |
| CVE-2002-0013       | A vulnerability in SNMPv1 implementations allowing for denial of service or privilege escalation.         |
| CVE-2002-0012       | A similar vulnerability to CVE-2002-0013, but related to the handling of SNMPv1 trap messages.               |

### Commands Attempted by Attackers

| Command                                                                 | Frequency |
|-------------------------------------------------------------------------|-----------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                  | High      |
| `lockr -ia .ssh`                                                        | High      |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`               | High      |
| `cat /proc/cpuinfo | grep name | wc -l`                                 | High      |
| `uname -a`                                                              | High      |
| `Enter new UNIX password:`                                              | High      |
| `free -m ...`                                                           | High      |
| `ls -lh $(which ls)`                                                     | High      |
| `which ls`                                                              | High      |
| `crontab -l`                                                            | High      |
| `w`                                                                     | High      |
| `uname -m`                                                              | High      |
| `top`                                                                   | High      |
| `whoami`                                                                | High      |
| `lscpu | grep Model`                                                    | High      |
| `df -h ...`                                                             | High      |
| `echo ... | base64 -d | perl &`                                         | Low       |
| `cd /tmp || cd /var/run || ... wget ...`                                 | Low       |

### Signatures Triggered

| Signature                                                   | Frequency |
|-------------------------------------------------------------|-----------|
| ET DROP Dshield Block Listed Source group 1                 | High      |
| ET SCAN MS Terminal Server Traffic on Non-standard Port       | High      |
| ET SCAN NMAP -sS window 1024                                | High      |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | High      |
| ET HUNTING RDP Authentication Bypass Attempt                  | High      |
| ET INFO Reserved Internal IP Traffic                          | High      |
| ET SCAN Sipsak SIP scan                                     | Medium    |
| ET FTP FTP PWD/CWD command attempt without login              | Medium    |
| ET INFO curl User-Agent Outbound                              | Low       |

### Users / Login Attempts

| Username/Password             | Frequency |
|-------------------------------|-----------|
| 345gs5662d34/345gs5662d34     | High      |
| user01/Password01             | High      |
| deploy/123123                 | High      |
| user01/3245gs5662d34          | High      |
| deploy/1234                   | Medium    |
| root/admin...                 | Medium    |
| test/test                     | Medium    |
| jenkins/jenkins...            | Low       |
| weblogic/weblogic             | Low       |
| postgres/postgres             | Low       |

### Files Uploaded/Downloaded

| Filename              | Type/Note                               |
|-----------------------|-----------------------------------------|
| `wget.sh`, `w.sh`, `c.sh` | Generic downloader scripts              |
| `arm.urbotnetisass`   | Mirai botnet variant (ARM architecture)   |
| `arm5.urbotnetisass`  | Mirai botnet variant (ARMv5)            |
| `arm6.urbotnetisass`  | Mirai botnet variant (ARMv6)            |
| `arm7.urbotnetisass`  | Mirai botnet variant (ARMv7)            |
| `x86_32.urbotnetisass`| Mirai botnet variant (x86 32-bit)       |
| `mips.urbotnetisass`  | Mirai botnet variant (MIPS)             |
| `mipsel.urbotnetisass`| Mirai botnet variant (MIPSel)           |
| `Mozi.m`              | Mozi P2P botnet                         |
| `string.js`           | JavaScript file, potentially malicious  |
| `.../k.php?a=x86_64...` | PHP-based downloader                    |

### HTTP User-Agents

No significant user agents were recorded in this period.

### SSH Clients and Servers

No specific SSH clients or servers were recorded in this period.

### Top Attacker AS Organizations

No attacker AS organizations were recorded in this period.

### OSINT All Commands Captured

The commands captured indicate a clear, multi-stage attack pattern:
1.  **Reconnaissance:** Attackers first gather information about the system's architecture (`uname -a`, `lscpu`, `cat /proc/cpuinfo`), memory (`free -m`), and running processes (`top`).
2.  **Persistence:** They then attempt to establish persistent access by deleting the existing `.ssh` directory and adding their own SSH key to a new `authorized_keys` file. The use of `chattr -ia .ssh` and the custom `lockr -ia .ssh` command is a sophisticated technique to make this change immutable.
3.  **Malware Deployment:** Finally, they attempt to download and execute malware, such as the `urbotnetisass` botnet client, using `wget` or `curl`.

### OSINT High Frequency IPs and Low Frequency IPs Captured

| IP Address      | Frequency | OSINT Findings                                                                                                   |
|-----------------|-----------|------------------------------------------------------------------------------------------------------------------|
| 72.146.232.13   | High      | Located in Baton Rouge, LA. Known for SSH brute-force attacks and listed on multiple blocklists.                 |
| 186.89.3.142    | High      | No specific threat intelligence found in public OSINT. The high volume of SMB traffic from this IP is anomalous.    |
| 5.167.79.4      | High      | Associated with a Russian network (AS57026) with a high rate of abusive activity.                                |
| 81.19.135.103   | High      | Linked to port scanning and SSH brute-force attacks.                                                              |
| 134.199.207.7   | High      | Low reputation score, but limited public OSINT available.                                                          |
| 129.212.187.82  | High      | No specific threat intelligence found in public OSINT.                                                              |

### OSINT on CVEs

The CVEs targeted by attackers represent a mix of old and new vulnerabilities. This "shotgun" approach allows them to compromise a wide range of systems, from legacy devices that have not been patched in years to newer devices with recently disclosed vulnerabilities. The most notable CVEs are:
*   **CVE-2024-3721:** A recent and critical command injection vulnerability in TBK DVRs. The active exploitation of this CVE shows that attackers are quick to adopt new exploits.
*   **CVE-2022-27255:** A critical vulnerability in Realtek's eCos SDK, affecting millions of networking devices.
*   **Legacy CVEs (e.g., CVE-2002-0012, CVE-2002-0013):** The continued exploitation of these 20+ year-old vulnerabilities highlights the "long tail" of unpatched systems on the internet.

## Key Observations and Anomalies

1.  **The "urbotnetisass" Campaign:** The repeated and coordinated attempts to download and execute the `urbotnetisass` malware across multiple architectures is the most significant anomaly. This points to a large-scale, automated campaign to build a Mirai-based botnet.

2.  **The `lockr` Command:** The use of the non-standard `lockr` command is a unique and interesting observation. It is likely a renamed version of the `chattr` command, used to evade detection. This technique, associated with the "Outlaw" cybercrime group, demonstrates a higher level of sophistication than typical brute-force attacks.

3.  **The "345gs5662d34" Credentials:** The high frequency of login attempts with the username and password `345gs5662d34` is unusual. This could be a default credential for a specific type of IoT device or a hardcoded credential in a popular piece of malware.

4.  **The "mdrfckr" Signature:** The presence of the string "mdrfckr" in the SSH key that attackers attempt to install is a known signature of a specific botnet. This provides a clear link between the attacks observed and a known threat actor.

5.  **Perl-based IRC Bot:** The command `echo ... | base64 -d | perl &` was used to deploy a Perl-based IRC bot. This is a classic technique for building a DDoS botnet and shows that older methods are still effective.

6.  **DoublePulsar Activity:** The continued high volume of traffic related to the DoublePulsar backdoor is a stark reminder that even well-known and patched vulnerabilities can remain a significant threat for years.
