# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T20:57:13Z
**Timeframe:** 2025-09-30T08:57:13Z to 2025-09-30T20:57:13Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-09-30T09:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T10:02:23Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T11:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T12:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T13:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T14:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T15:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T16:11:30Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T17:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T18:02:24Z.md

---

### **Executive Summary**

This report summarizes 124,611 malicious events targeting our honeypot infrastructure over a 12-hour period. The Cowrie honeypot, which emulates SSH and Telnet services, recorded the highest number of attacks, indicating a sustained campaign of brute-force and command-injection attempts. The most prominent attack vectors were attempts to exploit SMB and SSH vulnerabilities, with a significant amount of traffic originating from a small number of highly active IP addresses.

Attackers were observed attempting to download and execute a variety of malware, with the `urbotnetisass` family of malware being the most common. This malware appears to be a multi-architecture botnet client designed to compromise a wide range of devices. Attackers also frequently attempted to establish persistent access by adding their own SSH keys to the `authorized_keys` file.

A number of known vulnerabilities were targeted, with a focus on older, well-known CVEs such as those related to SNMPv1, as well as more recent vulnerabilities in OpenSSL. The high volume of automated attacks, coupled with the use of known exploits and malware, suggests that the majority of the observed activity is from botnets and other automated tools.

---

### **Detailed Analysis**

#### **Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

#### **Attacks by Honeypot**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 52805 |
| Honeytrap | 22402 |
| Suricata | 19692 |
| Ciscoasa | 11472 |
| Dionaea | 6301 |
| Mailoney | 2728 |
| Sentrypeer | 2120 |
| Tanner | 623 |
| Adbhoney | 340 |
| Heralding | 251 |
| H0neytr4p | 297 |
| ConPot | 258 |
| Redishoneypot | 170 |
| Miniprint | 255 |
| ElasticPot | 86 |
| Dicompot | 30 |
| Honeyaml | 61 |
| Ipphoney | 13 |
| Wordpot | 1 |
| ssh-ed25519 | 2 |
| ssh-rsa | 32 |

#### **Top Source Countries**

| Country | Attack Count |
|---|---|
| Russia | 844 |
| Vietnam | 811 |
| India | 744 |
| Pakistan | 533 |
| Indonesia | 525 |
| Netherlands | 228 |
| United States | 168 |
| Brazil | 115 |
| China | 114 |
| Germany | 107 |

#### **Top Attacking IPs**

| IP Address | Attack Count |
|---|---|
| 88.214.50.58 | 844 |
| 194.50.16.131 | 1759 |
| 105.112.198.126 | 1463 |
| 196.202.4.136 | 1299 |
| 187.201.26.33 | 1307 |
| 95.84.58.194 | 999 |
| 145.239.139.38 | 962 |
| 86.54.42.238 | 821 |
| 45.78.224.161 | 746 |
| 209.38.21.236 | 1499 |

#### **Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---|---|
| 445 | 10839 |
| 22 | 5198 |
| 5060 | 2120 |
| 8333 | 1059 |
| 25 | 2728 |
| 23 | 456 |
| 80 | 609 |
| TCP/1080 | 348 |
| 6001 | 33 |
| 3306 | 205 |

#### **Most Common CVEs**

| CVE | Count |
|---|---|
| CVE-2002-0013, CVE-2002-0012 | 68 |
| CVE-2021-3449 | 40 |
| CVE-2019-11500 | 28 |
| CVE-2024-3721 | 6 |
| CVE-1999-0183 | 2 |
| CVE-2021-35394 | 3 |
| CVE-2009-2765 | 2 |
| CVE-2005-4050 | 3 |
| CVE-2016-5696 | 8 |
| CVE-2024-1709 | 6 |

#### **Commands Attempted by Attackers**

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 336 |
| `lockr -ia .ssh` | 336 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` | 335 |
| `uname -a` | 66 |
| `cat /proc/cpuinfo | grep name | wc -l` | 66 |
| `whoami` | 66 |
| `w` | 66 |
| `top` | 66 |
| `crontab -l` | 66 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 66 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 65 |
| `cd /data/local/tmp/; rm *; busybox wget ...` | 13 |
| `Enter new UNIX password:` | 44 |

#### **Signatures Triggered**

| Signature | Count |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 4585 |
| ET DROP Dshield Block Listed Source group 1 | 2246 |
| ET SCAN NMAP -sS window 1024 | 1232 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 548 |
| ET INFO Reserved Internal IP Traffic | 346 |
| GPL INFO SOCKS Proxy attempt | 228 |
| ET HUNTING RDP Authentication Bypass Attempt | 213 |
| ET SCAN Potential SSH Scan | 52 |
| ET INFO VNC Authentication Failure | 27 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32 | 97 |

#### **Users / Login Attempts**

| Username/Password | Count |
|---|---|
| 345gs5662d34/345gs5662d34 | 344 |
| root/3245gs5662d34 | 146 |
| testuser/ | 199 |
| root/2glehe5t24th1issZs | 49 |
| superadmin/admin123 | 39 |
| test/zhbjETuyMffoL8F | 38 |
| root/LeitboGi0ro | 39 |
| root/nPSpP4PBW0 | 18 |
| splunk/splunk123 | 27 |
| foundry/foundry | 31 |

#### **Files Uploaded/Downloaded**

| Filename | Count |
|---|---|
| arm.urbotnetisass | 34 |
| arm5.urbotnetisass | 34 |
| arm6.urbotnetisass | 34 |
| arm7.urbotnetisass | 34 |
| x86_32.urbotnetisass | 34 |
| mips.urbotnetisass | 34 |
| mipsel.urbotnetisass | 34 |
| wget.sh | 18 |
| w.sh | 5 |
| c.sh | 5 |
| boatnet.mpsl | 3 |
| rondo.dgx.sh | 3 |

#### **HTTP User-Agents**

| User-Agent | Count |
|---|---|
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36 | 2 |

#### **SSH Clients and Servers**

No specific SSH client or server versions were recorded in the logs.

#### **Top Attacker AS Organizations**

No attacker AS organizations were recorded in the logs.

---

### **Google Searches**

- OSINT report on IP address 88.214.50.58
- OSINT report on IP address 194.50.16.131
- OSINT report on urbotnetisass malware
- OSINT report on CVE-2002-013 and CVE-2002-0012
- OSINT report on CVE-2021-3449

---

### **Key Observations and Anomalies**

- **High-Volume Automated Attacks:** The vast majority of attacks are automated, originating from a small number of IP addresses. The top attacking IP, 88.214.50.58, is a known malicious node associated with a Russian bulletproof hosting service. This IP has been linked to the distribution of malware and involvement in the "Clickfix" macOS malware campaign.
- **"urbotnetisass" Malware:** The most frequently downloaded malware is from the "urbotnetisass" family. OSINT research indicates that this is not a known malware family, and the name is likely a custom taunt from the attacker ("ur botnet is ass"). The malware is a multi-architecture botnet client, suggesting a widespread campaign to compromise a variety of devices.
- **Targeted Vulnerabilities:** Attackers are targeting a mix of old and new vulnerabilities. The most frequently targeted CVEs are a pair of SNMPv1 vulnerabilities from 2002 (CVE-2002-0013 and CVE-2002-0012). This indicates that attackers are still finding success in exploiting legacy systems that have not been patched. More recent vulnerabilities, such as CVE-2021-3449 in OpenSSL, are also being targeted.
- **Persistent Access Attempts:** A common tactic observed is the attempt to add a malicious SSH key to the `authorized_keys` file. This would give the attacker persistent access to the compromised system. The key is often associated with the username "mdrfckr".
- **Focus on SMB and SSH:** The most heavily targeted services are SMB (port 445) and SSH (port 22). This is consistent with widespread automated scanning for vulnerable systems. The high number of "DoublePulsar Backdoor" signatures suggests that attackers are attempting to exploit the EternalBlue vulnerability.
- **Lack of Sophistication:** The majority of the observed attacks are not sophisticated. They rely on brute-force attacks, known vulnerabilities, and common malware. This suggests that the attackers are casting a wide net, hoping to find unpatched and poorly secured systems.
