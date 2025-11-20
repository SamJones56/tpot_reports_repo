Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T15:01:24Z
**Timeframe:** 2025-10-18T14:20:01Z to 2025-10-18T15:00:01Z
**Files Used:**
- agg_log_20251018T142001Z.json
- agg_log_20251018T144001Z.json
- agg_log_20251018T150001Z.json

**Executive Summary**
This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 24,102 attacks were recorded. The most active honeypot was Sentrypeer, and the most frequent attacker IP was 5.182.209.68. The most targeted port was 5060/UDP (SIP). Several CVEs were detected, with CVE-2022-27255 being the most common. A significant number of shell commands were executed, indicating successful logins and post-exploitation activity.

**Detailed Analysis**

***Attacks by Honeypot***
- Sentrypeer: 9546
- Cowrie: 5907
- Mailoney: 5097
- Honeytrap: 1546
- Ciscoasa: 847
- Suricata: 607
- Tanner: 338
- Redishoneypot: 79
- Dionaea: 43
- Adbhoney: 21
- Miniprint: 24
- H0neytr4p: 17
- ConPot: 18
- ElasticPot: 7
- Honeyaml: 4
- Ipphoney: 1

***Top Attacking IPs***
- 5.182.209.68
- 172.245.211.35
- 194.50.16.73
- 176.9.111.156
- 72.146.232.13
- 161.132.48.14
- 89.117.150.149
- 61.151.249.194
- 162.214.92.14
- 172.176.97.33

***Top Targeted Ports/Protocols***
- 5060
- 25
- 22
- 80
- 5903
- 8333
- 6379
- 5901
- TCP/22
- 2323

***Most Common CVEs***
- CVE-2022-27255
- CVE-2021-44228
- CVE-2002-0013, CVE-2002-0012
- CVE-2021-3449
- CVE-2019-11500
- CVE-2024-3721
- CVE-2001-0414
- CVE-1999-0517

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:

***Signatures Triggered***
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Potential SSH Scan
- 2001219
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- 2038669
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 99

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/123@Robert
- ftpuser/ftppassword
- root/Qaz123qaz
- admin/admin00
- operator/operator2007
- admin/4444
- ftp/Password123
- linda/123

***Files Uploaded/Downloaded***
- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

***HTTP User-Agents***
- (No data in logs)

***SSH Clients and Servers***
- (No data in logs)

***Top Attacker AS Organizations***
- (No data in logs)

**Key Observations and Anomalies**
- A high volume of attacks originated from the IP address 5.182.209.68, primarily targeting the SIP port 5060. This suggests a targeted attack campaign against VoIP services.
- A significant number of commands were executed on the Cowrie honeypot, indicating that attackers were able to successfully log in and attempted to establish persistence by modifying SSH keys and cron jobs.
- The `interesting` commands show attempts to download and execute malicious scripts from external servers. The file names `w.sh`, `c.sh`, and `*.urbotnetisass` suggest the deployment of malware or botnet clients.
- The most frequently observed CVE was CVE-2022-27255, a buffer overflow vulnerability in Realtek eCos SDK. This indicates that attackers are actively exploiting this vulnerability.
- The high number of login attempts with various credentials highlights the ongoing brute-force attacks against SSH and other services. The credentials used are a mix of default, weak, and previously compromised passwords.
