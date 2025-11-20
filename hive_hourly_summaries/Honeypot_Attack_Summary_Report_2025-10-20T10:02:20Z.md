# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T10:01:24Z
**Timeframe:** 2025-10-20T09:20:02Z to 2025-10-20T10:00:01Z
**Files Used:**
- agg_log_20251020T092002Z.json
- agg_log_20251020T094001Z.json
- agg_log_20251020T100001Z.json

## Executive Summary

This report summarizes 12,354 malicious events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force and command execution attempts. A significant portion of the traffic originated from IP address `129.212.191.62`. The most targeted ports were 22 (SSH) and 5060 (SIP). A number of CVEs were targeted, with a focus on older vulnerabilities. Attackers were observed attempting to install SSH keys to maintain persistence.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6191
- **Honeytrap:** 3044
- **Suricata:** 1075
- **Dionaea:** 946
- **Sentrypeer:** 732
- **Mailoney:** 211
- **Tanner:** 38
- **H0neytr4p:** 24
- **Dicompot:** 18
- **Ciscoasa:** 15
- **ElasticPot:** 15
- **Redishoneypot:** 20
- **ConPot:** 15
- **Adbhoney:** 5
- **Wordpot:** 1
- **Ipphoney:** 2
- **ssh-rsa:** 2

### Top Attacking IPs
- **129.212.191.62:** 992
- **72.146.232.13:** 809
- **186.10.24.214:** 861
- **172.245.92.249:** 430
- **138.68.167.183:** 434
- **201.23.232.149:** 430
- **150.95.190.167:** 425
- **185.255.90.135:** 296
- **216.189.157.132:** 298
- **185.243.5.158:** 225
- **45.200.233.125:** 228
- **107.170.36.5:** 197
- **45.128.199.34:** 218
- **159.65.133.180:** 253
- **125.22.249.36:** 154
- **176.65.141.119:** 195
- **94.76.228.52:** 144
- **222.85.205.147:** 110
- **179.33.210.213:** 104
- **160.187.147.127:** 120
- **152.32.215.227:** 110
- **139.59.229.250:** 105
- **196.251.80.153:** 82
- **167.172.123.15:** 43
- **124.29.214.52:** 44
- **157.230.232.255:** 39

### Top Targeted Ports/Protocols
- **22:** 1034
- **445:** 900
- **5060:** 692
- **1987:** 156
- **8333:** 159
- **25:** 197
- **5903:** 123
- **5904:** 77
- **5905:** 77
- **5901:** 75
- **8090:** 28
- **80:** 29
- **6379:** 17
- **23:** 51
- **4433:** 47

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2025-30208 CVE-2025-30208
- CVE-2024-3721 CVE-2024-3721
- CVE-2023-26801 CVE-2023-26801
- CVE-2009-2765
- CVE-2023-31983 CVE-2023-31983
- CVE-2019-16920 CVE-2019-16920
- CVE-2020-10987 CVE-2020-10987
- CVE-2023-47565 CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 283
- **2402000:** 283
- **ET SCAN NMAP -sS window 1024:** 116
- **2009582:** 116
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 90
- **2023753:** 90
- **ET INFO Reserved Internal IP Traffic:** 51
- **2002752:** 51
- **GPL INFO SOCKS Proxy attempt:** 11
- **2100615:** 11
- **ET CINS Active Threat Intelligence Poor Reputation IP group 13:** 10
- **2403312:** 10
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46:** 11
- **2403345:** 11
- **ET HUNTING RDP Authentication Bypass Attempt:** 17
- **2034857:** 17

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 26
- **user01/Password01:** 14
- **deploy/123123:** 7
- **root/adminHW:** 5
- **user/Pa$$w0rd:** 4
- **deploy/3245gs5662d34:** 4
- **ec2-user/3245gs5662d34:** 3
- **root/3245gs5662d34:** 5
- **oracle/oracle@2022:** 3
- **www/123:** 3
- **superuser/superuser123:** 3
- **anton/123:** 3
- **root/p@ssw0rd:** 3
- **default/1:** 3
- **ftpuser/123:** 3
- **root/abc150790:** 3

### Files Uploaded/Downloaded
- `resty)`
- `server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=`
- `rondo.qre.sh||busybox`
- `rondo.qre.sh||curl`
- `rondo.qre.sh)|sh`
- `` `busybox` ``
- `rondo.sbx.sh|sh&echo${IFS}`
- `login_pic.asp`

### HTTP User-Agents
- No user agents were logged in this period.

### SSH Clients and Servers
- No specific SSH client or server versions were logged in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this period.

## Key Observations and Anomalies

1.  **Persistent SSH Key Installation Attempts:** A recurring pattern of commands aimed at deleting the existing `.ssh` directory and adding a new authorized key was observed. This indicates a common tactic to gain persistent access to compromised systems.

2.  **System Reconnaissance:** Attackers frequently run commands to gather system information, such as `uname -a`, `lscpu`, and `free -m`. This is a typical post-exploitation step to understand the environment they are in.

3.  **Targeting of VoIP Services:** The high number of attempts on port 5060 suggests that SIP (Session Initiation Protocol) services are a common target for attackers, likely for toll fraud or to exploit vulnerabilities in VoIP systems.

4.  **Lack of Sophistication in Payloads:** The file download attempts and commands executed do not indicate a highly sophisticated actor. The use of common tools like `curl` and `busybox` from a shell script is a common tactic for script-kiddies and botnets.

5.  **Focus on Older CVEs:** The list of targeted CVEs includes many that are several years old. This suggests that attackers are scanning for unpatched systems and relying on older, well-known vulnerabilities. The presence of `CVE-2014-6271` (Shellshock) is a notable example of this.
