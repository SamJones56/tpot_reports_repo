
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T04:01:29Z
**Timeframe:** 2025-10-12T03:20:01Z to 2025-10-12T04:00:01Z
**Files Used:**
- agg_log_20251012T032001Z.json
- agg_log_20251012T034001Z.json
- agg_log_20251012T040001Z.json

## Executive Summary
This report summarizes 25,746 attacks detected by the honeypot network. The majority of attacks were captured by the Dionaea honeypot. The most prominent attacker IP was 103.136.5.30, and the most targeted port was 445. Several CVEs were observed, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. A number of commands were attempted by attackers, primarily related to system enumeration and establishing persistence.

## Detailed Analysis

### Attacks by Honeypot
- Dionaea: 11,604
- Honeytrap: 4,665
- Cowrie: 4,372
- Suricata: 2,963
- Ciscoasa: 1,701
- Sentrypeer: 109
- Mailoney: 105
- ConPot: 84
- H0neytr4p: 47
- Tanner: 36
- Redishoneypot: 27
- Adbhoney: 18
- Honeyaml: 9
- Ipphoney: 3
- Miniprint: 3

### Top Attacking IPs
- 103.136.5.30: 10,882
- 45.128.199.212: 1,358
- 161.132.48.14: 1,254
- 114.143.201.158: 1,212
- 46.32.178.186: 936
- 188.166.115.135: 560
- 147.45.112.157: 500
- 36.80.190.210: 495
- 43.229.78.35: 419
- 188.84.51.3: 179
- 103.139.192.188: 139
- 152.32.253.152: 129
- 103.183.74.46: 110
- 36.103.243.179: 105
- 167.250.224.25: 84
- 107.170.36.5: 89
- 68.183.193.0: 100
- 159.89.121.144: 92
- 68.183.207.213: 92
- 114.200.93.107: 80

### Top Targeted Ports/Protocols
- 445: 11,389
- 5038: 1,358
- 22: 814
- TCP/445: 1,209
- 5903: 189
- 25: 105
- 5060: 109
- 1025: 64
- 8333: 87
- 5909: 80
- 5901: 77
- 5908: 78
- 2121: 373
- 3306: 39
- 443: 38
- TCP/22: 20
- 10443: 43
- 2323: 24
- 23: 16

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-2005-4050: 1
- CVE-2022-27255 CVE-2022-27255: 1

### Commands Attempted by Attackers
- `uname -a`: 4
- `whoami`: 5
- `uname`: 4
- `top`: 4
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 4
- `uname -m`: 4
- `w`: 4
- `crontab -l`: 4
- `which ls`: 4
- `ls -lh $(which ls)`: 4
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 4
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 4
- `Enter new UNIX password:`: 4
- `Enter new UNIX password: `: 4
- `cat /proc/cpuinfo | grep name | wc -l`: 4
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 4
- `lockr -ia .ssh`: 4
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 4
- `uname -s -v -n -r -m`: 4
- `echo -e "123\\nXNbDRaZcsqaO\\nXNbDRaZcsqaO"|passwd|bash`: 1
- `echo "123\\nXNbDRaZcsqaO\\nXNbDRaZcsqaO\\n"|passwd`: 1
- `netstat -tulpn | head -10`: 1
- `echo -e "123456\\nu1ULfjdIuWJl\\nu1ULfjdIuWJl"|passwd|bash`: 1
- `echo "123456\\nu1ULfjdIuWJl\\nu1ULfjdIuWJl\\n"|passwd`: 1

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,206
- 2402000: 449
- ET DROP Dshield Block Listed Source group 1: 449
- 2023753: 294
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 294
- 2009582: 146
- ET SCAN NMAP -sS window 1024: 146
- 2034857: 126
- ET HUNTING RDP Authentication Bypass Attempt: 126
- 2002752: 57
- ET INFO Reserved Internal IP Traffic: 57
- 2403347: 31
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 31
- 2400028: 22
- ET DROP Spamhaus DROP Listed Traffic Inbound group 29: 22
- 2403346: 23
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 23
- 2403345: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
- 2001219: 17
- ET SCAN Potential SSH Scan: 17

### Users / Login Attempts
- cron/: 45
- admin/111111: 7
- ubnt/5555555: 6
- root/!QAZ2wsx: 6
- user1/123: 6
- support/Support13: 6
- Admin/123.com: 6
- debian/7: 6
- root/admin123456: 5
- root/Gelincik08: 4
- admin/letmein: 4
- root/eUi174: 4
- Administrator/p@ssw0rd: 6
- root/tms0430: 4
- admin/p@ssword: 4
- root/orisysindia: 4
- debian/qwerty123: 4
- test/test: 3
- root/12345: 3

### Files Uploaded/Downloaded
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
- bot.html)

### HTTP User-Agents
- None Observed

### SSH Clients
- None Observed

### SSH Servers
- None Observed

### Top Attacker AS Organizations
- None Observed

## Key Observations and Anomalies
- The vast majority of attacks are automated and opportunistic, targeting common vulnerabilities and default credentials.
- The IP address 103.136.5.30 was responsible for a significant portion of the total attack volume, indicating a potentially compromised machine or a dedicated attacker.
- The targeting of port 445 (SMB) remains a dominant trend, likely related to attempts to exploit vulnerabilities like EternalBlue.
- A notable observation is the attempt to download and execute `urbotnetisass` malware, suggesting a campaign to compromise IoT devices and servers.
- The commands executed by attackers are consistent with initial reconnaissance and attempts to establish a foothold on the system.
- The presence of DoublePulsar backdoor installation communication suggests that some of the attacks are related to sophisticated malware campaigns.
