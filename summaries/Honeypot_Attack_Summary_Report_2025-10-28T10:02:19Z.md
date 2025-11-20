Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T10:01:33Z
**Timeframe:** 2025-10-28T09:20:01Z to 2025-10-28T10:00:02Z
**Files Used:**
- agg_log_20251028T092001Z.json
- agg_log_20251028T094001Z.json
- agg_log_20251028T100002Z.json

### Executive Summary
This report summarizes 23,431 attacks recorded by honeypots within the specified timeframe. The majority of attacks were captured by the Cowrie honeypot. A significant portion of the attacks originated from IP address 201.55.118.153, and the most targeted port was 445/TCP (SMB). Attackers were observed attempting to exploit multiple vulnerabilities, including older CVEs and more recent ones like CVE-2021-44228. A common attack vector involved attempts to add SSH keys to the authorized_keys file for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 9,421
- **Honeytrap:** 4,596
- **Dionaea:** 3,091
- **Sentrypeer:** 2,118
- **Suricata:** 1,985
- **Ciscoasa:** 1,967
- **Adbhoney:** 71
- **Mailoney:** 114
- **Redishoneypot:** 23
- **H0neytr4p:** 20
- **Tanner:** 11
- **Ipphoney:** 6
- **Dicompot:** 3
- **Wordpot:** 2
- **ConPot:** 1
- **Honeyaml:** 2

**Top Attacking IPs:**
- 201.55.118.153: 1,526
- 161.132.48.14: 1,248
- 37.140.254.195: 1,227
- 144.172.108.231: 1,128
- 20.2.136.52: 1,120
- 14.103.149.244: 908
- 122.185.26.34: 840
- 185.243.5.121: 518
- 69.63.77.146: 420
- 163.172.99.31: 423
- 182.253.156.184: 365
- 196.28.242.198: 345
- 103.191.92.118: 340
- 103.145.145.80: 337
- 189.143.79.58: 326

**Top Targeted Ports/Protocols:**
- 445: 2,848
- 5060: 2,118
- 22: 1,416
- 5038: 1,227
- 5901: 332
- 1433: 173
- 8333: 125
- 5903: 133
- 25: 114
- 8291: 65
- TCP/22: 86
- TCP/80: 66
- 3306: 35

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2021-44228 CVE-2021-44228: 5
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2025-22457 CVE-2025-22457: 1

**Commands Attempted by Attackers:**
- `cat /proc/cpuinfo | grep name | wc -l`: 46
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 46
- `lockr -ia .ssh`: 46
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 45
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 45
- `ls -lh $(which ls)`: 45
- `which ls`: 45
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 45
- `crontab -l`: 44
- `w`: 44
- `uname -m`: 45
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 45
- `top`: 45
- `uname`: 45
- `uname -a`: 45
- `whoami`: 45
- `lscpu | grep Model`: 45
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 45
- `Enter new UNIX password: `: 23
- `Enter new UNIX password:`: 23

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 424
- 2402000: 424
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 332
- 2023753: 332
- ET SCAN NMAP -sS window 1024: 198
- 2009582: 198
- ET HUNTING RDP Authentication Bypass Attempt: 110
- 2034857: 110
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61
- ET HUNTING curl User-Agent to Dotted Quad: 30
- 2034567: 30
- ET INFO curl User-Agent Outbound: 30
- 2013028: 30
- ET SCAN Potential SSH Scan: 23
- 2001219: 23

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 39
- root/3245gs5662d34: 17
- root/: 10
- saga/sagasaga: 8
- root/kmt2012KMT: 4
- root/koe4Leuv: 4
- kontakt/3245gs5662d34: 4
- minna/minna: 4
- root/koncepto: 4
- deploy/deploy2025: 4
- root/kovanie99: 4
- root/Kohxee1oonahphaewiab: 4
- ftpuser/test1234: 4
- root/KOKs432002: 4

**Files Uploaded/Downloaded:**
- wget.sh;: 28
- w.sh;: 7
- c.sh;: 7
- arm.uhavenobotsxd;: 2
- arm5.uhavenobotsxd;: 2
- arm6.uhavenobotsxd;: 2
- arm7.uhavenobotsxd;: 2
- x86_32.uhavenobotsxd;: 2
- mips.uhavenobotsxd;: 2
- mipsel.uhavenobotsxd;: 2

**HTTP User-Agents:**
- No user agents were reported in this timeframe.

**SSH Clients and Servers:**
- No specific SSH clients or servers were reported in this timeframe.

**Top Attacker AS Organizations:**
- No AS organizations were reported in this timeframe.

### Key Observations and Anomalies
- The high volume of attacks on port 445 suggests widespread scanning for SMB vulnerabilities.
- The repeated attempts to add a specific SSH key to `authorized_keys` indicate a coordinated campaign to gain persistent access to vulnerable systems.
- The presence of commands to download and execute shell scripts (`wget.sh`, `c.sh`, `w.sh`) is indicative of attempts to install malware or backdoors.
- The variety of architectures in the downloaded files (arm, x86, mips) suggests that the attackers are attempting to compromise a wide range of IoT and embedded devices.
- A new CVE, `CVE-2025-22457`, was observed, which may be a typo or a new, undisclosed vulnerability. This warrants further investigation.
