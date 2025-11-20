**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-11T12:01:35Z
**Timeframe:** 2025-10-11T11:20:01Z to 2025-10-11T12:00:01Z
**Files Used:**
- agg_log_20251011T112001Z.json
- agg_log_20251011T114002Z.json
- agg_log_20251011T120001Z.json

**Executive Summary**
This report summarizes 16,852 security events captured by the honeypot network over a 40-minute period. The majority of activity was logged by the Cowrie (SSH/Telnet) and Suricata (IDS) honeypots. A significant portion of the attacks originated from IP address 102.222.184.4, primarily targeting SMB services on TCP port 445, and was associated with the DoublePulsar backdoor. Attackers frequently attempted to gain access via SSH, using common credential pairs and attempting to install malicious SSH keys. Several CVEs were targeted, and multiple files related to botnet activity were downloaded.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 6,627
- Suricata: 3,684
- Honeytrap: 2,705
- Ciscoasa: 2,081
- Dionaea: 1,111
- H0neytr4p: 232
- Sentrypeer: 178
- Tanner: 68
- Redishoneypot: 60
- Mailoney: 46
- Honeyaml: 19
- Heralding: 14
- ConPot: 11
- ElasticPot: 6
- Adbhoney: 6
- ssh-rsa: 2
- Ipphoney: 2

**Top Attacking IPs:**
- 102.222.184.4: 1883
- 45.78.193.108: 1187
- 209.38.37.15: 511
- 203.135.22.130: 472
- 213.149.166.133: 464
- 152.32.135.217: 371
- 199.195.248.191: 234
- 118.193.61.149: 283
- 5.195.226.17: 272
- 78.39.48.166: 276
- 122.166.211.27: 247
- 134.209.162.179: 214
- 160.191.150.196: 198
- 176.213.141.182: 193
- 203.135.42.112: 172
- 159.65.133.180: 179
- 152.32.145.25: 156
- 195.10.205.242: 144
- 91.205.219.185: 138
- 27.150.188.148: 151

**Top Targeted Ports/Protocols:**
- TCP/445: 1885
- 445: 1078
- 22: 970
- TCP/8443: 346
- 5060: 178
- 443: 176
- TCP/443: 152
- 5903: 190
- 8333: 88
- TCP/8080: 96
- 1194: 78
- 6379: 57
- 25565: 68
- 5908: 84
- 5909: 82
- 5901: 78
- 25: 54
- TCP/80: 28
- 23: 36
- UDP/161: 50

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-41773
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-42013
- CVE-1999-0183
- CVE-2005-4050
- CVE-2022-27255

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 31
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 31
- `lockr -ia .ssh`: 31
- `cat /proc/cpuinfo | grep name | wc -l`: 28
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 28
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 28
- `ls -lh $(which ls)`: 28
- `which ls`: 28
- `crontab -l`: 28
- `w`: 28
- `uname -m`: 28
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 28
- `top`: 28
- `uname`: 28
- `uname -a`: 28
- `whoami`: 28
- `lscpu | grep Model`: 28
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 28
- `Enter new UNIX password: `: 17
- `Enter new UNIX password:`: 11

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1883
- ET DROP Dshield Block Listed Source group 1: 351
- ET SCAN NMAP -sS window 1024: 148
- GPL INFO SOCKS Proxy attempt: 45
- ET TOR Known Tor Exit Node Traffic group 94: 37
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 94: 35
- ET INFO Incoming Basic Auth Base64 HTTP Password detected unencrypted: 34
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 64
- GPL SNMP request udp: 49
- ET INFO Reserved Internal IP Traffic: 61

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 30
- root/nPSpP4PBW0: 16
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 13
- root/3245gs5662d34: 12
- admin/admin1234567890: 6
- pi/123: 6
- Admin/Admin2006: 6
- samba/samba: 6
- test/test@123: 6
- user/7777777777: 6
- config/1234: 6
- dns/dns: 6
- test/22: 4
- root/intellicell: 4
- root/adminHW: 3
- root/Pr0t3c73d841: 4
- root/555555: 4
- root/Rohs05tlNetwork: 4
- root/oplk7482: 4
- ansible/ansible!: 3

**Files Uploaded/Downloaded:**
- sh: 90
- config.all.php?x: 31
- 11: 8
- fonts.gstatic.com: 8
- css?family=Libre+Franklin...: 8
- ie8.css?ver=1.0: 8
- html5.js?ver=3.7.3: 8
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2

**HTTP User-Agents:**
- No data available in the provided logs.

**SSH Clients:**
- No data available in the provided logs.

**SSH Servers:**
- No data available in the provided logs.

**Top Attacker AS Organizations:**
- No data available in the provided logs.

**Key Observations and Anomalies**
- **High Volume of SMB Exploitation:** The most frequent signature triggered was related to the DoublePulsar backdoor, indicating widespread, automated attempts to exploit the SMB vulnerability.
- **Persistent SSH Intrusion Attempts:** Attackers repeatedly used commands to clear existing SSH configurations and install a specific SSH public key (`... mdrfckr`), indicating a coordinated campaign to maintain persistent access.
- **Botnet Activity:** The downloading of multiple files with names like `arm.urbotnetisass`, `mips.urbotnetisass`, etc., strongly suggests attempts to install botnet clients on compromised devices with different architectures.
- **Credential Stuffing:** A wide variety of common and default username/password combinations were attempted, particularly against the Cowrie honeypot.
- **Reconnaissance:** Standard reconnaissance commands (`uname`, `lscpu`, `whoami`, etc.) were executed post-login, which is typical behavior for automated scripts assessing a compromised environment.