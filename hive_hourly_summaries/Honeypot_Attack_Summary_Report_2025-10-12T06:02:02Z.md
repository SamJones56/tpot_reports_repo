Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T06:01:39Z
**Timeframe:** 2025-10-12T05:20:01Z to 2025-10-12T06:00:01Z
**Files Used:**
- agg_log_20251012T052001Z.json
- agg_log_20251012T054001Z.json
- agg_log_20251012T060001Z.json

### Executive Summary

This report summarizes 29,891 events collected from the honeypot network. The majority of attacks were captured by the Dionaea honeypot, primarily targeting port 445 (SMB). The most prominent attacker IP was `122.121.74.82`. A significant number of activities involved reconnaissance commands, attempts to modify SSH authorized keys, and exploitation of older vulnerabilities, including CVE-2002-0013, CVE-2002-0012, and CVE-1999-0517. Network traffic triggered a high number of alerts for blacklisted IP sources (Dshield, Spamhaus).

### Detailed Analysis

**Attacks by Honeypot**
- Dionaea: 14,488
- Honeytrap: 5,678
- Cowrie: 5,542
- Ciscoasa: 1,760
- Suricata: 1,516
- Sentrypeer: 526
- Tanner: 177
- Mailoney: 102
- Adbhoney: 16
- H0neytr4p: 27
- Honeyaml: 16
- Redishoneypot: 18
- Dicompot: 6
- ConPot: 4
- ElasticPot: 4
- Miniprint: 8
- Ipphoney: 3

**Top Attacking IPs**
- 122.121.74.82: 12,897
- 212.30.37.162: 2,961
- 134.209.54.142: 885
- 223.100.22.69: 760
- 188.166.115.135: 364
- 223.197.248.209: 317
- 43.229.78.35: 314
- 20.91.250.177: 233
- 210.79.190.46: 243
- 62.141.43.183: 291
- 107.174.67.215: 198
- 52.172.177.191: 232
- 158.178.141.16: 178

**Top Targeted Ports/Protocols**
- 445: 13,666
- 5038: 2,961
- 22: 850
- 5060: 526
- TCP/21: 216
- 5903: 172
- 80: 181
- 21: 111
- 23: 71
- 25: 102
- 8333: 85
- 3306: 62

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012: 21
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 17
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-1999-0517: 1

**Commands Attempted by Attackers**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 22
- `lockr -ia .ssh`: 22
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`: 22
- `crontab -l`: 21
- `uname -a`: 21
- `cat /proc/cpuinfo | grep name | wc -l`: 21
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 21
- `ls -lh $(which ls)`: 21
- `which ls`: 21
- `w`: 20
- `uname -m`: 20
- `top`: 20
- `whoami`: 20
- `Enter new UNIX password:`: 17

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1 / 2402000: 474
- ET SCAN NMAP -sS window 1024 / 2009582: 145
- ET FTP FTP PWD command attempt without login / 2010735: 107
- ET FTP FTP CWD command attempt without login / 2010731: 104
- ET INFO Reserved Internal IP Traffic / 2002752: 49
- ET SCAN Potential SSH Scan / 2001219: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 45 / 2403344: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 44 / 2403343: 18
- GPL SNMP request udp / 2101417: 19
- GPL SNMP public access udp / 2101411: 17

**Users / Login Attempts**
- cron/: 54
- 345gs5662d34/345gs5662d34: 20
- default/default123: 6
- test/6666: 6
- root/openvpnas: 7
- admin/88888: 4
- root/a36949359: 4
- admin/444444: 4
- root/zoloterra: 4
- admin/1981: 4

**Files Uploaded/Downloaded**
- sh: 6
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
- mipsel.urbotnetisass: 2

**HTTP User-Agents**
- (No data)

**SSH Clients and Servers**
- (No data)

**Top Attacker AS Organizations**
- (No data)

### Key Observations and Anomalies

- **High-Volume SMB Scans:** The overwhelming traffic to port 445 from a single IP (`122.121.74.82`) suggests a large-scale, automated SMB vulnerability scanning campaign.
- **SSH Key Manipulation:** A common pattern observed in the Cowrie honeypot was a series of commands designed to delete existing SSH configurations and insert a new public key, granting the attacker persistent access.
- **Outdated CVEs:** The CVEs triggered are quite old, indicating that attackers are still actively scanning for and attempting to exploit legacy vulnerabilities that may exist in unpatched systems.
- **Downloader and Botnet Activity:** The attempted download of files like `arm.urbotnetisass` points to efforts to enlist the compromised machine into a botnet. The variety of architectures targeted (ARM, x86, MIPS) is typical of IoT botnet malware.
