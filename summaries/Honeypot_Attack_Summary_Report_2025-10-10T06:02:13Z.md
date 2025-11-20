Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T06:01:31Z
**Timeframe:** 2025-10-10T05:20:01Z to 2025-10-10T06:00:01Z
**Files Used:**
- agg_log_20251010T052001Z.json
- agg_log_20251010T054001Z.json
- agg_log_20251010T060001Z.json

### Executive Summary
This report summarizes 22,257 events captured by the honeypot network over a 40-minute period. The majority of attacks were SSH brute-force attempts and scans for common vulnerabilities. The most active honeypots were Cowrie, Suricata, and Honeytrap. The top attacking IP address was 38.210.85.130, and the most targeted port was TCP/445 (SMB). Several CVEs were targeted, with a focus on older vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8,444
- Suricata: 5,070
- Honeytrap: 4,158
- Ciscoasa: 2,192
- Dionaea: 976
- Sentrypeer: 816
- H0neytr4p: 391
- Tanner: 74
- Miniprint: 32
- ElasticPot: 22
- Honeyaml: 22
- Mailoney: 22
- Adbhoney: 18
- Redishoneypot: 15
- Ipphoney: 3
- ssh-rsa: 2

**Top Attacking IPs:**
- 38.210.85.130
- 167.250.224.25
- 31.40.204.154
- 152.136.142.14
- 177.12.16.118
- 193.24.123.88
- 196.251.80.27
- 14.103.230.55
- 45.134.26.3
- 103.218.240.181
- 88.210.63.16

**Top Targeted Ports/Protocols:**
- TCP/445
- 22
- 5060
- 445
- TCP/8080
- 443
- TCP/8443
- 1433
- TCP/443
- 5903

**Most Common CVEs:**
- CVE-1999-0183
- CVE-1999-0517
- CVE-2002-0012
- CVE-2002-0013
- CVE-2002-0953
- CVE-2005-4050
- CVE-2019-11500
- CVE-2021-35394

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Incoming Basic Auth Base64 HTTP Password detected unencrypted
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- GPL INFO SOCKS Proxy attempt
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 93
- ET TOR Known Tor Exit Node Traffic group 93
- ET SCAN Potential SSH Scan

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/147147
- tmadmin/tmadmin
- support/support1234
- supervisor/pass
- guest/guest0
- ubuntu/3245gs5662d34
- admin/admin123
- root/asd123456!
- root/centos
- root/asd123456.
- root/asd@123456
- root/asd!123456
- support/passwor
- root/asd.123456
- root/@asd123456
- root/!asd123456
- root/.asd123456
- root/asd2025
- root/asd2025@

**Files Uploaded/Downloaded:**
- config.all.php?x
- config.all.php?
- wget.sh;
- Xiii.php?yokyok=cat+Xiii.php&
- cmd.txt
- rondo.kqa.sh|sh&echo
- Ultimatex.php?d111ae3c7c9bd50=id...
- vivovivow.php?dwxw=cat+vivovivow.php&
- index.php?pal=cat+index.php&
- .4f9dac240e7d3f8bf7a99d73d8db4a82.php?X
- phpversions.php?npv
- index.php?p=eNA@Salem@jAjXnEYSxX@Salem@ZarAbadrERfBadrjag&c=id...
- config.php?
- boatnet.mips
- w.sh;
- c.sh;

**HTTP User-Agents:**
- None observed in this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions were logged in this period.

**Top Attacker AS Organizations:**
- No specific AS organizations were logged in this period.

### Key Observations and Anomalies
- A high number of attacks originated from the IP address 38.210.85.130, primarily targeting SMB services.
- The most common commands attempted by attackers involve reconnaissance of the system's hardware and attempts to modify SSH authorized_keys.
- The DoublePulsar backdoor was a commonly triggered signature, indicating attempts to exploit SMB vulnerabilities.
- There is a noticeable trend of attackers using a series of commands to gather system information before attempting to deploy malware.
- The variety of login credentials used suggests dictionary-based brute-force attacks are prevalent.
- Several PHP files were uploaded or downloaded, indicating attempts to exploit web vulnerabilities.
