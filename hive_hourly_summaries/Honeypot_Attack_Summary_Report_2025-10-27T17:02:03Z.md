Here is the Honeypot Attack Summary Report.

**Report Generation Time:** 2025-10-27T17:01:30Z
**Timeframe:** 2025-10-27T16:20:01Z to 2025-10-27T17:00:01Z
**Files Used:**
- agg_log_20251027T162001Z.json
- agg_log_20251027T164001Z.json
- agg_log_20251027T170001Z.json

**Executive Summary**
This report summarizes 12,957 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most frequent attacks originated from IP address 185.68.247.151. Attackers primarily targeted port 5060, which is commonly used for SIP (Session Initiation Protocol) traffic. A variety of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted to gain access using a range of default and weak credentials and executed commands aimed at reconnaissance and establishing further access.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 4161
- Honeytrap: 2357
- Suricata: 1861
- Ciscoasa: 1802
- Sentrypeer: 1161
- Dionaea: 142
- Adbhoney: 84
- Mailoney: 107
- Redishoneypot: 73
- Tanner: 59
- H0neytr4p: 36
- Honeyaml: 7
- ElasticPot: 3
- ConPot: 2
- Ipphoney: 2

***Top Attacking IPs***
- 185.68.247.151: 1249
- 144.172.108.231: 1130
- 45.8.17.76: 509
- 85.208.84.168: 369
- 128.199.45.217: 293
- 107.170.36.5: 252
- 103.59.95.213: 194
- 103.181.143.232: 189
- 103.28.57.98: 183
- 121.229.9.110: 171

***Top Targeted Ports/Protocols***
- 5060: 1161
- 22: 718
- 5038: 509
- 5901: 276
- 12125: 200
- TCP/5900: 195
- TCP/22: 140
- 6379: 68
- 6666: 93
- 55577: 88

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2001-0414: 1
- CVE-1999-0183: 1
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2005-4050: 1

***Commands Attempted by Attackers***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `uname -a`
- `whoami`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...`

***Signatures Triggered***
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 411
- ET DROP Dshield Block Listed Source group 1: 287
- ET HUNTING RDP Authentication Bypass Attempt: 187
- ET SCAN NMAP -sS window 1024: 176
- ET SCAN Potential SSH Scan: 76
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 111
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 92
- ET INFO Reserved Internal IP Traffic: 57

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 7
- root/IvixcoMDunkel1!: 4
- root/iw123net: 4
- root/IWDLzxXc: 4
- root/IWTFaTpnow-2013: 4
- root/Iy8d26Izi8: 4
- root/iYrtR64b: 4
- user/yueme@123!!: 3
- user/yueme2022!!!: 3
- user/yqwang: 3

***Files Uploaded/Downloaded***
- wget.sh;: 28
- w.sh;: 7
- c.sh;: 7
- arm.uhavenobotsxd;: 3
- arm.uhavenobotsxd: 3
- arm5.uhavenobotsxd;: 3
- arm5.uhavenobotsxd: 3
- arm6.uhavenobotsxd;: 3
- arm6.uhavenobotsxd: 3
- arm7.uhavenobotsxd;: 3

***HTTP User-Agents***
- No user agents were logged in this period.

***SSH Clients***
- No SSH clients were logged in this period.

***SSH Servers***
- No SSH servers were logged in this period.

***Top Attacker AS Organizations***
- No AS organizations were logged in this period.

**Key Observations and Anomalies**
- The significant number of attacks on port 5060 suggests a coordinated effort to exploit vulnerabilities in VoIP systems.
- The commands executed by attackers indicate a clear pattern of attempting to establish persistent access by adding SSH keys and downloading additional malware.
- The presence of commands related to downloading and executing shell scripts and ARM/x86 binaries from specific IPs (e.g., 213.209.143.62, 94.154.35.154) points to automated botnet activity.
- The variety of CVEs, though low in number, indicates that attackers are probing for a range of known vulnerabilities.
- The high volume of login attempts with weak or default credentials highlights the ongoing threat of brute-force attacks.
