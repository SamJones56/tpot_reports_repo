Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T13:01:30Z
**Timeframe:** 2025-10-27T12:20:01Z to 2025-10-27T13:00:01Z
**Files Used:**
- agg_log_20251027T122001Z.json
- agg_log_20251027T124001Z.json
- agg_log_20251027T130001Z.json

### Executive Summary
This report summarizes 22,615 events collected from the T-Pot honeypot network over a period of 40 minutes. The majority of attacks were captured by the Honeytrap, Suricata, and Cowrie honeypots. A significant portion of the traffic was directed at TCP/445 and port 5038. The most prominent attack signatures indicate continued exploitation of the DoublePulsar backdoor and SIP vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 8524
- Suricata: 4915
- Cowrie: 4362
- Sentrypeer: 2081
- Ciscoasa: 1751
- Dionaea: 687
- Mailoney: 94
- H0neytr4p: 64
- Adbhoney: 52
- Redishoneypot: 36
- Dicompot: 11
- Tanner: 10
- ConPot: 6
- Miniprint: 6
- Honeyaml: 5
- Heralding: 3
- Ipphoney: 3
- ElasticPot: 2
- ssh-rsa: 2
- Wordpot: 1

**Top Attacking IPs:**
- 45.8.17.76: 2938
- 198.23.190.58: 2118
- 180.148.4.38: 1597
- 47.236.13.75: 1244
- 95.67.205.232: 1047
- 45.140.17.144: 926
- 45.134.26.62: 921
- 45.140.17.153: 909
- 58.186.217.58: 617
- 144.172.108.231: 554

**Top Targeted Ports/Protocols:**
- 5038: 2937
- TCP/445: 2645
- 5060: 2081
- 22: 780
- UDP/5060: 724
- 445: 632

**Most Common CVEs:**
- CVE-2005-4050: 706
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2018-11776: 1
- CVE-2023-48022 CVE-2023-48022: 1

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk ...`
- `free -m | grep Mem | awk ...`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `whoami`
- `df -h | head -n 2 | awk ...`
- `lscpu | grep Model`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2637
- 2024766: 2637
- ET VOIP MultiTech SIP UDP Overflow: 706
- 2003237: 706
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 342
- 2023753: 342
- ET DROP Dshield Block Listed Source group 1: 205
- 2402000: 205
- ET SCAN NMAP -sS window 1024: 166
- 2009582: 166
- ET HUNTING RDP Authentication Bypass Attempt: 150
- 2034857: 150
- ET INFO Reserved Internal IP Traffic: 54
- 2002752: 54

**Users / Login Attempts:**
- `345gs5662d34/345gs5662d34`
- `systemd/Voidsetdownload.so`
- `root/Iptech2014`
- `root/Iptech20A3`
- `root/is2burl4nd0`
- `root/isa02lwi4`
- `root/iptsp`
- `jla/xurros22$`

**Files Uploaded/Downloaded:**
- `wget.sh;`
- `w.sh;`
- `c.sh;`
- `arm.uhavenobotsxd;`
- `arm.uhavenobotsxd`
- `arm5.uhavenobotsxd;`
- `arm5.uhavenobotsxd`
- `arm6.uhavenobotsxd;`
- `arm6.uhavenobotsxd`
- `arm7.uhavenobotsxd;`
- `arm7.uhavenobotsxd`
- `x86_32.uhavenobotsxd;`
- `x86_32.uhavenobotsxd`
- `mips.uhavenobotsxd;`
- `mips.uhavenobotsxd`
- `mipsel.uhavenobotsxd;`
- `mipsel.uhavenobotsxd`
- `arm.urbotnetisass;`
- `arm.urbotnetisass`
- `?format=json`

**HTTP User-Agents:**
- No user agents were logged in this period.

**SSH Clients and Servers:**
- No SSH clients or servers were logged in this period.

**Top Attacker AS Organizations:**
- No AS organizations were logged in this period.

### Key Observations and Anomalies
- The high number of events targeting TCP/445, coupled with the DoublePulsar signature, suggests a continued focus on exploiting SMB vulnerabilities.
- A significant number of brute-force attempts were observed against SSH and other services, with a wide variety of usernames and passwords being tested.
- Attackers were observed attempting to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`), indicating attempts to install malware or establish persistence.
- The variety of architectures targeted by the downloaded binaries (arm, x86, mips) suggests that attackers are attempting to compromise a wide range of IoT and embedded devices.
- The command `cd ~ && rm -rf .ssh && ...` is a clear attempt to compromise SSH security by replacing the `authorized_keys` file.
