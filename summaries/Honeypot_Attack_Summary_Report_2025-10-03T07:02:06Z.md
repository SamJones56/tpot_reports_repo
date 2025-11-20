Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T07:01:29Z
**Timeframe:** 2025-10-03T06:20:01Z to 2025-10-03T07:00:01Z
**Files Used:**
- agg_log_20251003T062001Z.json
- agg_log_20251003T064001Z.json
- agg_log_20251003T070001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 15,937 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and Cisco ASA (Ciscoasa). The majority of attacks originated from a diverse set of IP addresses, with significant activity from `8.210.108.254`, `23.175.48.211`, and `34.47.232.78`. Attackers attempted to exploit several vulnerabilities, including CVE-2021-35394, CVE-2021-3449, CVE-2019-11500, and CVE-2002-0013. A variety of commands were executed, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 6947
- Ciscoasa: 2688
- Suricata: 2062
- Sentrypeer: 1568
- Mailoney: 849
- Dionaea: 723
- Honeytrap: 864
- Adbhoney: 39
- H0neytr4p: 41
- ConPot: 42
- Tanner: 34
- Honeyaml: 28
- Redishoneypot: 26
- Dicompot: 11
- Medpot: 4
- ElasticPot: 3
- Miniprint: 3
- Wordpot: 2
- Ipphoney: 3

**Top Attacking IPs:**
- 8.210.108.254: 1250
- 23.175.48.211: 1251
- 34.47.232.78: 1257
- 176.65.141.117: 820
- 101.95.153.214: 643
- 122.177.96.100: 359
- 175.176.23.37: 275
- 185.156.73.166: 362
- 92.63.197.55: 350
- 92.63.197.59: 311
- 107.189.29.175: 312
- 201.249.205.94: 222
- 196.188.116.41: 267
- 134.199.225.42: 196
- 14.103.112.105: 157
- 18.221.214.151: 129
- 68.183.93.67: 128
- 154.83.15.200: 194
- 147.93.189.166: 154
- 154.83.15.92: 195

**Top Targeted Ports/Protocols:**
- 5060: 1568
- 22: 1100
- 445: 652
- TCP/445: 694
- 25: 847
- TCP/22: 70
- 80: 44
- 443: 41
- TCP/443: 45
- 6379: 26
- 23: 49
- 2404: 23

**Most Common CVEs:**
- CVE-2021-35394
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `w`
- `uname -m`
- `crontab -l`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 67

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/3245gs5662d34
- superadmin/admin123
- root/2glehe5t24th1issZs
- foundry/foundry
- test/zhbjETuyMffoL8F
- wangke/wangke
- seekcy/Joysuch@Locate2022
- awx/awx123

**Files Uploaded/Downloaded:**
- mipsel.urbotnetisass;
- mips.urbotnetisass;
- ?format=json
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- (No data)

**SSH Clients and Servers:**
- (No data)

**Top Attacker AS Organizations:**
- (No data)

**Key Observations and Anomalies**

- A significant number of commands are related to manipulating the `.ssh/authorized_keys` file, indicating a clear intent to establish persistent SSH access.
- The high number of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor" signatures suggests attempts to compromise systems using this known backdoor.
- The variety of honeypots triggered indicates a broad spectrum of scanning and exploitation attempts against different services.
- The credentials attempted include a mix of default, weak, and more complex passwords, showing a range of brute-force techniques.
- The files downloaded appear to be related to botnet activity (`.urbotnetisass`).

This concludes the Honeypot Attack Summary Report. Further analysis of the source IPs and command patterns is recommended for proactive threat intelligence.
