Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T11:01:46Z
**Timeframe of Analysis:** 2025-10-15T10:20:01Z to 2025-10-15T11:00:02Z
**Log Files Analyzed:**
- agg_log_20251015T102001Z.json
- agg_log_20251015T104001Z.json
- agg_log_20251015T110002Z.json

### Executive Summary
This report summarizes 28,991 events collected from the T-Pot honeypot network. The majority of attacks were detected by the Suricata, Heralding, and Cowrie honeypots. The most prominent attacker IP was 45.134.26.47, with a focus on vnc/5900. A number of CVEs were observed, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access via SSH.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 6789
- Heralding: 6718
- Cowrie: 4951
- Honeytrap: 3649
- Sentrypeer: 3237
- Ciscoasa: 1633
- Dionaea: 869
- Mailoney: 897
- Adbhoney: 58
- Tanner: 74
- H0neytr4p: 80
- Honeyaml: 15
- ElasticPot: 8
- Redishoneypot: 6
- ConPot: 3
- Miniprint: 2
- Ipphoney: 2

**Top Attacking IPs:**
- 45.134.26.47: 6720
- 10.17.0.5: 2830
- 185.243.5.121: 1879
- 41.111.206.189: 1526
- 206.191.154.180: 1329
- 10.140.0.3: 1069
- 86.54.42.238: 822
- 193.24.123.88: 498
- 172.86.95.115: 480
- 172.86.95.98: 442
- 62.141.43.183: 316
- 158.51.124.56: 377
- 36.108.172.220: 264
- 116.249.226.18: 267
- 14.103.63.16: 137
- 103.172.204.83: 154
- 212.34.140.18: 150
- 106.215.82.134: 260
- 146.59.55.84: 199
- 198.50.248.192: 134

**Top Targeted Ports/Protocols:**
- vnc/5900: 6718
- 5060: 3237
- TCP/445: 1524
- 22: 737
- 25: 897
- 1433: 499
- 445: 319
- 23: 120
- 8333: 169
- 5903: 185
- 5908: 81
- 5909: 80
- 5901: 74
- 443: 76
- UDP/5060: 83
- TCP/22: 91
- 80: 80
- 5907: 49

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2006-2369: 2

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 20
- `lockr -ia .ssh`: 17
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 21
- `cat /proc/cpuinfo | grep name | wc -l`: 21
- `Enter new UNIX password: `: 19
- `Enter new UNIX password:`: 19
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 21
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 21
- `ls -lh $(which ls)`: 21
- `which ls`: 21
- `crontab -l`: 21
- `w`: 21
- `uname -m`: 21
- `uname -a`: 21
- `whoami`: 21
- `lscpu | grep Model`: 21
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 21
- `top`: 20
- `uname`: 20
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 20
- `shell`: 4

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 18
- root/123@@@: 17
- root/Password@2025: 14
- root/Qaz123qaz: 12
- admin/55555: 6
- centos/777777: 4
- user/9999: 4
- root/carito4500: 4
- root/622B2C79D1: 4
- supervisor/supervisor2012: 4
- builduser/qwerty123: 3
- nobody/test: 6
- config/config2018: 6
- ftpuser/ftppassword: 7
- nobody/nobody2010: 4
- user/666666: 6
- user/123321: 4
- guest/8888: 4
- root/69489a31e3c0: 4

**Files Uploaded/Downloaded:**
- sh: 6
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- 11: 5
- fonts.gstatic.com: 5
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 5
- ie8.css?ver=1.0: 5
- html5.js?ver=3.7.3: 5

**Signatures Triggered:**
- ET INFO VNC Authentication Failure: 3910
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1519
- ET DROP Dshield Block Listed Source group 1: 439
- ET SCAN NMAP -sS window 1024: 144
- ET SCAN Potential SSH Scan: 69
- ET INFO Reserved Internal IP Traffic: 57
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 43
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 41
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 35
- GPL TELNET Bad Login: 60
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 16
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 7
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 7

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies
- The high volume of VNC authentication failures suggests a widespread scanning or brute-force campaign targeting this service.
- The commands executed by attackers indicate a clear pattern of reconnaissance to identify the system's architecture and resources, followed by attempts to install a persistent SSH key.
- The presence of the "mdrfckr" comment in the authorized_keys file is a recurring signature.
- A significant number of attacks originate from a single IP address, 45.134.26.47, which should be prioritized for blocking and further investigation.
- The variety of credentials used in login attempts suggests the use of common password lists.
- The download of various shell scripts (`w.sh`, `c.sh`, `wget.sh`) from the same IP (72.60.107.93) in the "interesting" commands indicates a multi-stage attack framework.

This concludes the Honeypot Attack Summary Report.