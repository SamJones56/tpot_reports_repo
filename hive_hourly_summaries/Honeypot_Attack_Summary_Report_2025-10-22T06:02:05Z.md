## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T06:01:24Z
**Timeframe:** 2025-10-22T05:20:01Z to 2025-10-22T06:00:01Z
**Files Used:**
*   agg_log_20251022T052001Z.json
*   agg_log_20251022T054001Z.json
*   agg_log_20251022T060001Z.json

### Executive Summary
This report summarizes 29,593 events recorded across multiple honeypots. The most targeted services were VNC (port 5900) and SMB (port 445). A significant number of attacks originated from the IP addresses 185.243.96.105 and 111.175.37.46, with a high volume of VNC authentication failures. The Cowrie honeypot recorded the highest number of interactions, primarily SSH brute-force attempts and subsequent command execution. Several attackers attempted to add their SSH keys to the authorized_keys file for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 8,909
*   Suricata: 8,527
*   Heralding: 5,168
*   Honeytrap: 3,827
*   Ciscoasa: 1,531
*   Dionaea: 935
*   Sentrypeer: 339
*   Mailoney: 132
*   Tanner: 53
*   ElasticPot: 52
*   H0neytr4p: 51
*   ConPot: 27
*   Redishoneypot: 18
*   Miniprint: 9
*   Adbhoney: 9
*   Dicompot: 4
*   Honeyaml: 2

**Top Attacking IPs:**
*   185.243.96.105: 4,957
*   10.208.0.3: 4,957
*   111.175.37.46: 4,885
*   221.121.100.32: 731
*   94.79.7.120: 1361
*   88.210.63.16: 292
*   166.140.87.173: 297
*   129.213.226.156: 296
*   190.0.247.83: 268
*   107.170.36.5: 236
*   182.117.144.122: 201
*   112.196.70.142: 302
*   103.193.178.68: 213
*   35.189.200.233: 294
*   198.23.190.58: 205
*   34.77.105.225: 128
*   20.102.116.25: 193
*   5.195.226.17: 194
*   45.157.149.27: 119
*   186.7.30.18: 134

**Top Targeted Ports/Protocols:**
*   vnc/5900: 4,956
*   TCP/445: 2,108
*   22: 1,553
*   5060: 339
*   5903: 208
*   TCP/1433: 120
*   25: 132
*   1433: 108
*   8333: 96
*   5901: 104
*   TCP/1080: 211
*   socks5/1080: 209
*   UDP/5060: 105
*   3388: 78
*   9200: 40
*   23: 54
*   80: 50
*   443: 37

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2012-3152
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2002-1149

**Commands Attempted by Attackers:**
*   `uname -a`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `crontab -l`
*   `w`
*   `whoami`
*   `tftp; wget; /bin/busybox XQQQI`
*   `chmod +x ./.4511380047740896953/sshd;nohup ./.4511380047740896953/sshd ...`

**Signatures Triggered:**
*   ET INFO VNC Authentication Failure
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET SCAN Suspicious inbound to MSSQL port 1433
*   ET INFO Reserved Internal IP Traffic
*   GPL INFO SOCKS Proxy attempt
*   ET SCAN Sipsak SIP scan

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   /Passw0rd
*   /1q2w3e4r
*   root/bascara10
*   /1qaz2wsx
*   /passw0rd
*   /qwertyui
*   odin/odin
*   root/Bayram2013
*   root/Bba72445

**Files Uploaded/Downloaded:**
*   wget.sh;
*   w.sh;
*   c.sh;
*   11
*   fonts.gstatic.com
*   css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3

**HTTP User-Agents:**
*   None observed.

**SSH Clients and Servers:**
*   None observed.

**Top Attacker AS Organizations:**
*   None observed.

### Key Observations and Anomalies
*   The high number of VNC authentication failures from a small number of IPs suggests a targeted brute-force attack on VNC servers.
*   The repeated attempts to modify the `.ssh/authorized_keys` file indicate a common tactic to gain persistent access to compromised systems.
*   The command `chmod +x ./.4511380047740896953/sshd;nohup ...` is a clear attempt to install a malicious SSH daemon.
*   The presence of `tftp` and `wget` in commands suggests attempts to download additional malware.
*   The variety of honeypots that were triggered demonstrates a broad spectrum of automated attacks targeting different services.
