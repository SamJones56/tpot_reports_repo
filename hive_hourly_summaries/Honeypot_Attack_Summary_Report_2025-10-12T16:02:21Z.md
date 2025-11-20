**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-12T16:01:44Z
**Timeframe:** 2025-10-12T15:20:02Z to 2025-10-12T16:00:01Z
**Files Used:** `agg_log_20251012T152002Z.json`, `agg_log_20251012T154001Z.json`, `agg_log_20251012T160001Z.json`

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 16,738 attacks were recorded. The most targeted services were SMB (port 445) and SIP (port 5060). The Dionaea and Cowrie honeypots recorded the highest number of interactions. A significant portion of the attacks originated from IP address `202.88.244.34`. Multiple CVEs were targeted, with `CVE-2005-4050` being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 4149
*   Dionaea: 3956
*   Sentrypeer: 2882
*   Honeytrap: 2109
*   Ciscoasa: 1772
*   Suricata: 1620
*   Mailoney: 92
*   Redishoneypot: 35
*   H0neytr4p: 30
*   Honeyaml: 28
*   Adbhoney: 18
*   Tanner: 19
*   ElasticPot: 12
*   Dicompot: 7
*   ConPot: 4
*   Ipphoney: 3
*   ssh-ed25519: 2

***Top Attacking IPs***

*   202.88.244.34: 3025
*   198.12.68.114: 1596
*   45.128.199.212: 1002
*   223.100.22.69: 816
*   94.126.59.114: 702
*   172.86.95.98: 346
*   62.141.43.183: 324
*   104.218.165.175: 259
*   71.168.162.91: 250
*   196.251.84.181: 225

***Top Targeted Ports/Protocols***

*   445: 3890
*   5060: 2882
*   22: 686
*   UDP/5060: 548
*   5903: 190
*   23: 87
*   25: 94
*   8333: 90
*   5909: 83
*   5908: 81

***Most Common CVEs***

*   CVE-2005-4050
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2001-0414
*   CVE-2016-20016 CVE-2016-20016

***Commands Attempted by Attackers***

*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
*   cat /proc/cpuinfo | grep name | wc -l
*   Enter new UNIX password:
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   cat /proc/cpuinfo | grep model | grep name | wc -l
*   top
*   uname
*   uname -a
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   Accept-Encoding: gzip
*   uname -s -v -n -r -m
*   echo -e "123456\\nhZW14gs1IOdX\\nhZW14gs1IOdX"|passwd|bash
*   echo "123456\\nhZW14gs1IOdX\\nhZW14gs1IOdX\\n"|passwd

***Signatures Triggered***

*   ET SCAN Sipsak SIP scan: 511
*   2008598: 511
*   ET DROP Dshield Block Listed Source group 1: 288
*   2402000: 288
*   ET SCAN NMAP -sS window 1024: 156
*   2009582: 156
*   ET INFO Reserved Internal IP Traffic: 59
*   2002752: 59
*   ET VOIP MultiTech SIP UDP Overflow: 27
*   2003237: 27
*   ET SCAN Potential SSH Scan: 33
*   2001219: 33
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 26
*   2023753: 26
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 25
*   2024766: 25
*   ET INFO CURL User Agent: 16
*   2002824: 16

***Users / Login Attempts***

*   cron/: 26
*   test/password1!: 6
*   345gs5662d34/345gs5662d34: 8
*   backuppc/backuppc: 8
*   Admin/P@ssw0rd: 6
*   Admin/0000: 6
*   x/x: 4
*   support/support11: 4
*   ubnt/qwerty123456: 4
*   root/1111111: 4
*   root/senha1: 4
*   user/77777: 4
*   user/passloe: 3

***Files Uploaded/Downloaded***

*   json: 2
*   wget.sh;: 4
*   w.sh;: 1
*   c.sh;: 1
*   soap-envelope: 1
*   addressing: 1
*   discovery: 1
*   devprof: 1
*   soap:Envelope>: 1
*   arm.urbotnetisass;: 1
*   arm.urbotnetisass: 1
*   arm5.urbotnetisass;: 1
*   arm5.urbotnetisass: 1
*   arm6.urbotnetisass;: 1
*   arm6.urbotnetisass: 1
*   arm7.urbotnetisass;: 1
*   arm7.urbotnetisass: 1
*   x86_32.urbotnetisass;: 1
*   x86_32.urbotnetisass: 1
*   mips.urbotnetisass;: 1
*   mips.urbotnetisass: 1


***HTTP User-Agents***

*   None observed.

***SSH Clients***

*   None observed.

***SSH Servers***

*   None observed.

***Top Attacker AS Organizations***

*   None observed.

**Key Observations and Anomalies**

*   The high number of attacks from `202.88.244.34` targeting port 445 suggests a targeted campaign against SMB services from this source.
*   The commands attempted indicate a clear pattern of post-exploitation activity, including reconnaissance of system hardware and attempts to modify SSH authorized keys for persistent access.
*   The variety of files downloaded, particularly the `*.urbotnetisass` files for different architectures, points to attempts to deploy a botnet client.

This concludes the Honeypot Attack Summary Report.