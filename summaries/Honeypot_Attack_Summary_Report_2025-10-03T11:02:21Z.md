Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T11:01:29Z
**Timeframe:** 2025-10-03T10:20:01Z to 2025-10-03T11:00:01Z
**Files Used:**
- agg_log_20251003T102001Z.json
- agg_log_20251003T104001Z.json
- agg_log_20251003T110001Z.json

**Executive Summary:**
This report summarizes 14,065 attacks recorded by the honeypot network. The most targeted honeypot was Cowrie, a medium and high interaction SSH and Telnet honeypot. The most frequent attacker IP was 176.65.141.117. The most targeted port was 5060/UDP (SentryPeer). A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistence.

**Detailed Analysis:**

*   **Attacks by Honeypot:**
    *   Cowrie: 4276
    *   Ciscoasa: 2720
    *   Suricata: 2429
    *   Sentrypeer: 1806
    *   Mailoney: 1658
    *   Dionaea: 923
    *   Honeytrap: 112
    *   Tanner: 34
    *   Adbhoney: 33
    *   H0neytr4p: 28
    *   Redishoneypot: 18
    *   Honeyaml: 14
    *   ConPot: 9
    *   Dicompot: 3
    *   Miniprint: 2

*   **Top Attacking IPs:**
    *   176.65.141.117: 1640
    *   23.94.26.58: 1465
    *   196.203.170.42: 1330
    *   202.61.42.8: 482
    *   103.178.76.33: 392
    *   185.156.73.166: 382
    *   92.63.197.55: 364
    *   103.174.114.164: 331
    *   92.63.197.59: 326
    *   159.223.37.230: 419
    *   201.71.235.30: 414
    *   103.55.36.22: 227
    *   158.51.124.56: 271
    *   143.198.195.7: 232
    *   185.245.83.140: 147
    *   164.92.236.103: 124
    *   187.49.152.12: 161
    *   91.186.213.0: 212
    *   152.53.192.25: 178
    *   46.105.87.113: 183

*   **Top Targeted Ports/Protocols:**
    *   5060: 1806
    *   25: 1658
    *   TCP/445: 1328
    *   445: 885
    *   22: 558
    *   TCP/80: 70
    *   80: 36
    *   TCP/22: 40
    *   TCP/8080: 24
    *   6379: 18
    *   443: 28
    *   23: 36

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2021-3449 CVE-2021-3449
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
    *   CVE-2019-11500 CVE-2019-11500
    *   CVE-2016-20016 CVE-2016-20016

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 30
    *   `lockr -ia .ssh`: 30
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 30
    *   `uname -m`: 26
    *   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 26
    *   `top`: 26
    *   `uname`: 26
    *   `uname -a`: 26
    *   `whoami`: 26
    *   `lscpu | grep Model`: 26
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 26
    *   `cat /proc/cpuinfo | grep name | wc -l`: 26
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 26
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 25
    *   `ls -lh $(which ls)`: 25
    *   `which ls`: 25
    *   `crontab -l`: 25
    *   `w`: 25
    *   `Enter new UNIX password: `: 12
    *   `Enter new UNIX password:`: 9

*   **Signatures Triggered:**
    *   `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`: 1324
    *   `2024766`: 1324
    *   `ET DROP Dshield Block Listed Source group 1`: 275
    *   `2402000`: 275
    *   `ET SCAN NMAP -sS window 1024`: 178
    *   `2009582`: 178
    *   `ET INFO Reserved Internal IP Traffic`: 55
    *   `2002752`: 55
    *   `ET SCAN Potential SSH Scan`: 23
    *   `2001219`: 23
    *   `ET CINS Active Threat Intelligence Poor Reputation IP group 43`: 15
    *   `2403342`: 15
    *   `ET CINS Active Threat Intelligence Poor Reputation IP group 45`: 14
    *   `2403344`: 14
    *   `ET INFO curl User-Agent Outbound`: 18
    *   `2013028`: 18
    *   `ET HUNTING curl User-Agent to Dotted Quad`: 18
    *   `2034567`: 18
    *   `ET INFO Proxy CONNECT Request`: 12
    *   `2001675`: 12
    *   `ET DROP Spamhaus DROP Listed Traffic Inbound group 32`: 22
    *   `2400031`: 22
    *   `GPL INFO SOCKS Proxy attempt`: 13
    *   `2100615`: 13

*   **Users / Login Attempts:**
    *   `345gs5662d34/345gs5662d34`: 28
    *   `root/3245gs5662d34`: 17
    *   `root/nPSpP4PBW0`: 12
    *   `root/2glehe5t24th1issZs`: 9
    *   `root/LeitboGi0ro`: 9
    *   `superadmin/admin123`: 7
    *   `seekcy/Joysuch@Locate2021`: 4
    *   `test/zhbjETuyMffoL8F`: 5
    *   `foundry/foundry`: 5
    *   `test/3245gs5662d34`: 4

*   **Files Uploaded/Downloaded:**
    *   `wget.sh;`: 16
    *   `w.sh;`: 4
    *   `c.sh;`: 4
    *   `11`: 7
    *   `fonts.gstatic.com`: 7
    *   `css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&subset=latin%2Clatin-ext`: 7
    *   `ie8.css?ver=1.0`: 7
    *   `html5.js?ver=3.7.3`: 7

*   **HTTP User-Agents:** (No data in logs)

*   **SSH Clients:** (No data in logs)

*   **SSH Servers:** (No data in logs)

*   **Top Attacker AS Organizations:** (No data in logs)

**Key Observations and Anomalies:**
- The high number of attacks on Cowrie (SSH/Telnet) and the commands attempted suggest a focus on compromising IoT devices and servers for botnets.
- The `mdrfckr` SSH key is a known indicator of compromise.
- The commands also show attempts to gather system information (`uname`, `lscpu`, `free`, `df`).
- The DoublePulsar backdoor signature was triggered a significant number of times, indicating attempts to exploit the SMB vulnerability.
- There is a lot of scanning activity, particularly from Dshield block listed sources.
