Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T00:01:44Z

**Timeframe:** This report summarizes data from logs generated between 2025-10-17T23:20:01Z and 2025-10-18T00:00:01Z.

**Files Used:**
- `agg_log_20251017T232001Z.json`
- `agg_log_20251017T234001Z.json`
- `agg_log_20251018T000001Z.json`

**Executive Summary**

This report provides a consolidated summary of malicious activities recorded by our honeypot network. A total of 9,817 attacks were observed during the reporting period. The most targeted services were SSH (port 22) and SIP (port 5060). The `Cowrie` and `Honeytrap` honeypots recorded the highest number of interactions. A significant number of attacks originated from the IP address `72.146.232.13`. Attackers were observed attempting to gain access using default or weak credentials and executing commands to gather system information and manipulate SSH authorized keys.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 3435
- Honeytrap: 2766
- Ciscoasa: 1427
- Suricata: 1407
- Sentrypeer: 428
- Dionaea: 118
- Mailoney: 66
- H0neytr4p: 49
- Tanner: 43
- Redishoneypot: 18
- ElasticPot: 18
- Adbhoney: 18
- Miniprint: 9
- ConPot: 9
- Dicompot: 3
- Ipphoney: 2
- Honeyaml: 1

**Top Attacking IPs:**
- 72.146.232.13: 918
- 88.210.63.16: 341
- 20.255.62.58: 282
- 107.170.36.5: 249
- 116.193.191.46: 241
- 119.92.70.82: 243
- 198.12.68.114: 206
- 143.198.76.169: 198
- 115.190.77.17: 194
- 182.57.16.58: 189
- 200.13.244.219: 125
- 68.183.149.135: 111
- 43.252.231.122: 105
- 68.183.207.213: 94
- 159.89.121.144: 94
- 107.150.102.23: 84
- 167.250.224.25: 60
- 94.103.188.88: 57
- 141.52.36.57: 50
- 152.42.192.111: 48

**Top Targeted Ports/Protocols:**
- 22: 672
- 5060: 428
- 5903: 227
- 8333: 128
- 5901: 118
- 1969: 113
- UDP/5060: 87
- 5905: 77
- 5904: 76
- 25: 70
- TCP/80: 57
- 27017: 48
- 443: 47
- 445: 41
- 80: 38

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2023-26801 CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920 CVE-2019-16920
- CVE-2023-31983 CVE-2023-31983
- CVE-2020-10987 CVE-2020-10987
- CVE-2023-47565 CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
- CVE-2025-57819 CVE-2025-57819
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885

**Commands Attempted by Attackers:**
- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET SCAN Sipsak SIP scan
- 2008598
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET INFO CURL User Agent
- 2002824
- ET CINS Active Threat Intelligence Poor Reputation IP group 13
- 2403312

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- config/111111
- guest/11
- unknown/44
- support/99
- root/root2005
- config/config2014
- debian/121212
- unknown/unknown2018
- root/qwerty12345
- user/qwerty123456
- root/1Ictadmin
- qwe123/123
- root/1keeper123
- root/1master!
- root/1ms0luc1on3s
- root/1n5p1r0n.
- root/1n73n3gpass2kX

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=
- rondo.qre.sh||busybox
- rondo.qre.sh||curl
- rondo.qre.sh)|sh
- \`busybox
- 129.212.146.61:8088
- apply.cgi
- rondo.sbx.sh|sh&echo${IFS}
- login_pic.asp

**HTTP User-Agents:**
- No user-agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were identified in this period.

**Key Observations and Anomalies**

- A recurring pattern was observed where attackers, after gaining initial access, attempted to modify the `.ssh/authorized_keys` file. This is a common technique to establish persistent access. The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && ...` was frequently used.
- The high number of events on port 22 (SSH) and 5060 (SIP) suggests that these services are currently the most targeted by automated attacks.
- A wide variety of usernames and passwords were used in brute-force attempts, ranging from common defaults to more complex combinations. This highlights the importance of using strong, unique passwords.
- The presence of commands like `tftp; wget; /bin/busybox LSPJG` and attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) indicate attempts to download and run malicious payloads.
- The variety of CVEs seen in the logs indicates that attackers are attempting to exploit a range of vulnerabilities, some of which are quite old. This underscores the need for timely patching and vulnerability management.
