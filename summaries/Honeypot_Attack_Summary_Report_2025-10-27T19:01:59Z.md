Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T19:01:29Z
**Timeframe:** 2025-10-27T18:20:02Z - 2025-10-27T19:00:01Z
**Files Used:**
- agg_log_20251027T182002Z.json
- agg_log_20251027T184001Z.json
- agg_log_20251027T190001Z.json

**Executive Summary**

This report summarizes honeypot activity over the last hour, based on three log files. A total of 24,063 attacks were recorded. The most targeted honeypots were Honeytrap, Cowrie, and Suricata. The top attacking IP address was 77.83.240.70, responsible for a significant number of attacks. The most frequently targeted port was TCP/445, indicating a high volume of SMB-related probes. A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

**Detailed Analysis**

***Attacks by Honeypot***
- Honeytrap: 7790
- Cowrie: 8086
- Suricata: 4923
- Ciscoasa: 1720
- Sentrypeer: 1136
- Mailoney: 124
- Dionaea: 90
- Redishoneypot: 37
- Tanner: 28
- ConPot: 21
- Miniprint: 21
- Dicompot: 19
- Honeyaml: 19
- H0neytr4p: 19
- Adbhoney: 14
- ElasticPot: 10
- Ipphoney: 3
- Heralding: 3

***Top Attacking IPs***
- 77.83.240.70: 4822
- 196.1.184.18: 1568
- 114.31.29.186: 1419
- 144.172.108.231: 988
- 128.199.45.217: 546
- 64.227.174.243: 320
- 78.47.43.175: 255
- 51.158.120.121: 262
- 102.88.137.213: 202
- 190.181.44.194: 304
- 89.213.45.131: 181
- 83.229.122.23: 176
- 116.73.240.74: 172
- 191.96.225.225: 164
- 157.230.53.170: 227

***Top Targeted Ports/Protocols***
- TCP/445: 2979
- 22: 1013
- 5060: 1136
- 5901: 129
- 5903: 120
- 25: 124
- TCP/22: 110
- 8333: 73
- 5905: 69
- 5904: 69
- 6379: 52
- 9000: 50
- 5908: 44
- 5909: 45
- 5907: 52
- 5902: 41
- 2078: 117
- 15671: 34
- 9100: 18

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2005-4050: 1
- CVE-2016-6563: 1
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 1

***Commands Attempted by Attackers***
- cat /proc/cpuinfo | grep name | wc -l: 54
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 54
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 54
- ls -lh $(which ls): 54
- which ls: 54
- crontab -l: 54
- w: 54
- uname -m: 54
- cat /proc/cpuinfo | grep model | grep name | wc -l: 54
- top: 54
- uname: 54
- uname -a: 54
- whoami: 54
- lscpu | grep Model: 54
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 54
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 54
- lockr -ia .ssh: 54
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 54
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 31
- Enter new UNIX password: : 23

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2974
- 2024766: 2974
- ET DROP Dshield Block Listed Source group 1: 454
- 2402000: 454
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 261
- 2023753: 261
- ET SCAN NMAP -sS window 1024: 177
- 2009582: 177
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 114
- 2400041: 114
- ET HUNTING RDP Authentication Bypass Attempt: 90
- 2034857: 90
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 89
- 2400040: 89
- ET INFO Reserved Internal IP Traffic: 54
- 2002752: 54
- ET SCAN Potential SSH Scan: 40
- 2001219: 40
- ET COMPROMISED Known Compromised or Hostile Host Traffic group 10: 22
- 2500018: 22

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 51
- root/3245gs5662d34: 28
- Enter new UNIX password: : 23
- mehdi/mehdi: 3
- dst/123456789: 3
- wy/wy: 3
- root/qw12: 3
- testuser/password123: 3
- root/aa123123.: 3
- deploy2/deploy2: 3
- root/!12345678: 3
- test12/test: 3
- denis/12345: 3
- root/weiwei123: 3
- polls/polls: 3

***Files Uploaded/Downloaded***
- GetDeviceSettings: 5
- XMLSchema-instance: 5
- XMLSchema: 5
- HNAP1: 5
- proxy.sh: 5
- perl|perl: 1
- arm.uhavenobotsxd;: 2
- arm.uhavenobotsxd: 2
- arm5.uhavenobotsxd;: 2
- arm5.uhavenobotsxd: 2
- arm6.uhavenobotsxd;: 2
- arm6.uhavenobotsxd: 2
- arm7.uhavenobotsxd;: 2
- arm7.uhavenobotsxd: 2
- x86_32.uhavenobotsxd;: 2
- x86_32.uhavenobotsxd: 2
- mips.uhavenobotsxd;: 2
- mips.uhavenobotsxd: 2
- mipsel.uhavenobotsxd;: 2
- mipsel.uhavenobotsxd: 2

***HTTP User-Agents***
- No user agents recorded in this timeframe.

***SSH Clients***
- No SSH clients recorded in this timeframe.

***SSH Servers***
- No SSH servers recorded in this timeframe.

***Top Attacker AS Organizations***
- No AS organizations recorded in this timeframe.

**Key Observations and Anomalies**

- A large number of attacks from the IP 77.83.240.70 were observed, almost entirely targeting the Honeytrap honeypot.
- The high number of attacks on port TCP/445 suggests a widespread campaign targeting the SMB protocol, likely related to vulnerabilities like EternalBlue.
- Attackers are using a consistent set of commands for reconnaissance and to modify the system's security (e.g., changing SSH keys, clearing logs).
- The "DoublePulsar Backdoor installation" signature was triggered a significant number of times, indicating that attackers are attempting to install this known backdoor.
- A long and complex command was observed, attempting to download and execute multiple malicious binaries for different architectures (ARM, x86, MIPS). This is indicative of a sophisticated, cross-platform attack.
- The majority of login attempts use common or default credentials, highlighting the ongoing threat of brute-force attacks.
