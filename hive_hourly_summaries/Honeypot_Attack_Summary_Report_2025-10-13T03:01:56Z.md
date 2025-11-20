Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T03:01:26Z
**Timeframe:** 2025-10-13T02:20:01Z to 2025-10-13T03:00:01Z

**Files Used:**
- agg_log_20251013T022001Z.json
- agg_log_20251013T024001Z.json
- agg_log_20251013T030001Z.json

**Executive Summary**

This report summarizes 18,574 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Honeytrap, Dionaea, and Cowrie honeypots. A significant portion of the attacks originated from the IP address 45.58.127.135. The most targeted port was 445/TCP (SMB), indicating widespread scanning for vulnerabilities like EternalBlue. Several CVEs were detected, with CVE-2005-4050 being the most common. Attackers were observed attempting to gain access via SSH and execute commands to gather system information and add their SSH keys to the authorized_keys file.

**Detailed Analysis**

***Attacks by honeypot***
- Honeytrap: 6820
- Dionaea: 4158
- Cowrie: 3872
- Suricata: 1551
- Ciscoasa: 1263
- Sentrypeer: 690
- Miniprint: 38
- Mailoney: 46
- Dicompot: 35
- ConPot: 24
- Tanner: 22
- H0neytr4p: 18
- Heralding: 16
- Redishoneypot: 9
- Adbhoney: 4
- Honeyaml: 5
- ElasticPot: 3

***Top attacking IPs***
- 45.58.127.135: 4044
- 103.184.72.162: 2726
- 203.78.147.68: 1371
- 36.229.206.51: 529
- 103.97.177.230: 324
- 62.141.43.183: 323
- 172.86.95.98: 314
- 71.41.130.50: 223
- 2.59.156.61: 182
- 185.50.38.169: 181
- 179.43.150.26: 179
- 143.198.225.212: 104
- 130.83.245.115: 151
- 129.13.189.202: 106
- 115.240.221.28: 85
- 167.250.224.25: 77
- 68.183.193.0: 68
- 159.89.121.144: 62
- 68.183.207.213: 62
- 62.60.131.157: 60

***Top targeted ports/protocols***
- 445: 3346
- 5060: 690
- 22: 645
- 8333: 265
- TCP/21: 223
- 5903: 187
- 21: 113
- 5908: 84
- 5909: 83
- 5901: 74
- 25: 43
- TCP/22: 54
- 5907: 48
- 9100: 38
- 3388: 39
- 1025: 18
- postgresql/5432: 16
- UDP/5060: 15
- TCP/1521: 25
- 1433: 14

***Most common CVEs***
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2016-5696
- CVE-2021-3449
- CVE-2019-11500
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255

***Commands attempted by attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 
- Enter new UNIX password:
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh
- cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps
- curl2
- ps aux | head -10

***Signatures triggered***
- ET DROP Dshield Block Listed Source group 1: 557
- 2402000: 557
- ET SCAN NMAP -sS window 1024: 117
- 2009582: 117
- ET FTP FTP PWD command attempt without login: 109
- 2010735: 109
- ET FTP FTP CWD command attempt without login: 108
- 2010731: 108
- ET INFO Reserved Internal IP Traffic: 50
- 2002752: 50
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 41
- 2023753: 41
- ET SCAN Potential SSH Scan: 37
- 2001219: 37
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 20
- 2010936: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
- 2403346: 10
- ET VOIP MultiTech SIP UDP Overflow: 9
- 2003237: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 9
- 2403349: 9

***Users / login attempts***
- cron/: 8
- Admin/9: 6
- root/netillo123: 5
- root/P@ssw0rd: 5
- admin/webadmin: 4
- root/000000: 4
- root/sistema500: 4
- root/vicidial: 4
- test/9999: 4
- root/nimda: 3
- root/P@55w0rd: 3
- root/palosanto: 3
- root/passw0rd: 3
- root/Password@1: 3
- root/Pr0t3c73d: 3
- root/gmeola: 3
- root/P@ssw0rd123: 3
- root/pvox@16@19: 3
- root/reilucas917382: 3
- root/s1sv0xs0ft: 3
- admin/00: 4
- root/123456789: 4
- admin/c1@r0: 4
- root/LaySys: 3
- root/Derrick00019: 3
- 345gs5662d34/345gs5662d34: 10
- debian/654321: 5
- user/webadmin: 4
- root/3245gs5662d34: 4
- ubnt/Ubnt2010: 4
- root/wxcvbn: 3
- root/datalink: 3
- root/coastal: 3

***Files uploaded/downloaded***
- No files were uploaded or downloaded.

***HTTP User-Agents***
- No HTTP User-Agents were recorded.

***SSH clients and servers***
- No SSH clients or servers were recorded.

***Top attacker AS organizations***
- No attacker AS organizations were recorded.

**Key Observations and Anomalies**

- A single IP address, 45.58.127.135, was responsible for a disproportionately high number of attacks (4,044), all of which were directed at the Honeytrap honeypot.
- The vast majority of attacks targeted port 445/TCP, indicating widespread scanning for SMB vulnerabilities.
- A common attack pattern observed in the Cowrie honeypot involved attempts to add a specific SSH public key to the `~/.ssh/authorized_keys` file. This indicates a campaign to create a persistent backdoor into compromised systems. The attackers also attempted to gather system information using commands like `uname`, `lscpu`, and `free`.
- There were multiple attempts to change the root password using `chpasswd`.
- The Suricata logs show a high number of "ET DROP Dshield Block Listed Source group 1" signatures, indicating that many of the attacking IPs are known bad actors.
