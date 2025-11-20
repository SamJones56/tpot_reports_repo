Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T07:01:33Z
**Timeframe:** This report summarizes data from the following log files:
- agg_log_20251028T062001Z.json
- agg_log_20251028T064001Z.json
- agg_log_20251028T070001Z.json

**Executive Summary**

This report provides a consolidated summary of attack data collected from our honeypot network. A total of 21,132 attacks were recorded across various honeypots. The most targeted honeypot was Cowrie, with 10,093 events. The most active attacking IP address was 144.172.108.231, with a total of 1,161 attacks. The most targeted port was 5060/UDP (SIP), followed by 445/TCP (SMB) and 22/TCP (SSH). Attackers were observed attempting to gain access via common credential stuffing attacks and attempting to modify SSH authorized_keys files.

**Detailed Analysis**

***Attacks by honeypot***

- Cowrie: 10093
- Honeytrap: 3196
- Ciscoasa: 2219
- Sentrypeer: 2057
- Suricata: 1725
- Dionaea: 1442
- Mailoney: 149
- Tanner: 142
- Adbhoney: 47
- H0neytr4p: 44
- ElasticPot: 10
- ConPot: 4
- Wordpot: 2
- Honeyaml: 2

***Top attacking IPs***

- 144.172.108.231: 1161
- 180.242.216.184: 748
- 66.116.196.243: 602
- 34.66.72.251: 562
- 80.253.251.63: 562
- 5.198.176.28: 488
- 185.243.5.121: 504
- 41.94.88.49: 458
- 195.110.35.118: 430
- 162.223.91.130: 401

***Top targeted ports/protocols***

- 5060: 2057
- 445: 1237
- 22: 1129
- 5901: 215
- 1433: 153
- 8333: 148
- 25: 149
- 5903: 131
- 80: 133
- 23: 52

***Most common CVEs***

- CVE-2002-1149
- CVE-2017-3506
- CVE-2017-3606
- CVE-2019-16920
- CVE-2014-6271
- CVE-2023-47565
- CVE-2023-31983
- CVE-2009-2765
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2016-20017
- CVE-2021-35395
- CVE-2024-12856
- CVE-2024-12885
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2021-42013
- CVE-2018-7600
- CVE-2023-26801
- CVE-2020-10987
- CVE-2019-11500
- CVE-2021-3449

***Commands attempted by attackers***

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 77
- `lockr -ia .ssh`: 77
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 77
- `cat /proc/cpuinfo | grep name | wc -l`: 76
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 76
- `ls -lh $(which ls)`: 77
- `which ls`: 77
- `crontab -l`: 77
- `w`: 77
- `uname -m`: 77
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 77
- `top`: 77
- `uname`: 77
- `uname -a`: 77
- `whoami`: 77
- `lscpu | grep Model`: 77
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 77
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 76
- `Enter new UNIX password: `: 56
- `Enter new UNIX password:`: 56

***Signatures triggered***

- ET DROP Dshield Block Listed Source group 1: 394
- 2402000: 394
- ET SCAN NMAP -sS window 1024: 199
- 2009582: 199
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 200
- 2023753: 200
- ET HUNTING RDP Authentication Bypass Attempt: 70
- 2034857: 70
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61

***Users / login attempts***

- 345gs5662d34/345gs5662d34: 73
- root/3245gs5662d34: 20
- root/pass@2024: 4
- root/kalem1y1rootp: 4
- root/kangenm4m4: 4
- root/P@5sw0rd: 3
- mark/12345: 3
- carina/carina: 3
- root/12345678s: 3
- root/pa$$word123456: 3

***Files uploaded/downloaded***

- rondo.dtm.sh||busybox
- rondo.dtm.sh||curl
- rondo.dtm.sh)|sh
- rondo.xcw.sh||busybox
- rondo.xcw.sh||curl
- string>
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=
- 129.212.146.61
- rondo.qre.sh||busybox
- rondo.qre.sh||curl
- rondo.qre.sh)|sh
- ns#
- rondo.dgx.sh||busybox
- rondo.dgx.sh||curl
- rondo.dgx.sh)|sh&
- `busybox
- login_pic.asp
- rondo.tkg.sh|sh&echo
- cfg_system_time.htm
- rondo.sbx.sh|sh&echo${IFS}
- &currentsetting.htm=1
- arm.uhavenobotsxd;
- arm.uhavenobotsxd
- arm5.uhavenobotsxd;
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd;
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd;
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd;
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd;
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd;
- mipsel.uhavenobotsxd

***HTTP User-Agents***

- No HTTP User-Agents were logged in this period.

***SSH clients and servers***

- No SSH clients or servers were logged in this period.

***Top attacker AS organizations***

- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A high volume of attacks were observed from a small number of IP addresses, suggesting targeted attacks.
- Attackers were observed using a consistent set of commands to enumerate system information and attempt to install SSH keys.
- The most frequently attempted command involved modifying the `.ssh/authorized_keys` file to add a new SSH key, indicating a clear intent to establish persistent access.
- A significant number of attacks targeted SIP (5060), SMB (445), and SSH (22) ports, which are common targets for reconnaissance and exploitation.
- The Adbhoney honeypot detected attempts to download and execute malicious binaries, such as `arm.uhavenobotsxd`, indicating attempts to compromise Android-based systems.
- The Suricata logs show a high number of alerts for "ET DROP Dshield Block Listed Source group 1", indicating that many of the attacking IPs are already known to be malicious.
