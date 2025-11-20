Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T23:01:22Z
**Timeframe:** 2025-10-17T22:20:02Z to 2025-10-17T23:00:01Z
**Log Files:** agg_log_20251017T222002Z.json, agg_log_20251017T224002Z.json, agg_log_20251017T230001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 14,254 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and various TCP/UDP ports (Honeytrap). The most active attacking IP address was 72.146.232.13. A significant number of CVEs were targeted, with CVE-2002-0012 and CVE-2002-0013 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

*   **Cowrie:** 6,780
*   **Honeytrap:** 3,144
*   **Suricata:** 1,645
*   **Ciscoasa:** 1,460
*   **Sentrypeer:** 482
*   **Dionaea:** 369
*   **Mailoney:** 208
*   **Tanner:** 48
*   **Redishoneypot:** 34
*   **H0neytr4p:** 25
*   **Adbhoney:** 18
*   **ConPot:** 16
*   **ElasticPot:** 11
*   **Dicompot:** 6
*   **Honeyaml:** 5
*   **Ipphoney:** 2
*   **Heralding:** 1

***Top Attacking IPs***

*   **72.146.232.13:** 1,109
*   **193.168.196.68:** 458
*   **88.210.63.16:** 423
*   **77.46.147.77:** 328
*   **216.10.242.161:** 208
*   **107.170.36.5:** 251
*   **46.148.229.196:** 212
*   **81.177.101.45:** 212
*   **188.164.195.81:** 213
*   **185.158.23.150:** 196

***Top Targeted Ports/Protocols***

*   **22:** 1,195
*   **5060:** 482
*   **445:** 326
*   **25:** 208
*   **5903:** 227
*   **5901:** 114
*   **8333:** 78
*   **23:** 56
*   **80:** 50
*   **5905:** 78
*   **5904:** 77

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2001-0414
*   CVE-2014-6271
*   CVE-2023-52163 CVE-2023-52163
*   CVE-2023-31983 CVE-2023-31983
*   CVE-2024-10914 CVE-2024-10914
*   CVE-2009-2765
*   CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
*   CVE-2024-3721 CVE-2024-3721
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
*   CVE-2021-42013 CVE-2021-42013
*   CVE-2019-16920 CVE-2019-16920
*   CVE-2024-12856 CVE-2024-12856 CVE-2024-12885
*   CVE-2023-47565 CVE-2023-47565

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `top`
*   `uname`
*   `uname -a`
*   `whoami`
*   `system`
*   `shell`

***Signatures Triggered***

*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   2023753
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET HUNTING RDP Authentication Bypass Attempt
*   2034857
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET INFO CURL User Agent
*   2002824
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46
*   2403345
*   ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system
*   2008953

***Users / Login Attempts***

*   **345gs5662d34/345gs5662d34:** 24
*   **root/3245gs5662d34:** 11
*   **root/123@Robert:** 9
*   **root/Qaz123qaz:** 6
*   **ftpuser/ftppassword:** 6
*   **test/test123456789:** 6
*   **ubnt/ubnt2016:** 6
*   **test/test2022:** 6
*   **default/default2017:** 6
*   **config/password321:** 6

***Files Uploaded/Downloaded***

*   `wget.sh;`
*   `rondo.dgx.sh||busybox`
*   `rondo.dgx.sh||curl`
*   `rondo.dgx.sh)|sh&`
*   `cfg_system_time.htm`
*   `server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=`
*   `update.sh;`
*   `rondo.qre.sh||busybox`
*   `rondo.qre.sh||curl`
*   `rondo.qre.sh)|sh`
*   `update.sh`
*   `rondo.sbx.sh|sh&echo${IFS}`
*   `busybox`
*   `login_pic.asp`
*   `rondo.tkg.sh|sh&echo`
*   `apply.cgi`
*   `w.sh;`
*   `c.sh;`
*   `soap-envelope`
*   `addressing`
*   `discovery`
*   `devprof`
*   `soap:Envelope>`

***HTTP User-Agents***

*   Not observed in the provided logs.

***SSH Clients and Servers***

*   Not observed in the provided logs.

***Top Attacker AS Organizations***

*   Not observed in the provided logs.

**Key Observations and Anomalies**

*   The high number of attacks from the IP address 72.146.232.13 suggests a targeted or persistent attacker.
*   The commands attempted indicate a focus on system reconnaissance and establishing a foothold for further attacks, likely for inclusion in a botnet. The repeated attempts to add an SSH key to `authorized_keys` is a common tactic for maintaining access.
*   The variety of CVEs targeted indicates that attackers are using automated tools to scan for a wide range of vulnerabilities.
*   The presence of commands related to downloading and executing shell scripts (`wget.sh`, `w.sh`, `c.sh`, `update.sh`) from various IP addresses is a strong indicator of malware infection attempts.
