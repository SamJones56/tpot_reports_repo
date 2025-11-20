Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T07:01:43Z
**Timeframe:** 2025-10-09T06:20:01Z to 2025-10-09T07:00:01Z
**Log Files:**
- agg_log_20251009T062001Z.json
- agg_log_20251009T064001Z.json
- agg_log_20251009T070001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 18,265 attacks were recorded, with a significant focus on the Suricata, Cowrie, and Dionaea honeypots. The most targeted ports were 445 (SMB) and 22 (SSH). A notable observation is the high volume of attacks from the IP address 171.42.244.192. Several CVEs were targeted, and a variety of system reconnaissance and access manipulation commands were attempted.

**Detailed Analysis**

***Attacks by Honeypot***

*   **Suricata:** 4555
*   **Cowrie:** 4450
*   **Dionaea:** 4092
*   **Honeytrap:** 3153
*   **Ciscoasa:** 1643
*   **Heralding:** 110
*   **Mailoney:** 80
*   **Sentrypeer:** 60
*   **Tanner:** 39
*   **H0neytr4p:** 26
*   **Honeyaml:** 22
*   **ConPot:** 14
*   **Redishoneypot:** 12
*   **Adbhoney:** 4
*   **ElasticPot:** 2
*   **Wordpot:** 2
*   **Ipphoney:** 1

***Top Attacking IPs***

*   171.42.244.192
*   14.224.170.239
*   190.35.66.46
*   103.130.205.82
*   80.94.95.238
*   198.186.131.155
*   45.164.39.253
*   154.12.94.3
*   114.219.56.203
*   162.240.156.34

***Top Targeted Ports/Protocols***

*   445 (SMB)
*   TCP/445
*   22 (SSH)
*   TCP/21 (FTP)
*   5903 (VNC)
*   8333 (Bitcoin)
*   21 (FTP)
*   25 (SMTP)
*   5901 (VNC)
*   80 (HTTP)
*   5060 (SIP)
*   vnc/5900

***Most Common CVEs***

*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2006-2369
*   CVE-2005-4050
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `Enter new UNIX password:`
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
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

***Signatures Triggered***

*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET FTP FTP CWD command attempt without login
*   ET FTP FTP PWD command attempt without login
*   ET INFO Reserved Internal IP Traffic
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   GPL INFO SOCKS Proxy attempt
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34
*   user/102030
*   operator/P@ssword
*   pivpn/pivpn!
*   remoto/123321
*   default/default10
*   admin/sky
*   guest/159753
*   root/root12345
*   admin/admin555
*   config/config88

***Files Uploaded/Downloaded***

*   ?format=json
*   &currentsetting.htm=1
*   11
*   fonts.gstatic.com
*   css?family=Libre+Franklin...
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3

***SSH Clients and Servers***

*   No SSH client data available in the logs.
*   No SSH server data available in the logs.

***Top Attacker AS Organizations***

*   No AS organization data available in the logs.

**Key Observations and Anomalies**

*   The high number of attacks from 171.42.244.192 suggests a targeted campaign or a compromised machine being used for attacks.
*   The commands attempted indicate a focus on reconnaissance and establishing persistent access through SSH key manipulation.
*   The variety of honeypots triggered shows a broad spectrum of scanning and exploitation attempts against different services.
*   The "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature indicates attempts to install a known backdoor, likely related to the EternalBlue exploit.
