Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T08:01:21Z
**Timeframe:** 2025-10-18T07:20:01Z to 2025-10-18T08:00:01Z
**Log Files:**
- agg_log_20251018T072001Z.json
- agg_log_20251018T074001Z.json
- agg_log_20251018T080001Z.json

**Executive Summary**

This report summarizes 17,918 events collected from the T-Pot honeypot network. The majority of attacks targeted the Dionaea and Cowrie honeypots. The most frequent attacks were aimed at port 445 (SMB), with a significant number of attempts also recorded on ports 22 (SSH) and 5060 (SIP). A variety of CVEs were detected, with CVE-2024-3721 being the most common. Attackers attempted a range of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

*   **Dionaea:** 6,364
*   **Cowrie:** 4,996
*   **Honeytrap:** 2,634
*   **Suricata:** 1,449
*   **Ciscoasa:** 1,285
*   **Sentrypeer:** 824
*   **Tanner:** 106
*   **Adbhoney:** 82
*   **Mailoney:** 69
*   **H0neytr4p:** 53
*   **Redishoneypot:** 35
*   **Honeyaml:** 8
*   **ConPot:** 6
*   **Dicompot:** 4
*   **ElasticPot:** 2
*   **Ipphoney:** 1

***Top Attacking IPs***

*   14.139.92.36
*   180.246.177.205
*   72.146.232.13
*   182.18.139.237
*   88.210.63.16
*   172.86.95.115
*   107.170.36.5
*   172.86.95.98
*   ...and others

***Top Targeted Ports/Protocols***

*   445
*   22
*   5060
*   5903
*   80
*   81
*   443
*   25
*   1433
*   ...and others

***Most Common CVEs***

*   CVE-2024-3721
*   CVE-2016-20016
*   CVE-2018-10562, CVE-2018-10561
*   CVE-2023-26801
*   CVE-2019-16920
*   CVE-2009-2765
*   CVE-2023-31983
*   CVE-2020-10987
*   CVE-2015-2051, CVE-2019-10891, CVE-2024-33112, CVE-2025-11488, CVE-2022-37056
*   CVE-2023-47565
*   CVE-2014-6271
*   CVE-2002-0013, CVE-2002-0012

***Commands Attempted by Attackers***

*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `lockr -ia .ssh`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `uname -a`
*   `whoami`
*   `system`
*   `shell`
*   ...and others

***Signatures Triggered***

*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET INFO CURL User Agent
*   ET INFO Reserved Internal IP Traffic
*   ...and others

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34
*   root/20gfsouto15
*   admin/777777
*   ubnt/ubnt2009
*   ...and others

***Files Uploaded/Downloaded***

*   11
*   fonts.gstatic.com
*   css?family=Libre+Franklin...
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3
*   gpon8080&ipv=0
*   ...and others

***HTTP User-Agents***

*   No user agents reported.

***SSH Clients and Servers***

*   No SSH clients or servers reported.

***Top Attacker AS Organizations***

*   No AS organizations reported.

**Key Observations and Anomalies**

*   A high volume of activity was observed from the IP address 14.139.92.36, primarily targeting port 445.
*   The repeated use of commands to remove and replace SSH authorized_keys suggests a campaign to maintain persistent access to compromised systems.
*   The presence of various CVEs indicates that attackers are attempting to exploit a wide range of vulnerabilities.
*   No specific HTTP User-Agents or SSH clients were identified, which may suggest the use of custom tools or scripts by the attackers.

This report provides a snapshot of the threat landscape as observed by the honeypot network. Continuous monitoring is recommended to identify emerging threats and attack patterns.
