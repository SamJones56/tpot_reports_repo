Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T06:01:26Z
**Timeframe:** 2025-10-07T05:20:02Z to 2025-10-07T06:00:01Z
**Files Used:**
*   agg_log_20251007T052002Z.json
*   agg_log_20251007T054001Z.json
*   agg_log_20251007T060001Z.json

**Executive Summary**

This report summarizes 16,301 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most active attacking IP address was 42.118.158.88. The most targeted port was 445/TCP. Several CVEs were detected, with the most frequent being CVE-2002-1149. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***

**Attacks by Honeypot**

*   **Cowrie:** 6319
*   **Honeytrap:** 2831
*   **Dionaea:** 1910
*   **Mailoney:** 1684
*   **Suricata:** 1444
*   **Ciscoasa:** 1184
*   **Sentrypeer:** 607
*   **Tanner:** 133
*   **Heralding:** 63
*   **H0neytr4p:** 29
*   **ElasticPot:** 21
*   **Honeyaml:** 21
*   **ConPot:** 21
*   **Miniprint:** 18
*   **Redishoneypot:** 12
*   **Dicompot:** 3
*   **Ipphoney:** 1

**Top Attacking IPs**

*   42.118.158.88: 1853
*   86.54.42.238: 821
*   176.65.141.117: 820
*   172.86.95.98: 434
*   110.39.162.202: 426
*   200.73.135.75: 322
*   103.59.94.4: 317
*   178.128.152.40: 233
*   161.132.37.66: 235
*   80.97.160.148: 212

**Top Targeted Ports/Protocols**

*   445: 1864
*   25: 1671
*   22: 812
*   5060: 607
*   80: 142
*   8333: 126
*   5903: 95
*   TCP/80: 32
*   23: 56
*   vnc/5900: 63

**Most Common CVEs**

*   CVE-2019-11500
*   CVE-2002-1149
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

**Commands Attempted by Attackers**

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `Enter new UNIX password:`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`

**Signatures Triggered**

*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET INFO VNC Authentication Failure
*   2002920
*   ET SCAN Potential SSH Scan
*   2001219

**Users / Login Attempts**

*   345gs5662d34/345gs5662d34
*   pivpn/3245gs5662d34
*   me/me!
*   rocky/rocky!
*   teste/temp.123
*   runner/Password1
*   vncuser/123vncuser
*   es/es!
*   it/it!
*   admin/070273

**Files Uploaded/Downloaded**

*   &currentsetting.htm=1
*   ?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine
*   xhtml1-transitional.dtd
*   xhtml
*   fbml
*   tomcat?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine
*   community.bitnami.com?utm_source=bitnami&amp;utm_medium=virtualmachine&amp;utm_campaign=Virtual%2BMachine

**HTTP User-Agents**

*   No user agents were logged during this period.

**SSH Clients and Servers**

*   No SSH clients or servers were logged during this period.

**Top Attacker AS Organizations**

*   No attacker AS organizations were logged during this period.

**Key Observations and Anomalies**

*   The majority of commands are focused on system enumeration and establishing persistence by adding an SSH key to `authorized_keys`.
*   The high number of events on port 445 suggests widespread scanning for SMB vulnerabilities.
*   The presence of VNC authentication failures indicates brute-force attempts against remote desktop services.
*   A significant amount of SMTP traffic was observed on port 25.
