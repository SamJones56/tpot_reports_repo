Honeypot Attack Summary Report

*   **Report Generation Time:** 2025-10-06T10:01:29Z
*   **Timeframe:** 2025-10-06T09:20:01Z to 2025-10-06T10:00:01Z
*   **Files Used:**
    *   agg_log_20251006T092001Z.json
    *   agg_log_20251006T094001Z.json
    *   agg_log_20251006T100001Z.json

**Executive Summary**

This report summarizes 25,890 events collected from the honeypot network. The majority of attacks were detected by the Cowrie and Dionaea honeypots. The most targeted services were SMB (port 445) and SMTP (port 25). The most active attacking IP was `120.55.160.161`.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 10317
    *   Dionaea: 6265
    *   Honeytrap: 2353
    *   Mailoney: 2505
    *   Suricata: 1878
    *   Ciscoasa: 1331
    *   Sentrypeer: 842
    *   Tanner: 94
    *   H0neytr4p: 78
    *   Adbhoney: 64
    *   Miniprint: 82
    *   Redishoneypot: 52
    *   ConPot: 19
    *   Honeyaml: 7
    *   Ipphoney: 1
    *   Heralding: 1
    *   ElasticPot: 1

*   **Top Attacking IPs:**
    *   120.55.160.161: 2929
    *   113.160.58.86: 1501
    *   196.251.88.103: 1367
    *   170.64.159.245: 1202
    *   113.23.104.52: 1047
    *   176.65.148.44: 980
    *   86.54.42.238: 1641
    *   176.65.141.117: 820
    *   20.2.136.52: 740
    *   40.82.137.99: 655
    *   62.162.61.154: 650
    *   172.86.95.98: 368

*   **Top Targeted Ports/Protocols:**
    *   445: 6209
    *   25: 2505
    *   22: 1655
    *   5060: 842
    *   80: 96
    *   443: 78
    *   9100: 82
    *   5902: 98
    *   5903: 95
    *   6379: 46

*   **Most Common CVEs:**
    *   CVE-2021-44228
    *   CVE-2019-12263
    *   CVE-2019-12261
    *   CVE-2019-12260
    *   CVE-2019-12255
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-2002-1149
    *   CVE-1999-0183
    *   CVE-2018-14847
    *   CVE-1999-0517
    *   CVE-2019-11500
    *   CVE-2005-4050
    *   CVE-2006-2369

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `Enter new UNIX password:`
    *   `uname -a`
    *   `w`
    *   `whoami`
    *   `tftp; wget; /bin/busybox ULRLN`

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1
    *   2402000
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   2023753
    *   ET SCAN NMAP -sS window 1024
    *   2009582
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   2034857

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   postgres/postgres
    *   root/1qaz@WSX
    *   worker/worker
    *   plex/plex
    *   centos/centos
    *   root/123456789
    *   nexus/nexus
    *   pass/pass123

*   **Files Uploaded/Downloaded:**
    *   wget.sh;
    *   w.sh;
    *   c.sh;
    *   fonts.gstatic.com
    *   Mozi.m dlink.mips

*   **HTTP User-Agents:**
    *   *No user agents recorded in this period.*

*   **SSH Clients:**
    *   *No SSH clients recorded in this period.*

*   **SSH Servers:**
    *   *No SSH servers recorded in this period.*

*   **Top Attacker AS Organizations:**
    *   *No AS organizations recorded in this period.*

**Key Observations and Anomalies**

*   A significant amount of scanning activity was observed against SMB (445/TCP), likely related to opportunistic worms or vulnerability scanners.
*   The repeated execution of shell commands to download and execute scripts from remote servers (`wget`, `curl`, `sh`) indicates automated attempts to install malware or backdoors.
*   The presence of CVE-2021-44228 (Log4Shell) indicates continued exploitation attempts for this vulnerability.
