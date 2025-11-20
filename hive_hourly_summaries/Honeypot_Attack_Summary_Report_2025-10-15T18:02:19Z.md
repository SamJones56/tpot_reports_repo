Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T18:01:31Z
**Timeframe:** 2025-10-15T17:20:01Z to 2025-10-15T18:00:01Z
**Files Used:**
- agg_log_20251015T172001Z.json
- agg_log_20251015T174001Z.json
- agg_log_20251015T180001Z.json

**Executive Summary**
This report summarizes 26,301 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot. The most prominent attack vector was exploitation attempts against SMB (port 445), likely related to the DoublePulsar backdoor, followed by SIP (port 5060) and SSH (port 22) scans and brute-force attempts. A significant number of commands were executed on compromised systems, primarily focused on reconnaissance and establishing further footholds.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 10239
    *   Honeytrap: 4130
    *   Sentrypeer: 3828
    *   Suricata: 2960
    *   Dionaea: 2679
    *   Ciscoasa: 1601
    *   ElasticPot: 558
    *   Heralding: 113
    *   Mailoney: 52
    *   H0neytr4p: 50
    *   ConPot: 28
    *   Tanner: 22
    *   Ipphoney: 13
    *   Adbhoney: 9
    *   Miniprint: 9
    *   Redishoneypot: 9
    *   Honeyaml: 1

*   **Top Attacking IPs:**
    *   45.171.150.123: 2090
    *   61.7.187.121: 1513
    *   185.243.5.121: 1446
    *   206.191.154.180: 1425
    *   45.78.193.100: 1244
    *   134.199.207.58: 999
    *   196.251.88.103: 998
    *   79.143.89.199: 837
    *   143.198.201.181: 580
    *   185.90.162.108: 750

*   **Top Targeted Ports/Protocols:**
    *   5060: 3828
    *   445: 2599
    *   22: 1824
    *   TCP/445: 1516
    *   9200: 558
    *   5903: 224
    *   1557: 156
    *   TCP/22: 131
    *   5901: 116
    *   UDP/5060: 97

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
    *   CVE-2019-11500 CVE-2019-11500
    *   CVE-2016-20016 CVE-2016-20016

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh
    *   lockr -ia .ssh
    *   lscpu | grep Model
    *   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
    *   which ls
    *   ls -lh $(which ls)
    *   crontab -l
    *   w
    *   uname -m
    *   cat /proc/cpuinfo | grep model | grep name | wc -l
    *   top
    *   uname -a
    *   whoami
    *   Enter new UNIX password:
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766)
    *   ET DROP Dshield Block Listed Source group 1 (2402000)
    *   ET SCAN NMAP -sS window 1024 (2009582)
    *   ET INFO VNC Authentication Failure (2002920)
    *   ET SCAN Potential SSH Scan (2001219)
    *   ET SCAN Suspicious inbound to MSSQL port 1433 (2010935)
    *   ET INFO Reserved Internal IP Traffic (2002752)
    *   ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper (2012297)
    *   ET VOIP Modified Sipvicious Asterisk PBX User-Agent (2012296)

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   ftpuser/ftppassword
    *   root/123@@@
    *   root/Qaz123qaz
    *   debian/555
    *   blank/77
    *   root/Password@2025
    *   unknown/555555
    *   guest/5555
    *   nobody/nobody2012

*   **Files Uploaded/Downloaded:**
    *   arm.urbotnetisass
    *   arm5.urbotnetisass
    *   arm6.urbotnetisass
    *   arm7.urbotnetisass
    *   x86_32.urbotnetisass
    *   mips.urbotnetisass
    *   mipsel.urbotnetisass
    *   fonts.gstatic.com
    *   css?family=Libre+Franklin...
    *   ie8.css?ver=1.0
    *   html5.js?ver=3.7.3

*   **HTTP User-Agents:**
    *   No user agents recorded in this period.

*   **SSH Clients:**
    *   No SSH clients recorded in this period.

*   **SSH Servers:**
    *   No SSH servers recorded in this period.

*   **Top Attacker AS Organizations:**
    *   No AS organizations recorded in this period.

**Key Observations and Anomalies**
- A high volume of exploitation attempts targeting the DoublePulsar backdoor was observed, indicating a potential worm or automated attack campaign.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` was frequently used, which is a common technique to maintain persistence on a compromised machine by adding the attacker's public SSH key.
- Multiple files with the name `*.urbotnetisass` were downloaded, which are likely malware payloads for different architectures.
- The activity is distributed across a wide range of honeypots, with Cowrie, Honeytrap, and Sentrypeer seeing the most action. This indicates a broad-spectrum attack approach by the adversaries.
