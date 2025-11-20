**Honeypot Attack Summary Report**

*   **Report Generation Time**: 2025-10-19T11:01:30Z
*   **Timeframe**: 2025-10-19T10:20:01Z to 2025-10-19T11:00:01Z
*   **Log Files**:
    *   `agg_log_20251019T102001Z.json`
    *   `agg_log_20251019T104002Z.json`
    *   `agg_log_20251019T110001Z.json`

**Executive Summary**

This report summarizes 29,984 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Suricata, and Heralding honeypots. The most prominent attack vectors include exploitation of VNC, SMB, and SSH services, with a significant number of attempts to exploit CVE-2005-4050. A wide range of reconnaissance and exploitation commands were observed.

**Detailed Analysis**

*   **Attacks by Honeypot**:
    *   Cowrie: 10,046
    *   Suricata: 5,078
    *   Heralding: 5,325
    *   Dionaea: 3,725
    *   Honeytrap: 2,778
    *   Sentrypeer: 1,997
    *   Ciscoasa: 780
    *   Tanner: 131
    *   Adbhoney: 31
    *   Mailoney: 33
    *   ElasticPot: 11
    *   ConPot: 14
    *   H0neytr4p: 15
    *   Redishoneypot: 11
    *   Honeyaml: 3
    *   Dicompot: 3
    *   Miniprint: 3

*   **Top Attacking IPs**:
    *   185.243.96.105: 3966
    *   88.234.160.126: 2503
    *   41.139.200.19: 1487
    *   198.44.138.123: 1364
    *   129.212.179.205: 1005
    *   129.212.182.165: 1005
    *   143.198.201.181: 1090
    *   102.90.115.22: 1151
    *   194.50.16.73: 1678
    *   72.146.232.13: 984

*   **Top Targeted Ports/Protocols**:
    *   vnc/5900: 3966
    *   445: 3669
    *   TCP/445: 2634
    *   22: 2242
    *   5060: 1997
    *   UDP/5060: 1139
    *   postgresql/5432: 1359
    *   80: 126

*   **Most Common CVEs**:
    *   CVE-2005-4050
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-1999-0183
    *   CVE-2023-26801
    *   CVE-2009-2765
    *   CVE-2019-16920
    *   CVE-2023-31983
    *   CVE-2020-10987
    *   CVE-2023-47565
    *   CVE-2014-6271
    *   CVE-2015-2051
    *   CVE-2019-10891
    *   CVE-2024-33112
    *   CVE-2022-37056
    *   CVE-2021-3449
    *   CVE-2019-11500
    *   CVE-2024-4577
    *   CVE-2002-0953
    *   CVE-2021-41773
    *   CVE-2021-42013

*   **Commands Attempted by Attackers**:
    *   `uname -s -v -n -r -m`
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

*   **Signatures Triggered**:
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   ET VOIP MultiTech SIP UDP Overflow
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN Potential SSH Scan
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET SCAN NMAP -sS window 1024
    *   ET INFO Reserved Internal IP Traffic
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 43
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 49
    *   GPL INFO SOCKS Proxy attempt
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 6
    *   ET INFO CURL User Agent
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 28
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 3

*   **Users / Login Attempts**:
    *   /Passw0rd
    *   root/123
    *   admin/admin333
    *   /1q2w3e4r
    *   postgres/1234567
    *   guest/1111
    *   config/config666

*   **Files Uploaded/Downloaded**:
    *   sh
    *   wget.sh;
    *   w.sh;
    *   c.sh;
    *   server.cgi
    *   rondo.qre.sh
    *   login_pic.asp
    *   welcome.jpg
    *   writing.jpg
    *   tags.jpg

*   **HTTP User-Agents**: None Observed
*   **SSH Clients**: None Observed
*   **SSH Servers**: None Observed
*   **Top Attacker AS Organizations**: None Observed

**Key Observations and Anomalies**

*   The high number of VNC and SMB attacks suggests a focus on exploiting remote access and file-sharing services.
*   The repeated use of `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates a common tactic to install persistent backdoors.
*   The presence of commands to gather system information (`uname`, `lscpu`, `free`) is typical of post-exploitation reconnaissance.
*   The variety of CVEs targeted, from older vulnerabilities like CVE-2005-4050 to more recent ones, highlights the broad-spectrum approach of attackers.
*   The download of shell scripts (`wget.sh`, `w.sh`, `c.sh`) is a clear indication of attempts to install malware or establish further control.