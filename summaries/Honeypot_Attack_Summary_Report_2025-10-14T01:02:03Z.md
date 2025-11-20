**Honeypot Attack Summary Report**

*   **Report Generation Time**: `2025-10-14T01:01:34Z`
*   **Timeframe**: `2025-10-14T00:20:01Z` to `2025-10-14T01:00:01Z`
*   **Files Used**:
    *   `agg_log_20251014T002001Z.json`
    *   `agg_log_20251014T004001Z.json`
    *   `agg_log_20251014T010001Z.json`

**Executive Summary**

This report summarizes 16,331 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Sentrypeer, Dionaea, and Redishoneypot. The most prominent attacker IP was `8.222.207.98`. The most targeted ports were 5060 (SIP), 445 (SMB), and 6379 (Redis). A number of CVEs were targeted, with `CVE-2005-4050` being the most frequent. Attackers attempted a variety of commands, including downloading and executing malicious files.

**Detailed Analysis**

*   **Attacks by Honeypot**:
    *   Cowrie: 5458
    *   Sentrypeer: 2911
    *   Dionaea: 2415
    *   Redishoneypot: 2058
    *   Suricata: 1493
    *   Honeytrap: 1087
    *   Mailoney: 583
    *   ssh-rsa: 136
    *   Ciscoasa: 38
    *   Tanner: 43
    *   Adbhoney: 28
    *   H0neytr4p: 30
    *   Honeyaml: 20
    *   ConPot: 17
    *   Dicompot: 7
    *   Wordpot: 2
    *   ElasticPot: 2
    *   Ipphoney: 3

*   **Top Attacking IPs**:
    *   8.222.207.98: 2704
    *   42.119.232.181: 1522
    *   129.212.185.225: 1002
    *   185.243.5.146: 1020
    *   36.229.206.51: 755
    *   46.32.178.94: 745
    *   45.236.188.4: 717
    *   185.243.5.148: 661
    *   86.54.42.238: 450
    *   71.168.162.91: 371
    *   172.86.95.115: 397
    *   172.86.95.98: 377
    *   62.141.43.183: 293

*   **Top Targeted Ports/Protocols**:
    *   5060: 2911
    *   445: 2283
    *   6379: 2058
    *   22: 988
    *   25: 585
    *   1433: 99
    *   UDP/5060: 78
    *   80: 53
    *   23: 52
    *   TCP/22: 60

*   **Most Common CVEs**:
    *   CVE-2005-4050: 63
    *   CVE-2002-0013 CVE-2002-0012: 23
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 14
    *   CVE-2006-0189: 2
    *   CVE-2022-27255 CVE-2022-27255: 2
    *   CVE-2019-11500 CVE-2019-11500: 2
    *   CVE-2001-0414: 1
    *   CVE-2016-6563: 1

*   **Commands Attempted by Attackers**:
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh: 3
    *   lockr -ia .ssh: 3
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 4
    *   cat /proc/cpuinfo | grep name | wc -l: 3
    *   Enter new UNIX password: : 3
    *   uname -s -v -n -r -m: 3
    *   ... and many long `nohup bash -c` commands for downloading and executing files.

*   **Signatures Triggered**:
    *   ET DROP Dshield Block Listed Source group 1: 434
    *   2402000: 434
    *   ET SCAN NMAP -sS window 1024: 158
    *   2009582: 158
    *   ET VOIP MultiTech SIP UDP Overflow: 63
    *   2003237: 63
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 66
    *   2023753: 66
    *   ET INFO Reserved Internal IP Traffic: 59
    *   2002752: 59

*   **Users / Login Attempts**:
    *   root/: 136
    *   sa/!@#123qwe: 10
    *   centos/centos2018: 6
    *   support/666: 6
    *   centos/password321: 6
    *   debian/debian2010: 6

*   **Files Uploaded/Downloaded**:
    *   arm.urbotnetisass;: 2
    *   arm.urbotnetisass: 2
    *   arm5.urbotnetisass;: 2
    *   arm5.urbotnetisass: 2
    *   ... many others, including `Mozi.m`

*   **HTTP User-Agents**: None observed.
*   **SSH Clients**: None observed.
*   **SSH Servers**: None observed.
*   **Top Attacker AS Organizations**: None observed.

**Key Observations and Anomalies**

*   A significant number of commands are related to downloading and executing a file from a remote server, often using `nohup bash -c "exec 6<>/dev/tcp/...`. This is a common technique for malware droppers. The IPs `8.152.7.218` and `8.222.207.98` are frequently used as the download source.
*   The `urbotnetisass` files suggest a botnet campaign targeting various architectures (ARM, x86, MIPS).
*   There's a recurring attempt to modify the `.ssh/authorized_keys` file, indicating attempts to establish persistent access.

This concludes the Honeypot Attack Summary Report.