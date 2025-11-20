**Honeypot Attack Summary Report**

*   **Report Generation Time**: 2025-10-11T05:01:24Z
*   **Timeframe**: 2025-10-11T04:20:00Z to 2025-10-11T05:00:01Z
*   **Files Used**:
    *   `agg_log_20251011T042001Z.json`
    *   `agg_log_20251011T044001Z.json`
    *   `agg_log_20251011T050001Z.json`

**Executive Summary**
This report summarizes 15,308 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap, Suricata, Ciscoasa, and Mailoney. Attackers were observed attempting to gain access via SSH and other common ports, and a number of common CVEs were targeted. A variety of commands were attempted post-breach, including system reconnaissance and attempts to disable security measures.

**Detailed Analysis**

*   **Attacks by Honeypot**:
    *   Cowrie: 6664
    *   Honeytrap: 3095
    *   Suricata: 1952
    *   Ciscoasa: 1809
    *   Mailoney: 865
    *   Dionaea: 631
    *   Tanner: 64
    *   Redishoneypot: 40
    *   H0neytr4p: 57
    *   Sentrypeer: 39
    *   ConPot: 16
    *   Dicompot: 17
    *   ElasticPot: 12
    *   Adbhoney: 12
    *   Honeyaml: 12
    *   Heralding: 16
    *   ssh-rsa: 2
    *   Ipphoney: 5

*   **Top Attacking IPs**:
    *   176.65.141.117: 820
    *   143.44.164.80: 503
    *   101.36.113.80: 410
    *   88.210.63.16: 465
    *   36.91.166.34: 306
    *   14.29.214.161: 302
    *   4.213.160.153: 306
    *   183.82.126.193: 297
    *   103.51.216.210: 252
    *   118.194.231.208: 233
    *   102.210.148.53: 242
    *   195.88.82.23: 214
    *   103.136.200.241: 183
    *   211.201.163.70: 173
    *   114.218.158.24: 164
    *   167.250.224.25: 215
    *   183.83.194.85: 189
    *   85.18.236.229: 134
    *   120.48.88.39: 132
    *   125.142.37.91: 118
    *   172.208.48.177: 108
    *   83.168.107.46: 174
    *   212.233.136.201: 104
    *   64.227.170.229: 114
    *   103.191.178.123: 113
    *   182.53.220.26: 109
    *   186.123.101.50: 104
    *   107.172.180.208: 94
    *   58.37.95.14: 92
    *   181.120.189.255: 90
    *   181.97.224.21: 89
    *   45.249.245.22: 85
    *   103.88.112.66: 83
    *   219.146.255.202: 55
    *   103.98.37.247: 50
    *   188.246.224.87: 46
    *   34.122.106.61: 40
    *   3.137.73.221: 39
    *   107.175.39.180: 38
    *   103.145.145.80: 35
    *   68.183.193.0: 34

*   **Top Targeted Ports/Protocols**:
    *   25: 861
    *   22: 893
    *   445: 525
    *   5903: 191
    *   80: 60
    *   8333: 73
    *   5909: 83
    *   5908: 82
    *   5901: 76
    *   443: 54
    *   6379: 34
    *   1433: 51
    *   TCP/22: 34
    *   5907: 50
    *   1081: 45
    *   28017: 26
    *   5060: 39
    *   UDP/161: 19
    *   81: 18
    *   8001: 16
    *   postgresql/5432: 16
    *   135: 14
    *   TCP/8080: 14
    *   9000: 14
    *   9090: 13
    *   TCP/1080: 12

*   **Most Common CVEs**:
    *   CVE-2002-0013 CVE-2002-0012: 12
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 9
    *   CVE-2019-11500 CVE-2019-11500: 3
    *   CVE-2021-3449 CVE-2021-3449: 3
    *   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
    *   CVE-2006-2369: 1
    *   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
    *   CVE-2005-4050: 1
    *   CVE-2022-27255 CVE-2022-27255: 1

*   **Commands Attempted by Attackers**:
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 40
    *   `lockr -ia .ssh`: 40
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 40
    *   `whoami`: 39
    *   `cat /proc/cpuinfo | grep name | wc -l`: 38
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 38
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 38
    *   `ls -lh $(which ls)`: 38
    *   `which ls`: 38
    *   `crontab -l`: 38
    *   `w`: 38
    *   `uname -m`: 38
    *   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 38
    *   `top`: 38
    *   `uname`: 38
    *   `uname -a`: 44
    *   `lscpu | grep Model`: 38
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 38
    *   `Enter new UNIX password: `: 28
    *   `Enter new UNIX password:`: 22
    *   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 6

*   **Signatures Triggered**:
    *   ET DROP Dshield Block Listed Source group 1: 552
    *   2402000: 552
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 322
    *   2023753: 322
    *   ET HUNTING RDP Authentication Bypass Attempt: 145
    *   2034857: 145
    *   ET SCAN NMAP -sS window 1024: 152
    *   2009582: 152
    *   ET INFO Reserved Internal IP Traffic: 56
    *   2002752: 56
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 24
    *   2403343: 24
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 47: 33
    *   2403346: 33
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 20
    *   2400031: 20
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
    *   2403345: 11
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 11
    *   2403347: 11
    *   ET SCAN Potential SSH Scan: 10
    *   2001219: 10
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 42: 14
    *   2403341: 14
    *   GPL INFO SOCKS Proxy attempt: 9
    *   2100615: 9
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 50: 8
    *   2403349: 8
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 49: 10
    *   2403348: 10
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 45: 10
    *   2403344: 10
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 29: 10
    *   2400028: 10

*   **Users / Login Attempts**:
    *   345gs5662d34/345gs5662d34: 38
    *   root/nPSpP4PBW0: 16
    *   root/Ahgf3487@rtjhskl854hd47893@#a4nC: 14
    *   admin/admin2020: 6
    *   root/3245gs5662d34: 9
    *   nobody/1q2w3e: 6
    *   ubnt/admin1: 6
    *   root/calderon: 4
    *   root/aDm1nI.: 4
    *   nobody/nobody2012: 4
    *   training/training: 4
    *   root/12Az789cok==: 4
    *   user/password123: 4
    *   root/rta1212: 4
    *   root/AM1504.@: 4
    *   root/a102030a: 4
    *   root/jf162500: 4
    *   root/V1rf0n@3c: 4
    *   root/09N1RCa1Hs31: 7
    *   ali/ali: 3
    *   apt/apt: 2
    *   drew/drew123: 2

*   **Files Uploaded/Downloaded**:
    *   arm.urbotnetisass;: 2
    *   arm.urbotnetisass: 2
    *   arm5.urbotnetisass;: 2
    *   arm5.urbotnetisass: 2
    *   arm6.urbotnetisass;: 2
    *   arm6.urbotnetisass: 2
    *   arm7.urbotnetisass;: 2
    *   arm7.urbotnetisass: 2
    *   x86_32.urbotnetisass;: 2
    *   x86_32.urbotnetisass: 2
    *   mips.urbotnetisass;: 2
    *   mips.urbotnetisass: 2
    *   mipsel.urbotnetisass;: 2
    *   mipsel.urbotnetisass: 2
    *   &currentsetting.htm=1: 1
    *   applebot): 1
    *   11: 9
    *   fonts.gstatic.com: 9
    *   css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 8
    *   ie8.css?ver=1.0: 8
    *   html5.js?ver=3.7.3: 8
    *   k.php?a=x86_64,5R60WLJRT4F253B1H: 1

*   **HTTP User-Agents**:
    *   None Observed

*   **SSH Clients**:
    *   None Observed

*   **SSH Servers**:
    *   None Observed

*   **Top Attacker AS Organizations**:
    *   None Observed

**Key Observations and Anomalies**
*   A high number of commands related to disabling security measures (`chattr`, `lockr`, `rm -rf /tmp/secure.sh`) and reconnaissance (`whoami`, `uname -a`, `lscpu`) were observed, suggesting that attackers were attempting to establish a persistent presence on the compromised systems.
*   The repeated use of the same SSH key (`ssh-rsa ... mdrfckr`) across multiple attacks indicates a coordinated campaign by a single threat actor or group.
*   The file `arm.urbotnetisass` was downloaded multiple times, suggesting a focus on compromising IoT devices.
*   The presence of `Enter new UNIX password:` in the command logs suggests that some of the attacks may have been interactive.

This concludes the Honeypot Attack Summary Report.