Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T07:01:43Z
**Timeframe:** 2025-10-21T06:20:01Z to 2025-10-21T07:00:01Z
**Log Files:** agg_log_20251021T062001Z.json, agg_log_20251021T064001Z.json, agg_log_20251021T070001Z.json

### Executive Summary

This report summarizes 5,727 malicious events recorded across the honeypot network. The majority of attacks targeted the Cowrie honeypot. The most prominent attack vector was SSH brute-forcing, with significant activity also observed on ports related to SIP and SMB. A notable observation is the repeated attempt to download and execute a Perl-based IRC bot, indicating a campaign to recruit devices into a botnet. Attackers also performed extensive system reconnaissance and attempted to install malicious SSH keys.

### Detailed Analysis

**Attacks by Honeypot**
*   Cowrie: 2,881
*   Honeytrap: 1,563
*   Suricata: 790
*   Sentrypeer: 236
*   Dionaea: 87
*   Mailoney: 33
*   ConPot: 39
*   H0neytr4p: 24
*   Ciscoasa: 18
*   Tanner: 22
*   Miniprint: 15
*   Redishoneypot: 8
*   Honeyaml: 4
*   ElasticPot: 3
*   Adbhoney: 2
*   Wordpot: 2

**Top Attacking IPs**
*   129.212.187.82: 740
*   72.146.232.13: 606
*   201.249.182.130: 172
*   185.243.5.158: 228
*   152.32.135.139: 99
*   103.48.84.147: 94
*   152.42.165.179: 94
*   107.170.36.5: 153
*   151.19.43.3: 148
*   18.222.255.237: 133
*   217.112.80.175: 118
*   159.89.98.186: 109

**Top Targeted Ports/Protocols**
*   22: 578
*   5060: 236
*   445: 212
*   8333: 86
*   5905: 77
*   5904: 77
*   25: 33
*   1025: 37

**Most Common CVEs**
*   CVE-2021-3449: 5
*   CVE-2019-11500: 4
*   CVE-2024-3721: 1
*   CVE-2002-0013: 1
*   CVE-2002-0012: 1

**Commands Attempted by Attackers**
*   `echo ... | base64 -d | perl &`: 9
*   `cat /proc/cpuinfo | grep name | wc -l`: 6
*   `Enter new UNIX password:`: 6
*   `uname -a`: 6
*   `whoami`: 6
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 5
*   `lockr -ia .ssh`: 5
*   `cd ~ && rm -rf .ssh && ... >> .ssh/authorized_keys`: 4
*   `uname -s -v -n -r -m`: 1

**Signatures Triggered**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication / 2024766: 201
*   ET DROP Dshield Block Listed Source group 1 / 2402000: 186
*   ET SCAN NMAP -sS window 1024 / 2009582: 85
*   ET INFO Reserved Internal IP Traffic / 2002752: 41
*   ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 10
*   ET SCAN Suspicious inbound to MSSQL port 1433 / 2010935: 8

**Users / Login Attempts**
*   345gs5662d34/345gs5662d34: 5
*   user01/Password01: 3
*   root/allstar1151: 2
*   root/allterra: 2
*   root/unicorn: 2
*   root/Alm4Q3g4l: 2
*   root/allc: 2
*   root/123qwe!@#: 2
*   alireza/alireza123: 3
*   root/Alianza4733: 2

**Files Uploaded/Downloaded**
*   No file transfer activity was observed.

**HTTP User-Agents**
*   No significant HTTP user-agent activity was observed.

**SSH Clients and Servers**
*   No specific SSH client or server software information was logged.

**Top Attacker AS Organizations**
*   No attacker AS organization data was available in the logs.

### Key Observations and Anomalies

- **IRC Bot Deployment:** A recurring command involves decoding a large base64 string and piping it to a Perl interpreter. This script is a Perl-based IRC bot designed for DDoS attacks ("DDoS Perl IrcBot v1.0"). This indicates a coordinated effort to add compromised devices to a botnet.
- **System Reconnaissance:** Attackers frequently ran commands to profile the system, including `uname -a`, `lscpu`, `cat /proc/cpuinfo`, and `free -m`. This is standard post-exploitation behavior to understand the environment.
- **SSH Key Manipulation:** Multiple commands aimed to delete existing SSH configurations (`rm -rf .ssh`) and install a new public SSH key. This allows the attacker to gain persistent, passwordless access to the machine.
- **DoublePulsar Activity:** The high number of "DoublePulsar Backdoor" signatures suggests scanning or exploitation attempts related to the NSA-leaked SMB exploit, even years after it was patched.
