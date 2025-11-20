Here is your Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-20T12:01:32Z
*   **Timeframe:** 2025-10-20T11:20:01Z to 2025-10-20T12:00:01Z
*   **Files Used:**
    *   `agg_log_20251020T112001Z.json`
    *   `agg_log_20251020T114001Z.json`
    *   `agg_log_20251020T120001Z.json`

**Executive Summary**

This report summarizes 21,179 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most targeted service was SMB on TCP port 445. A significant number of attacks originated from the IP address 170.155.12.3. The most common attack signature detected was related to the DoublePulsar backdoor. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 8705
    *   Honeytrap: 7170
    *   Suricata: 3419
    *   Sentrypeer: 791
    *   Dionaea: 437
    *   Mailoney: 274
    *   Adbhoney: 135
    *   Tanner: 88
    *   ConPot: 32
    *   Redishoneypot: 26
    *   H0neytr4p: 23
    *   Ciscoasa: 29
    *   Miniprint: 19
    *   Dicompot: 12
    *   Honeyaml: 7
    *   Heralding: 8
    *   ElasticPot: 4

*   **Top Attacking IPs:**
    *   45.134.20.151: 3053
    *   170.155.12.3: 1968
    *   72.146.232.13: 1251
    *   51.89.1.88: 1248
    *   72.167.220.12: 1241
    *   212.87.220.20: 916
    *   8.209.85.186: 615
    *   57.129.61.16: 475
    *   196.203.109.209: 349
    *   107.174.26.130: 367
    *   45.61.187.220: 367
    *   213.229.116.35: 298
    *   34.71.52.51: 283
    *   157.230.178.76: 247
    *   185.243.5.158: 241
    *   107.170.36.5: 252
    *   176.65.141.119: 200
    *   185.243.5.103: 193
    *   202.83.162.167: 224
    *   45.128.199.34: 171

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 2315
    *   5038: 3054
    *   22: 1666
    *   5060: 791
    *   1995: 195
    *   4443: 202
    *   5903: 225
    *   23: 142
    *   25: 258
    *   5901: 116
    *   8333: 87
    *   80: 69
    *   5555: 61
    *   5905: 76
    *   5904: 78
    *   TCP/1433: 55
    *   5909: 50
    *   5908: 33
    *   5907: 33
    *   TCP/22: 23

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
    *   CVE-2024-4577 CVE-2002-0953
    *   CVE-2024-4577 CVE-2024-4577
    *   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
    *   CVE-2021-42013 CVE-2021-42013
    *   CVE-2019-11500 CVE-2019-11500
    *   CVE-2021-3449 CVE-2021-3449
    *   CVE-2024-3721 CVE-2024-3721
    *   CVE-2005-4050

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh
    *   lockr -ia .ssh
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
    *   cat /proc/cpuinfo | grep name | wc -l
    *   Enter new UNIX password:
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
    *   ls -lh $(which ls)
    *   which ls
    *   crontab -l
    *   w
    *   uname -m
    *   cat /proc/cpuinfo | grep model | grep name | wc -l
    *   top
    *   uname
    *   uname -a
    *   whoami
    *   lscpu | grep Model
    *   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1960
    *   2024766: 1960
    *   ET DROP Dshield Block Listed Source group 1: 369
    *   2402000: 369
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 263
    *   2023753: 263
    *   ET SCAN NMAP -sS window 1024: 168
    *   2009582: 168
    *   ET HUNTING RDP Authentication Bypass Attempt: 88
    *   2034857: 88
    *   ET INFO Reserved Internal IP Traffic: 61
    *   2002752: 61
    *   ET SCAN Suspicious inbound to MSSQL port 1433: 43
    *   2010935: 43
    *   ET SCAN Potential SSH Scan: 28
    *   2001219: 28
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 14
    *   2400040: 14
    *   ET SCAN Suspicious inbound to Oracle SQL port 1521: 9
    *   2010936: 9

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 17
    *   deploy/1234: 5
    *   user01/Password01: 8
    *   root/aA123456: 4
    *   esroot/esroot: 4
    *   gitlab/gitlab: 4
    *   apache/apache123: 4
    *   root/P@ssw0rd: 4
    *   root/!qaz@WSX: 4
    *   user/user: 4
    *   root/acessoATV12: 4
    *   user1/user1: 4
    *   hadoop/hadoop: 4
    *   root/p@ssword: 4
    *   root/Ab123456: 4
    *   oscar/oscar123: 4
    *   root/1qaz@wsx: 4
    *   root/P@ssword: 4
    *   root/qQ123456: 4
    *   flink/flink: 4

*   **Files Uploaded/Downloaded:**
    *   sh: 98
    *   arm.urbotnetisass;: 3
    *   arm.urbotnetisass: 3
    *   arm5.urbotnetisass;: 3
    *   arm5.urbotnetisass: 3
    *   arm6.urbotnetisass;: 3
    *   arm6.urbotnetisass: 3
    *   arm7.urbotnetisass;: 3
    *   arm7.urbotnetisass: 3
    *   x86_32.urbotnetisass;: 3
    *   x86_32.urbotnetisass: 3
    *   mips.urbotnetisass;: 3
    *   mips.urbotnetisass: 3
    *   mipsel.urbotnetisass;: 3
    *   mipsel.urbotnetisass: 3
    *   ): 1

*   **HTTP User-Agents:**
    *   None

*   **SSH Clients:**
    *   None

*   **SSH Servers:**
    *   None

*   **Top Attacker AS Organizations:**
    *   None

**Key Observations and Anomalies**

*   The high number of attacks on TCP port 445 (SMB) and the prevalence of the DoublePulsar signature suggest ongoing automated exploitation attempts targeting Windows systems.
*   The commands executed by attackers indicate a clear pattern of attempting to disable security measures (`chattr`), install SSH keys for persistence, and perform system reconnaissance.
*   The "urbotnetisass" malware family was observed being downloaded, indicating an active campaign to compromise IoT devices.
*   The absence of HTTP User-Agents, SSH clients, and server software information suggests that the attacks were primarily low-level and did not involve more sophisticated interaction with the honeypots.
*   The high volume of attacks from a small number of IP addresses suggests that these are likely compromised systems or servers being used for malicious activities.

This concludes the Honeypot Attack Summary Report.
