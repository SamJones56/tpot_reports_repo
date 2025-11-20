Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02 00:05:00 UTC
**Timeframe:** 2025-10-01 23:20:01 UTC to 2025-10-02 00:00:02 UTC
**Files Used:** agg_log_20251001T232001Z.json, agg_log_20251001T234001Z.json, agg_log_20251002T000002Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 23,850 attacks were recorded across various honeypots. The most targeted services were SMB (port 445), SSH (port 22), and SMTP (port 25). The majority of attacks originated from a small number of IP addresses, with 103.130.215.15 being the most prolific attacker. A number of CVEs were targeted, and attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

*   **Attacks by honeypot:**
    *   Cowrie: 9114
    *   Honeytrap: 5792
    *   Dionaea: 4035
    *   Suricata: 1606
    *   Mailoney: 1653
    *   Ciscoasa: 1398
    *   Adbhoney: 70
    *   Tanner: 46
    *   Sentrypeer: 39
    *   Redishoneypot: 38
    *   H0neytr4p: 24
    *   ConPot: 19
    *   ElasticPot: 6
    *   Honeyaml: 5
    *   Dicompot: 3
    *   ssh-rsa: 2

*   **Top attacking IPs:**
    *   103.130.215.15: 5368
    *   171.102.83.142: 3914
    *   103.220.207.174: 3555
    *   176.65.141.117: 1640
    *   178.128.152.40: 461
    *   209.38.35.67: 457
    *   34.58.124.191: 391
    *   185.156.73.167: 361
    *   27.71.230.3: 357
    *   92.63.197.55: 356
    *   88.210.63.16: 345
    *   103.76.120.70: 347
    *   92.63.197.59: 324
    *   118.193.43.244: 312
    *   104.168.101.178: 189
    *   87.106.36.193: 153
    *   140.249.22.89: 154
    *   103.144.87.192: 145
    *   216.10.242.161: 129
    *   80.66.88.30: 39
    *   202.151.185.199: 38
    *   196.251.84.140: 38
    *   3.131.215.38: 47

*   **Top targeted ports/protocols:**
    *   445: 3961
    *   25: 1653
    *   22: 1558
    *   8333: 171
    *   5901: 64
    *   80: 47
    *   TCP/22: 41
    *   5060: 39
    *   TCP/5432: 38
    *   6379: 32
    *   TCP/445: 32
    *   3306: 26
    *   TCP/80: 22
    *   TCP/1433: 20
    *   443: 16
    *   4443: 16
    *   7443: 14
    *   10003: 14
    *   1433: 12
    *   3790: 12
    *   UDP/5060: 11

*   **Most common CVEs:**
    *   CVE-2019-11500
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-1999-0517
    *   CVE-2021-35394
    *   CVE-2017-7577

*   **Commands attempted by attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh
    *   lockr -ia .ssh
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "...key..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
    *   cat /proc/cpuinfo | grep name | wc -l
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
    *   which ls
    *   ls -lh $(which ls)
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
    *   Enter new UNIX password:

*   **Signatures triggered:**
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 286
    *   ET DROP Dshield Block Listed Source group 1: 250
    *   ET SCAN NMAP -sS window 1024: 163
    *   ET HUNTING RDP Authentication Bypass Attempt: 107
    *   ET INFO Reserved Internal IP Traffic: 54
    *   ET SCAN Suspicious inbound to PostgreSQL port 5432: 32
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 31
    *   ET SCAN Potential SSH Scan: 23
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 45: 26
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 14
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 22
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 25

*   **Users / login attempts:**
    *   openser/: 30
    *   345gs5662d34/345gs5662d34: 20
    *   root/nPSpP4PBW0: 7
    *   test/zhbjETuyMffoL8F: 6
    *   root/LeitboGi0ro: 6
    *   root/2glehe5t24th1issZs: 6
    *   foundry/foundry: 5
    *   root/asdf;lkj: 4
    *   bitwarden/bitwarden123: 3
    *   foundry/3245gs5662d34: 3
    *   superadmin/admin123: 3
    *   root/gD.123345: 3
    *   root/PAssw0rd: 3
    *   root/3245gs5662d34: 2
    *   root/Zhouxingyu$2019: 2
    *   worker/worker: 2
    *   vinay/vinay: 2
    *   vinay/3245gs5662d34: 2
    *   teamtalk/teamtalk: 2
    *   root/: 2
    *   pam/pam123: 2
    *   bitwarden/3245gs5662d34: 2
    *   username/111: 2
    *   username/3245gs5662d34: 2
    *   root/Huawei@1234: 2
    *   fmanager/fmanager123: 2
    *   root/Abc123123: 2
    *   dmdba/dmdba2024: 2
    *   akash/akash123: 2
    *   root/My123456@: 2
    *   root/Root@111: 2
    *   lrendon/lrendon123: 2
    *   geoserver/geoserver: 2
    *   deploybot/deploybot: 2
    *   anonymous/: 2
    *   scsadmin/scsadmin123: 2
    *   ubuntu/12345: 2
    *   gmodserver/gmodserver123: 2
    *   this/this123: 2
    *   root/Cloud123: 2
    *   root/qazwsx123...: 2
    *   root/Zz123123: 2
    *   mine/mine: 2
    *   5/5123: 2
    *   5/3245gs5662d34: 2
    *   erika/erika123: 2
    *   root/123@123a: 2
    *   dev/qwer1234: 2
    *   old/sor123in: 2

*   **Files uploaded/downloaded:**
    *   wget.sh;: 8
    *   Mozi.m: 4
    *   Space.mips;: 2
    *   w.sh;: 2
    *   c.sh;: 2
    *   arm.urbotnetisass;: 4
    *   arm.urbotnetisass: 4
    *   arm5.urbotnetisass;: 4
    *   arm5.urbotnetisass: 4
    *   arm6.urbotnetisass;: 4
    *   arm6.urbotnetisass: 4
    *   arm7.urbotnetisass;: 4
    *   arm7.urbotnetisass: 4
    *   x86_32.urbotnetisass;: 4
    *   x86_32.urbotnetisass: 4
    *   mips.urbotnetisass;: 4
    *   mips.urbotnetisass: 4
    *   mipsel.urbotnetisass;: 4
    *   mipsel.urbotnetisass: 4

*   **HTTP User-Agents:**
    *   None observed.

*   **SSH clients and servers:**
    *   None observed.

*   **Top attacker AS organizations:**
    *   None observed.

**Key Observations and Anomalies**

*   The high volume of attacks from a few IP addresses suggests targeted or automated scanning campaigns.
*   The commands attempted indicate a focus on establishing persistent access through SSH authorized_keys and reconnaissance of the system.
*   The variety of usernames and passwords attempted suggests brute-force attacks using common or previously breached credentials.
*   The downloading and execution of `.sh` and other executable files indicate attempts to install malware or other malicious tools.
*   The "urbotnetisass" and "Mozi.m" filenames suggest activity related to specific botnets.
*   The presence of CVEs from as far back as 1999 suggests that attackers are still attempting to exploit old, well-known vulnerabilities.
