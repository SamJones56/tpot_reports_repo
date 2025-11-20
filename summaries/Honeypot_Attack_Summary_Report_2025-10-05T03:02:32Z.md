**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-05T03:01:56Z
*   **Timeframe:** 2025-10-05T02:20:01Z to 2025-10-05T03:00:01Z
*   **Files Used:**
    *   `agg_log_20251005T022001Z.json`
    *   `agg_log_20251005T024002Z.json`
    *   `agg_log_20251005T030001Z.json`

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 13,653 events were recorded across various honeypots. The most targeted services were SSH (Cowrie) and email (Mailoney). A significant number of attacks originated from a small number of IP addresses, with `176.65.141.117` being the most prominent. The most common attack vector appears to be brute-force login attempts, with a large number of username/password combinations being tested. Several CVEs were also targeted, with `CVE-2005-4050` being the most frequent.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 6498
    *   Mailoney: 2468
    *   Ciscoasa: 1481
    *   Suricata: 1422
    *   Honeytrap: 959
    *   Sentrypeer: 539
    *   H0neytr4p: 76
    *   Dionaea: 68
    *   Miniprint: 39
    *   Honeyaml: 27
    *   ConPot: 26
    *   Dicompot: 17
    *   Tanner: 9
    *   Adbhoney: 9
    *   Redishoneypot: 6
    *   Ipphoney: 6
    *   ElasticPot: 3

*   **Top Attacking IPs:**
    *   176.65.141.117: 1640
    *   83.168.107.46: 904
    *   86.54.42.238: 793
    *   116.110.10.13: 451
    *   171.231.194.120: 386
    *   170.64.185.131: 382
    *   103.48.84.20: 309
    *   172.86.95.98: 284
    *   175.6.37.135: 217
    *   43.155.14.27: 195

*   **Top Targeted Ports/Protocols:**
    *   25: 2468
    *   22: 990
    *   5060: 539
    *   443: 76
    *   TCP/22: 54
    *   UDP/5060: 61
    *   9100: 39
    *   80: 26
    *   23: 28

*   **Most Common CVEs:**
    *   CVE-2005-4050: 56
    *   CVE-2021-3449 CVE-2021-3449: 7
    *   CVE-2019-11500 CVE-2019-11500: 6
    *   CVE-2002-0013 CVE-2002-0012: 4
    *   CVE-2024-3721 CVE-2024-3721: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 40
    *   `lockr -ia .ssh`: 40
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 40
    *   `uname -a`: 19
    *   `Enter new UNIX password: `: 18
    *   `Enter new UNIX password:`: 18
    *   `cat /proc/cpuinfo | grep name | wc -l`: 26
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 26
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 26
    *   `ls -lh $(which ls)`: 26
    *   `which ls`: 26
    *   `crontab -l`: 26
    *   `w`: 26
    *   `uname -m`: 26
    *   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 26
    *   `top`: 26
    *   `uname`: 26
    *   `whoami`: 26
    *   `lscpu | grep Model`: 26
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 26
    *   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 2
    *   `echo "root:tLh8NktDx35c"|chpasswd|bash`: 1

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1: 489
    *   2402000: 489
    *   ET SCAN NMAP -sS window 1024: 110
    *   2009582: 110
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 84
    *   2023753: 84
    *   ET VOIP MultiTech SIP UDP Overflow: 56
    *   2003237: 56
    *   ET INFO Reserved Internal IP Traffic: 51
    *   2002752: 51

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 35
    *   root/nPSpP4PBW0: 13
    *   test/zhbjETuyMffoL8F: 10
    *   root/3245gs5662d34: 8
    *   novinhost/novinhost.org: 9
    *   root/2glehe5t24th1issZs: 8
    *   test/3245gs5662d34: 7
    *   root/LeitboGi0ro: 6

*   **Files Uploaded/Downloaded:**
    *   wget.sh;: 4
    *   w.sh;: 1
    *   c.sh;: 1

*   **HTTP User-Agents:**
    *   Not observed in the logs.

*   **SSH Clients and Servers:**
    *   Not observed in the logs.

*   **Top Attacker AS Organizations:**
    *   Not observed in the logs.

**Key Observations and Anomalies**

*   The high volume of attacks from a single IP (`176.65.141.117`) suggests a targeted attack or a botnet.
*   The commands attempted by attackers indicate a focus on establishing persistent access and gathering system information. The repeated use of commands to modify SSH authorized_keys is particularly noteworthy.
*   The presence of the command `rm -rf /data/local/tmp; ...` suggests attempts to compromise Android devices (ADBHoney).
*   The variety of usernames and passwords used in login attempts indicates a brute-force approach, likely using common password lists.
