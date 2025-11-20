**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-20T14:01:25Z
*   **Timeframe:** 2025-10-20T13:20:01Z to 2025-10-20T14:00:01Z
*   **Files:** `agg_log_20251020T132001Z.json`, `agg_log_20251020T134001Z.json`, `agg_log_20251020T140001Z.json`

**Executive Summary**

This report summarizes 18,148 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Honeytrap, Cowrie, and Suricata honeypots. A significant amount of activity originated from IP address `193.22.146.182` and targeted port `22`. Several CVEs were detected, with `CVE-2002-0013` and `CVE-2002-0012` being the most frequent. Attackers attempted a variety of commands, including reconnaissance and attempts to add SSH keys.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Honeytrap: 8918
    *   Cowrie: 6613
    *   Suricata: 1642
    *   Sentrypeer: 411
    *   Dionaea: 119
    *   Miniprint: 76
    *   Redishoneypot: 90
    *   Mailoney: 85
    *   Tanner: 46
    *   H0neytr4p: 32
    *   Ciscoasa: 28
    *   Dicompot: 27
    *   Adbhoney: 20
    *   ConPot: 17
    *   ElasticPot: 7
    *   Honeyaml: 9
    *   Ipphoney: 5
    *   Heralding: 3

*   **Top Attacking IPs:**
    *   `193.22.146.182`: 1976
    *   `45.134.20.151`: 2438
    *   `192.171.62.226`: 1149
    *   `72.146.232.13`: 1224
    *   `213.109.67.90`: 550
    *   `167.172.107.20`: 273
    *   `192.3.105.24`: 283
    *   `37.120.247.198`: 263
    *   `185.243.5.158`: 298
    *   `202.91.35.236`: 210

*   **Top Targeted Ports/Protocols:**
    *   `5038`: 2439
    *   `22`: 1242
    *   `5060`: 411
    *   `4444`: 164
    *   `5903`: 227
    *   `9100`: 76
    *   `8333`: 141
    *   `6379`: 90
    *   `5901`: 113
    *   `25`: 85

*   **Most Common CVEs:**
    *   `CVE-2002-0013 CVE-2002-0012`: 13
    *   `CVE-2019-11500 CVE-2019-11500`: 9
    *   `CVE-2002-0013 CVE-2002-0012 CVE-1999-0517`: 7
    *   `CVE-2021-3449 CVE-2021-3449`: 6
    *   `CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051`: 2
    *   `CVE-2024-12847 CVE-2024-12847`: 1
    *   `CVE-2023-52163 CVE-2023-52163`: 1
    *   `CVE-2023-31983 CVE-2023-31983`: 1
    *   `CVE-2024-10914 CVE-2024-10914`: 1
    *   `CVE-2009-2765`: 1
    *   `CVE-2024-3721 CVE-2024-3721`: 1
    *   `CVE-2006-3602 CVE-2006-4458 CVE-2006-4542`: 1
    *   `CVE-2018-7600 CVE-2018-7600`: 1
    *   `CVE-2006-2369`: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 22
    *   `lockr -ia .ssh`: 22
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo ...`: 22
    *   `cat /proc/cpuinfo | grep name | wc -l`: 22
    *   `Enter new UNIX password: `: 19
    *   `Enter new UNIX password:`: 19
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 22
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 22
    *   `ls -lh $(which ls)`: 22
    *   `which ls`: 22

*   **Signatures Triggered:**
    *   `ET DROP Dshield Block Listed Source group 1`: 483
    *   `2402000`: 483
    *   `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 231
    *   `2023753`: 231
    *   `ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system`: 164
    *   `2008953`: 164
    *   `ET SCAN NMAP -sS window 1024`: 181
    *   `2009582`: 181
    *   `ET HUNTING RDP Authentication Bypass Attempt`: 67
    *   `2034857`: 67

*   **Users / Login Attempts:**
    *   `345gs5662d34/345gs5662d34`: 20
    *   `user01/Password01`: 11
    *   `deploy/123123`: 9
    *   `root/adm...`: 15 (various)
    *   `deploy/password123`: 2
    *   `support/99999`: 2
    *   `root/adminHW`: 2
    *   `erpnext/welcome1`: 2
    *   `manasa/123`: 2

*   **Files Uploaded/Downloaded:**
    *   `)`: 1
    *   `arm.urbotnetisass;`: 2
    *   `arm.urbotnetisass`: 2
    *   `arm5.urbotnetisass;`: 2
    *   `arm5.urbotnetisass`: 2
    *   `arm6.urbotnetisass;`: 2
    *   `arm6.urbotnetisass`: 2
    *   `arm7.urbotnetisass;`: 2
    *   `arm7.urbotnetisass`: 2
    *   `x86_32.urbotnetisass;`: 2
    *   `x86_32.urbotnetisass`: 2
    *   `mips.urbotnetisass;`: 2
    *   `mips.urbotnetisass`: 2
    *   `mipsel.urbotnetisass;`: 2
    *   `mipsel.urbotnetisass`: 2

*   **HTTP User-Agents:** (None Observed)
*   **SSH Clients:** (None Observed)
*   **SSH Servers:** (None Observed)
*   **Top Attacker AS Organizations:** (None Observed)

**Key Observations and Anomalies**

*   The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a clear attempt to install a persistent SSH key for backdoor access.
*   The downloaded files with the `.urbotnetisass` extension suggest an attempt to install a botnet client.
*   The high volume of traffic from a small number of IPs suggests targeted attacks rather than random scanning.

This concludes the Honeypot Attack Summary Report.