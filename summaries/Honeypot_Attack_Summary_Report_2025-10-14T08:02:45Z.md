Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T08:01:39Z
**Timeframe:** 2025-10-14T07:20:01Z to 2025-10-14T08:00:01Z
**Files Used:** `agg_log_20251014T072001Z.json`, `agg_log_20251014T074001Z.json`, `agg_log_20251014T080001Z.json`

**Executive Summary**

This report summarizes 19,470 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Sentrypeer honeypots. The most frequent attacks originated from IP address `206.191.154.180`. The primary targeted port was `5060` (SIP), followed by port `25` (SMTP) and `445` (SMB). Several CVEs were detected, with `CVE-2005-4050` being the most common. Attackers attempted a variety of commands, including reconnaissance and attempts to install malware.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 5333
    *   Honeytrap: 4829
    *   Sentrypeer: 3345
    *   Suricata: 1917
    *   Ciscoasa: 1792
    *   Dionaea: 929
    *   Mailoney: 920
    *   Heralding: 121
    *   ConPot: 109
    *   H0neytr4p: 60
    *   Tanner: 29
    *   Miniprint: 21
    *   Adbhoney: 23
    *   Redishoneypot: 12
    *   ElasticPot: 11
    *   Ipphoney: 9
    *   Honeyaml: 7
    *   Dicompot: 3

*   **Top Attacking IPs:**
    *   `206.191.154.180`: 1414
    *   `185.243.5.146`: 1230
    *   `157.245.101.239`: 1190
    *   `185.243.5.148`: 822
    *   `176.65.141.119`: 821
    *   `42.119.232.181`: 807
    *   `45.236.188.4`: 615
    *   `172.86.95.98`: 411
    *   `172.86.95.115`: 400
    *   `104.244.74.84`: 372
    *   `78.187.21.105`: 372
    *   `62.141.43.183`: 322
    *   `77.105.182.78`: 302
    *   `46.32.178.186`: 268
    *   `88.210.63.16`: 257
    *   `114.225.60.53`: 228
    *   `163.47.34.82`: 227
    *   `150.230.252.188`: 213
    *   `196.251.115.80`: 195
    *   `210.245.54.206`: 179

*   **Top Targeted Ports/Protocols:**
    *   `5060`: 3345
    *   `25`: 920
    *   `445`: 860
    *   `22`: 859
    *   `5903`: 193
    *   `TCP/1080`: 132
    *   `1459`: 78
    *   `5908`: 83
    *   `5909`: 82
    *   `UDP/5060`: 69
    *   `5901`: 75
    *   `1433`: 52
    *   `TCP/22`: 49
    *   `5907`: 48
    *   `443`: 52
    *   `8333`: 34
    *   `socks5/1080`: 105
    *   `50100`: 108

*   **Most Common CVEs:**
    *   `CVE-2005-4050`: 65
    *   `CVE-2002-0013 CVE-2002-0012`: 3
    *   `CVE-2019-11500 CVE-2019-11500`: 2
    *   `CVE-2021-35394 CVE-2021-35394`: 1
    *   `CVE-2023-26801 CVE-2023-26801`: 1
    *   `CVE-2002-0013 CVE-2002-0012 CVE-1999-0517`: 1
    *   `CVE-2006-2369`: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 17
    *   `lockr -ia .ssh`: 17
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo ...`: 17
    *   `cat /proc/cpuinfo | grep name | wc -l`: 17
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk ...`: 17
    *   `free -m | grep Mem | awk ...`: 17
    *   `ls -lh $(which ls)`: 17
    *   `which ls`: 17
    *   `crontab -l`: 17
    *   `w`: 17
    *   `uname -m`: 17
    *   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 17
    *   `top`: 17
    *   `uname`: 17
    *   `uname -a`: 17
    *   `whoami`: 17
    *   `lscpu | grep Model`: 17
    *   `df -h | head -n 2 | awk ...`: 17
    *   `Enter new UNIX password: `: 15
    *   `Enter new UNIX password:`: 15

*   **Signatures Triggered:**
    *   `ET DROP Dshield Block Listed Source group 1`: 521
    *   `2402000`: 521
    *   `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 198
    *   `2023753`: 198
    *   `ET SCAN NMAP -sS window 1024`: 166
    *   `2009582`: 166
    *   `GPL INFO SOCKS Proxy attempt`: 129
    *   `2100615`: 129
    *   `ET HUNTING RDP Authentication Bypass Attempt`: 73
    *   `2034857`: 73
    *   `ET VOIP MultiTech SIP UDP Overflow`: 65
    *   `2003237`: 65
    *   `ET INFO Reserved Internal IP Traffic`: 55
    *   `2002752`: 55
    *   `ET SCAN Potential SSH Scan`: 37
    *   `2001219`: 37
    *   `ET SCAN Suspicious inbound to MSSQL port 1433`: 22
    *   `2010935`: 22

*   **Users / Login Attempts:**
    *   `345gs5662d34/345gs5662d34`: 15
    *   `nobody/123abc`: 6
    *   `test/4444444`: 6
    *   `test/test2025`: 6
    *   `guest/44444`: 6
    *   `admin/888`: 6
    *   `test/777`: 6
    *   `root/Admin159`: 4
    *   `centos/33`: 4
    *   `test/3`: 4
    *   `root/123@@@`: 4
    *   `root/admin159`: 4
    *   `blank/1111`: 4
    *   `root/Password@2025`: 4
    *   `root/alberto20x21`: 4
    *   `root/Qaz123qaz`: 4
    *   `root/nqe138f`: 4
    *   `nobody/0000`: 4
    *   `test/Passw@rd`: 4
    *   `default/000`: 4

*   **Files Uploaded/Downloaded:**
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
    *   `1.sh;`: 4
    *   `wget.sh;`: 4
    *   `shadow.mips;`: 3
    *   `boatnet.mpsl;`: 1
    *   `w.sh;`: 1
    *   `c.sh;`: 1

*   **HTTP User-Agents:** (No data)
*   **SSH Clients:** (No data)
*   **SSH Servers:** (No data)
*   **Top Attacker AS Organizations:** (No data)

**Key Observations and Anomalies**

*   A significant number of attacks are automated and appear to be part of large-scale scanning campaigns.
*   The commands executed suggest attempts to gather system information and prepare the system for malware installation. The recurring command to modify `.ssh/authorized_keys` is a common technique to establish persistent access.
*   The `urbotnetisass` and `shadow.mips` files appear to be related to botnet activity, targeting various architectures (ARM, x86, MIPS).
*   The Suricata signatures for "Dshield Block Listed Source" and "MS Terminal Server Traffic on Non-standard Port" are the most frequently triggered, indicating a high volume of traffic from known malicious IPs and scans for RDP services.
