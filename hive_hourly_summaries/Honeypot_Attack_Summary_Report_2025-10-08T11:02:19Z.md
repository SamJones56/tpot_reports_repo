**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-08T11:01:40Z
*   **Timeframe:** Approximately 2025-10-08T10:20:01Z to 2025-10-08T11:00:01Z
*   **Files Used:**
    *   `agg_log_20251008T102001Z.json`
    *   `agg_log_20251008T104001Z.json`
    *   `agg_log_20251008T110001Z.json`

**Executive Summary**

This report summarizes 12,750 recorded events across the honeypot network. The majority of attacks were captured by the Cowrie, Mailoney, and Honeytrap honeypots. The most frequent attacks originated from IP address `209.38.91.18`. The most targeted port was port 25 (SMTP). A number of CVEs were detected, with `CVE-2002-0013 CVE-2002-0012` being the most common. A variety of commands were attempted, with a significant number of reconnaissance and remote access commands.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 4763
    *   Mailoney: 2542
    *   Honeytrap: 2024
    *   Ciscoasa: 1656
    *   Suricata: 1109
    *   Dionaea: 208
    *   H0neytr4p: 114
    *   Sentrypeer: 167
    *   Redishoneypot: 77
    *   Tanner: 27
    *   ConPot: 23
    *   Adbhoney: 19
    *   Honeyaml: 10
    *   Miniprint: 8
    *   ElasticPot: 3

*   **Top Attacking IPs:**
    *   209.38.91.18: 1533
    *   86.54.42.238: 1641
    *   176.65.141.117: 820
    *   51.68.199.166: 179
    *   87.3.152.245: 288
    *   2.50.100.172: 228
    *   103.249.84.18: 297
    *   4.240.96.126: 233
    *   85.215.65.189: 179
    *   145.224.75.214: 204
    *   23.88.43.131: 109
    *   82.112.238.153: 105
    *   106.12.173.59: 97
    *   103.186.0.19: 96
    *   90.169.216.25: 89
    *   59.144.223.126: 84
    *   45.94.31.135: 78
    *   111.180.193.6: 115
    *   68.183.207.213: 94
    *   107.170.36.5: 97

*   **Top Targeted Ports/Protocols:**
    *   25: 2542
    *   22: 731
    *   5060: 167
    *   37777: 117
    *   3306: 110
    *   443: 103
    *   5903: 93
    *   6379: 77
    *   5901: 85
    *   TCP/22: 61
    *   5909: 49
    *   5908: 49
    *   5907: 48
    *   UDP/161: 28
    *   9093: 54
    *   445: 48
    *   23: 52
    *   8333: 25
    *   27017: 14
    *   9600: 20

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012: 17
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 13
    *   CVE-2021-3449 CVE-2021-3449: 7
    *   CVE-2019-11500 CVE-2019-11500: 6
    *   CVE-2021-35394 CVE-2021-35394: 1

*   **Commands Attempted by Attackers:** (Top 10)
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 21
    *   `lockr -ia .ssh`: 21
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 21
    *   `cat /proc/cpuinfo | grep name | wc -l`: 18
    *   `Enter new UNIX password: `: 18
    *   `Enter new UNIX password:`: 18
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 18
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 18
    *   `ls -lh $(which ls)`: 18
    *   `which ls`: 18

*   **Signatures Triggered:** (Top 10)
    *   ET DROP Dshield Block Listed Source group 1: 301
    *   2402000: 301
    *   ET SCAN NMAP -sS window 1024: 151
    *   2009582: 151
    *   ET INFO Reserved Internal IP Traffic: 58
    *   2002752: 58
    *   ET SCAN Potential SSH Scan: 41
    *   2001219: 41
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 21
    *   2023753: 21

*   **Users / Login Attempts:** (Top 10)
    *   appuser/: 104
    *   345gs5662d34/345gs5662d34: 19
    *   supervisor/techsupport: 6
    *   sysadmin/sysadmin@1: 8
    *   ubuntu/3245gs5662d34: 6
    *   ubnt/ubnt55: 6
    *   Support/Support2007: 6
    *   supervisor/toor: 6
    *   guest/guest66: 6
    *   default/default: 4

*   **Files Uploaded/Downloaded:**
    *   wget.sh;: 4
    *   w.sh;: 3
    *   c.sh;: 3
    *   parm;: 6
    *   parm5;: 6
    *   parm6;: 6
    *   parm7;: 6
    *   psh4;: 6
    *   parc;: 6
    *   pmips;: 6
    *   pmipsel;: 6
    *   psparc;: 6
    *   px86_64;: 6
    *   pi686;: 6
    *   pi586;: 6
    *   boatnet.mpsl;: 1

*   **HTTP User-Agents:** (No data)
*   **SSH Clients:** (No data)
*   **SSH Servers:** (No data)
*   **Top Attacker AS Organizations:** (No data)

**Key Observations and Anomalies**

*   A significant amount of reconnaissance and credential stuffing activity was observed, particularly against SSH (port 22) and SMTP (port 25) services.
*   The commands attempted by attackers indicate a focus on establishing persistent access, gathering system information, and disabling security measures. The recurring command to modify `.ssh/authorized_keys` is a clear indicator of this.
*   The variety of files downloaded suggests attackers are attempting to deploy various malware payloads, possibly for different system architectures.
*   The high number of events from the `appuser/` login attempt suggests a targeted or automated attack against a specific application or default credential.