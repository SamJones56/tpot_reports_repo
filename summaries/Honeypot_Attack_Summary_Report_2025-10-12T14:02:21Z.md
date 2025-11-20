**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-12T14:01:39Z
*   **Timeframe:** 2025-10-12T13:20:01Z to 2025-10-12T14:00:01Z
*   **Files Used:**
    *   `agg_log_20251012T132001Z.json`
    *   `agg_log_20251012T134001Z.json`
    *   `agg_log_20251012T140001Z.json`

**Executive Summary**
This report summarizes 16,742 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was 192.171.62.226. The most targeted port was 5060/UDP (SIP). Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access via SSH authorized_keys.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 8737
    *   Honeytrap: 2505
    *   Ciscoasa: 1798
    *   Sentrypeer: 1772
    *   Suricata: 1326
    *   Dionaea: 258
    *   Miniprint: 111
    *   Mailoney: 92
    *   Tanner: 38
    *   ConPot: 24
    *   H0neytr4p: 22
    *   Dicompot: 18
    *   Honeyaml: 14
    *   Redishoneypot: 12
    *   Adbhoney: 9
    *   Heralding: 3
    *   Ipphoney: 2
    *   ElasticPot: 1

*   **Top Attacking IPs:**
    *   192.171.62.226: 1225
    *   45.128.199.212: 1027
    *   192.81.208.35: 489
    *   45.15.126.99: 410
    *   170.254.229.191: 361
    *   137.184.111.54: 356
    *   23.95.128.167: 351
    *   62.141.43.183: 325
    *   172.86.95.98: 293
    *   158.178.141.16: 288
    *   191.37.72.46: 288
    *   118.219.234.233: 282
    *   198.98.56.205: 262
    *   27.254.137.144: 258
    *   200.39.46.41: 233
    *   4.240.96.126: 228
    *   120.71.7.15: 225
    *   181.23.107.245: 188
    *   95.58.255.251: 184
    *   107.174.67.215: 179
    *   1.240.43.35: 158
    *   147.78.100.99: 145
    *   159.89.98.186: 129
    *   94.182.174.231: 128
    *   216.10.242.161: 123

*   **Top Targeted Ports/Protocols:**
    *   5060: 1772
    *   22: 1144
    *   5903: 188
    *   3306: 158
    *   1344: 121
    *   9100: 111
    *   5901: 109
    *   8333: 95
    *   25: 92
    *   445: 46
    *   80: 37
    *   TCP/445: 25

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012: 14
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
    *   CVE-2018-10562 CVE-2018-10561: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 50
    *   `lockr -ia .ssh`: 50
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 50
    *   `cat /proc/cpuinfo | grep name | wc -l`: 50
    *   `uname -a`: 50
    *   `whoami`: 50
    *   `Enter new UNIX password: `: 38
    *   `Enter new UNIX password:`: 36
    *   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 4
    *   `cd /data/local/tmp/; ...`: 1
    *   `tftp; wget; /bin/busybox LYNUY`: 1

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1: 523
    *   2402000: 523
    *   ET SCAN NMAP -sS window 1024: 188
    *   2009582: 188
    *   ET INFO Reserved Internal IP Traffic: 58
    *   2002752: 58
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 34
    *   2023753: 34
    *   ET INFO CURL User Agent: 28
    *   2002824: 28
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 25
    *   2024766: 25

*   **Users / Login Attempts:**
    *   root/: 158
    *   345gs5662d34/345gs5662d34: 49
    *   root/3245gs5662d34: 12
    *   debian/P@ssword: 6
    *   root/qwerty12: 6
    *   root/123qwe: 6
    *   blank/ubuntu: 6
    *   test/7777777: 6
    *   root/qwe123: 6

*   **Files Uploaded/Downloaded:**
    *   gpon80&ipv=0: 4
    *   arm.urbotnetisass;: 1
    *   arm.urbotnetisass: 1
    *   arm5.urbotnetisass;: 1
    *   arm5.urbotnetisass: 1
    *   arm6.urbotnetisass;: 1
    *   arm6.urbotnetisass: 1
    *   arm7.urbotnetisass;: 1
    *   arm7.urbotnetisass: 1
    *   x86_32.urbotnetisass;: 1
    *   x86_32.urbotnetisass: 1
    *   mips.urbotnetisass;: 1
    *   mips.urbotnetisass: 1
    *   mipsel.urbotnetisass;: 1
    *   mipsel.urbotnetisass: 1

*   **HTTP User-Agents:** (No data in logs)
*   **SSH Clients:** (No data in logs)
*   **SSH Servers:** (No data in logs)
*   **Top Attacker AS Organizations:** (No data in logs)

**Key Observations and Anomalies**
*   A significant number of commands are related to attackers attempting to add their SSH key to the `authorized_keys` file for persistent access. The specific key used ("...mdrfckr") is a known indicator of a botnet.
*   Multiple download attempts for various architectures (arm, arm5, arm6, arm7, x86_32, mips, mipsel) of a file named `urbotnetisass` were observed, suggesting a widespread campaign targeting IoT and embedded devices.
*   The IP address `192.171.62.226` showed a very high volume of activity in one of the log files but was not present in the others, indicating a burst of targeted activity.