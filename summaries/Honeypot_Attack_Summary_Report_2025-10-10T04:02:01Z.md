Here is the consolidated Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-10T04:01:22Z
*   **Timeframe:** 2025-10-10T03:20:01Z to 2025-10-10T04:00:01Z
*   **Files Used:** `agg_log_20251010T032001Z.json`, `agg_log_20251010T034001Z.json`, `agg_log_20251010T040001Z.json`

**Executive Summary**

This report summarizes 15,359 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of attacks were also observed on the Honeytrap, Suricata, and Ciscoasa honeypots. The most prominent attack vector appears to be brute-force login attempts, with a large number of common and default credentials being tested. Several attackers also attempted to deploy cryptocurrency miners and other malware after gaining access.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 7078
    *   Honeytrap: 3200
    *   Suricata: 1899
    *   Ciscoasa: 1683
    *   Mailoney: 839
    *   Sentrypeer: 346
    *   Dionaea: 195
    *   ConPot: 34
    *   Redishoneypot: 23
    *   Heralding: 16
    *   Honeyaml: 16
    *   Tanner: 14
    *   H0neytr4p: 10
    *   ElasticPot: 2
    *   Adbhoney: 2
    *   Ipphoney: 2

*   **Top Attacking IPs:**
    *   167.250.224.25: 1221
    *   176.65.141.117: 820
    *   144.31.26.225: 441
    *   187.110.238.50: 356
    *   123.58.213.127: 354
    *   157.230.242.104: 302
    *   45.134.26.3: 279
    *   88.210.63.16: 275
    *   152.32.172.146: 199
    *   20.37.218.60: 159
    *   189.50.142.82: 158
    *   103.241.43.23: 174
    *   103.210.21.178: 189
    *   103.59.94.155: 169
    *   115.190.80.209: 159
    *   87.201.127.149: 169
    *   142.111.244.241: 134
    *   177.12.16.118: 131
    *   51.178.141.222: 129
    *   62.133.61.220: 129

*   **Top Targeted Ports/Protocols:**
    *   22: 1051
    *   25: 829
    *   5060: 346
    *   445: 201
    *   5903: 202
    *   UDP/161: 65
    *   TCP/445: 55
    *   3388: 83
    *   8333: 83
    *   5908: 85
    *   5909: 82
    *   5901: 74
    *   9093: 31
    *   54321: 26
    *   2181: 37
    *   6379: 17
    *   9090: 20
    *   postgresql/5432: 16
    *   5907: 48
    *   2103: 24

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012

*   **Commands Attempted by Attackers:**
    *   `uname -a`
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
    *   `which ls`
    *   `ls -lh $(which ls)`
    *   `crontab -l`
    *   `w`
    *   `uname -m`
    *   `cat /proc/cpuinfo | grep model | grep name | wc -l`
    *   `top`
    *   `uname`
    *   `whoami`
    *   `lscpu | grep Model`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
    *   `Enter new UNIX password:`

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET SCAN NMAP -sS window 1024
    *   GPL SNMP request udp
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   ET INFO Reserved Internal IP Traffic
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 42
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 44
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 48

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   gns3/gns3
    *   vpn/vpn
    *   default/letmein
    *   root/qazwsx123
    *   root/xsw!2025
    *   root/xsw.2025
    *   root/@xsw2025
    *   root/!xsw2025
    *   root/.xsw2025
    *   root/zxc12345
    *   ubuntu/3245gs5662d34
    *   admin/firewall
    *   operator/letmein

*   **Files Uploaded/Downloaded:**
    *   ?format=json
    *   11
    *   fonts.gstatic.com
    *   css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
    *   ie8.css?ver=1.0
    *   html5.js?ver=3.7.3
    *   bot.html)

*   **HTTP User-Agents:**
    *   *No user agents recorded in this timeframe.*

*   **SSH Clients:**
    *   *No SSH clients recorded in this timeframe.*

*   **SSH Servers:**
    *   *No SSH servers recorded in this timeframe.*

*   **Top Attacker AS Organizations:**
    *   *No AS organizations recorded in this timeframe.*

**Key Observations and Anomalies**

*   **High Volume of Cowrie Attacks:** The high number of attacks on the Cowrie honeypot suggests a widespread, automated campaign of SSH and Telnet brute-forcing.
*   **Repetitive Reconnaissance Commands:** Attackers consistently run a series of commands (`uname`, `lscpu`, `free`, etc.) to fingerprint the system. This is likely automated scripting to determine if the environment is suitable for deploying malware.
*   **SSH Key Manipulation:** The repeated attempts to modify `.ssh/authorized_keys` indicate a clear goal of establishing persistent access to the compromised machine.
*   **Mail Server Probing:** The significant number of attacks on the Mailoney honeypot, specifically targeting port 25, suggests that attackers are actively searching for open mail relays for spamming or other malicious purposes.
*   **Lack of Sophistication:** The majority of the observed attacks appear to be automated and unsophisticated, relying on common vulnerabilities and weak credentials. However, the sheer volume of these attacks presents a significant threat.

This concludes the Honeypot Attack Summary Report for this period. Continued monitoring is recommended.