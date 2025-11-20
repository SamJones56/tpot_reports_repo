Honeypot Attack Summary Report

Report Generated: 2025-10-17T09:01:30Z
Timeframe: 2025-10-17T08:20:01Z to 2025-10-17T09:00:02Z
Files used in this report:
- agg_log_20251017T082001Z.json
- agg_log_20251017T084001Z.json
- agg_log_20251017T090002Z.json

Executive Summary

This report summarizes 29,053 attacks recorded by honeypots between 08:20 and 09:00 UTC on October 17, 2025. The majority of attacks were intercepted by the Sentrypeer, Dionaea, and Cowrie honeypots. The most prominent attacker IP was 23.94.26.58, and the most targeted port was 5060. Attackers attempted to exploit several vulnerabilities, with CVE-2021-3449, CVE-2019-11500, CVE-2006-2369, CVE-2002-0013, CVE-2002-0012, and CVE-2001-0414 being the most common. A number of commands were attempted, many of which were aimed at reconnaissance and establishing persistence.

Detailed Analysis

Attacks by honeypot:
- Sentrypeer: 14509
- Dionaea: 4922
- Cowrie: 4112
- Honeytrap: 2637
- Suricata: 1339
- Ciscoasa: 1062
- Wordpot: 193
- Mailoney: 62
- Miniprint: 61
- Tanner: 60
- ElasticPot: 34
- Redishoneypot: 31
- Dicompot: 6
- ConPot: 6
- H0neytr4p: 6
- Honeyaml: 6
- Adbhoney: 4
- Ipphoney: 2
- Heralding: 1

Top attacking IPs:
- 23.94.26.58: 13672
- 14.234.243.121: 3101
- 77.90.185.47: 1534
- 193.193.249.106: 916
- 45.140.17.52: 355
- 88.214.50.58: 388
- 47.100.58.160: 328
- 172.86.95.115: 338
- 172.86.95.98: 322
- 103.88.76.27: 203
- 83.150.218.116: 226
- 91.107.118.186: 228
- 103.49.238.51: 240
- 119.42.59.197: 217
- 107.170.36.5: 168
- 159.223.210.164: 115
- 4.224.36.103: 103
- 154.83.15.92: 110
- 103.136.106.84: 92
- 5.182.83.231: 98
- 181.49.8.57: 79
- 45.7.171.18: 79
- 162.214.211.246: 79
- 162.214.92.14: 79
- 62.164.177.28: 75
- 34.93.128.179: 105
- 68.183.149.135: 68
- 167.250.224.25: 37
- 103.136.106.117: 64
- 123.58.209.112: 34

Top targeted ports/protocols:
- 5060: 14509
- 445: 4020
- 3306: 328
- 22: 578
- 80: 255
- 23: 133
- 5903: 154
- TCP/21: 153
- 9100: 61
- 8333: 110
- 21: 82
- 5901: 80
- 1026: 36
- 9200: 34
- 25: 65
- 6379: 22
- 2181: 37
- 5905: 51
- 5904: 52
- 5908: 34
- 8880: 17
- 5909: 33
- 5907: 33

Most common CVEs:
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2006-2369: 1
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2001-0414: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 16
- lockr -ia .ssh: 16
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr": 16
- cat /proc/cpuinfo | grep name | wc -l: 16
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 16
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 16
- ls -lh $(which ls): 16
- which ls: 16
- crontab -l: 16
- w: 16
- uname -m: 16
- cat /proc/cpuinfo | grep model | grep name | wc -l: 16
- top: 16
- uname: 16
- uname -a: 16
- whoami: 16
- lscpu | grep Model: 16
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 16
- Enter new UNIX password: : 11
- Enter new UNIX password:: 9
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 3

Signatures triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 270
- ET DROP Dshield Block Listed Source group 1: 255
- ET HUNTING RDP Authentication Bypass Attempt: 122
- ET SCAN NMAP -sS window 1024: 99
- ET FTP FTP PWD command attempt without login: 77
- ET FTP FTP CWD command attempt without login: 76
- ET INFO Reserved Internal IP Traffic: 37
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 15
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 22
- GPL INFO SOCKS Proxy attempt: 15
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 11

Users / login attempts:
- root/: 328
- 345gs5662d34/345gs5662d34: 14
- debian/444: 6
- guest/guest2021: 6
- guest/33333: 6
- blank/qwerty123456: 6
- user/qwer1234: 5
- ubnt/ubnt2007: 4
- root/10Tecnicos: 4
- debian/debian2002: 4
- root/7777: 4
- support/4: 4
- root/11084036703leo: 4
- root/3245gs5662d34: 3
- user/qwert12345: 3
- sa/: 3
- sybase/sybase: 3
- sybase/3245gs5662d34: 3

Files uploaded/downloaded:
- soap-envelope: 1
- addressing: 1
- discovery: 1
- devprof: 1
- soap:Envelope>: 1

HTTP User-Agents:
- (No user agents recorded in this period)

SSH clients:
- (No SSH clients recorded in this period)

SSH servers:
- (No SSH servers recorded in this period)

Top attacker AS organizations:
- (No AS organizations recorded in this period)

Key Observations and Anomalies

- The overwhelming number of attacks on port 5060, all attributed to the Sentrypeer honeypot, suggests a targeted campaign against VoIP infrastructure.
- The IP address 23.94.26.58 was responsible for a significant portion of the total attack volume, indicating a single, highly active threat actor or a large botnet.
- The commands executed by attackers are consistent with initial reconnaissance and attempts to secure access to the compromised system by adding an SSH key to `authorized_keys`.
- The variety of credentials used in brute-force attempts suggests that attackers are using common and default username/password lists.
- A small number of files were uploaded, primarily related to SOAP web services, which could indicate scanning for vulnerabilities in web applications or APIs.
