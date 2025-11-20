Honeypot Attack Summary Report
Report generated on 2025-10-03T02:01:31Z for the timeframe of 2025-10-03T01:20:01Z to 2025-10-03T02:00:02Z.
Files used to generate this report:
- agg_log_20251003T012001Z.json
- agg_log_20251003T014001Z.json
- agg_log_20251003T020002Z.json

Executive Summary:
This report summarizes 19282 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Suricata, and Dionaea honeypots. The most frequently attacked ports were TCP/445 and 5060. A number of CVEs were detected, including CVE-2024-4577, CVE-2021-41773, CVE-2021-42013, CVE-2019-11500, CVE-2006-2369, and CVE-2002-0953. Attackers attempted various commands, primarily related to enumeration and establishing remote access via SSH.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 5192
- Suricata: 4512
- Dionaea: 3209
- Ciscoasa: 2728
- Sentrypeer: 1602
- Honeytrap: 995
- Mailoney: 867
- Tanner: 66
- H0neytr4p: 47
- ElasticPot: 23
- Dicompot: 12
- Adbhoney: 10
- Honeyaml: 10
- Redishoneypot: 3
- ConPot: 3

Top Attacking IPs:
- 113.161.22.87: 3147
- 40.134.34.145: 1377
- 103.155.105.206: 1436
- 23.175.48.211: 1251
- 176.65.141.117: 820
- 49.207.240.113: 444
- 123.58.213.52: 442
- 88.210.63.16: 393
- 185.156.73.166: 361
- 92.63.197.55: 356
- 39.109.116.40: 360
- 92.63.197.59: 320
- 181.188.172.6: 318
- 52.187.61.159: 217
- 36.77.220.197: 217
- 147.93.189.166: 212
- 213.142.151.19: 159
- 197.5.145.73: 192
- 172.245.45.194: 133
- 43.138.59.170: 185

Top Targeted Ports/Protocols:
- TCP/445: 4204
- 445: 3167
- 5060: 1602
- 25: 867
- 22: 595
- TCP/22: 34
- 80: 70
- TCP/80: 50
- 443: 47
- TCP/443: 32
- 23: 38
- 9200: 21
- TCP/1080: 20
- TCP/8443: 8
- 2222: 8
- TCP/5432: 7
- 20000: 7
- 49154: 7
- 6000: 7
- UDP/53: 11

Most Common CVEs:
- CVE-2024-4577
- CVE-2021-41773
- CVE-2021-42013
- CVE-2019-11500
- CVE-2006-2369
- CVE-2002-0953

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 44
- lockr -ia .ssh: 44
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 44
- cat /proc/cpuinfo | grep name | wc -l: 38
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 38
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 38
- ls -lh $(which ls): 38
- which ls: 38
- crontab -l: 38
- w: 38
- uname -m: 38
- cat /proc/cpuinfo | grep model | grep name | wc -l: 38
- top: 38
- uname: 38
- whoami: 38
- lscpu | grep Model: 38
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 38
- uname -a: 41
- Enter new UNIX password: : 21
- Enter new UNIX password:: 21

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2800
- 2024766: 2800
- ET DROP Dshield Block Listed Source group 1: 377
- 2402000: 377
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 219
- 2023753: 219
- ET SCAN NMAP -sS window 1024: 163
- 2009582: 163
- ET HUNTING RDP Authentication Bypass Attempt: 106
- 2034857: 106
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 44
- 2010517: 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 38
- 2403342: 38
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 23
- 2403347: 23
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 11
- 2400027: 11

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 43
- root/3245gs5662d34: 19
- root/nPSpP4PBW0: 13
- root/LeitboGi0ro: 11
- foundry/foundry: 9
- test/zhbjETuyMffoL8F: 9
- marketing/marketing: 6
- root/2glehe5t24th1issZs: 5
- superadmin/admin123: 5
- seekcy/Joysuch@Locate2021: 3
- mustafa/mustafa123: 3
- bw/bw123: 3
- css/css: 3
- root/QAZwsx123.: 3
- ubuntu/123456789: 3
- ubuntu/3245gs5662d34: 3
- walter/walter123: 3
- seekcy/Joysuch@Locate2020: 3
- ubuntu/123456@: 3
- root/fa: 3

Files Uploaded/Downloaded:
- sh: 98
- a>: 27
- Help:Contents: 5
- 11: 3
- fonts.gstatic.com: 3
- css?family=Libre+Franklin...: 3
- ie8.css?ver=1.0: 3
- html5.js?ver=3.7.3: 3
- Mozi.m: 1
- soap-envelope: 1
- addressing: 1
- discovery: 1
- devprof: 1
- soap:Envelope>: 1

HTTP User-Agents:
- No HTTP User-Agents were logged in this timeframe.

SSH Clients:
- No SSH clients were logged in this timeframe.

SSH Servers:
- No SSH servers were logged in this timeframe.

Top Attacker AS Organizations:
- No attacker AS organizations were logged in this timeframe.

Key Observations and Anomalies:
- A significant number of attacks are leveraging the DoublePulsar backdoor, indicating a continued threat from this malware.
- The majority of commands executed by attackers are focused on reconnaissance and establishing persistent access. The repeated use of commands to manipulate SSH authorized_keys files is a key indicator of this.
- The credentials being used in brute-force attacks are a mix of common default passwords and more complex, potentially phished or leaked, credentials.
- The variety of honeypots that are being triggered indicates a broad spectrum of scanning and exploitation attempts against different services.
- The presence of `Mozi.m` in the downloaded files indicates activity related to IoT botnets.
