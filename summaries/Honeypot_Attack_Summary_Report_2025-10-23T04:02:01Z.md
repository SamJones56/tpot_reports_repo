Honeypot Attack Summary Report
Report Generated: 2025-10-23T04:01:33Z
Timeframe: 2025-10-23T03:20:01Z to 2025-10-23T04:00:01Z
Files used to generate this report:
- agg_log_20251023T032001Z.json
- agg_log_20251023T034001Z.json
- agg_log_20251023T040001Z.json

Executive Summary:
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 18,317 attacks were recorded. The most active honeypots were Honeytrap, Cowrie, and Suricata. The most frequent attacker IP was 109.205.211.9. The most targeted port was 5060/UDP (SIP). Several CVEs were observed, with CVE-2002-0013 and CVE-2002-0012 being the most common. A significant number of shell commands were attempted, primarily related to establishing SSH access and reconnaissance.

Detailed Analysis:

Attacks by honeypot:
- Honeytrap: 5761
- Cowrie: 5087
- Suricata: 3525
- Dionaea: 1068
- Ciscoasa: 1735
- Sentrypeer: 977
- Tanner: 52
- Mailoney: 34
- ConPot: 19
- Redishoneypot: 25
- H0neytr4p: 20
- ElasticPot: 3
- Honeyaml: 3
- Wordpot: 1
- Dicompot: 3
- Ipphoney: 2
- Adbhoney: 2

Top attacking IPs:
- 109.205.211.9: 2360
- 180.232.204.50: 1025
- 62.3.42.68: 336
- 204.44.127.231: 336
- 86.102.131.54: 356
- 123.58.212.133: 251
- 179.190.103.164: 257
- 188.166.248.139: 287
- 107.170.36.5: 242
- 185.243.5.146: 223
- 211.201.163.70: 169
- 216.155.93.75: 218
- 43.157.169.99: 188
- 103.164.63.144: 208
- 107.173.10.71: 266
- 203.228.30.198: 163
- 67.220.72.44: 268
- 113.228.109.76: 180
- 103.172.236.15: 119
- 103.187.147.214: 119

Top targeted ports/protocols:
- 5060: 977
- 22: 607
- 445: 1034
- 23: 126
- 1024-1062 (various): 890
- 5901-5909 (various): 336
- 8333: 76
- 6379: 16
- 25: 34
- 80: 45
- TCP/80: 10
- TCP/445: 52
- UDP/161: 43

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 26
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 21
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2024-3721 CVE-2024-3721: 2

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 30
- lockr -ia .ssh: 30
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 30
- cat /proc/cpuinfo | grep name | wc -l: 30
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 30
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 30
- ls -lh $(which ls): 30
- which ls: 30
- crontab -l: 30
- w: 30
- uname -m: 30
- cat /proc/cpuinfo | grep model | grep name | wc -l: 30
- top: 30
- uname: 30
- uname -a: 26
- whoami: 26
- lscpu | grep Model: 30
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 30
- Enter new UNIX password: : 19
- Enter new UNIX password::: 19

Signatures triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1432
- 2023753: 1432
- ET HUNTING RDP Authentication Bypass Attempt: 675
- 2034857: 675
- ET DROP Dshield Block Listed Source group 1: 500
- 2402000: 500
- ET SCAN NMAP -sS window 1024: 173
- 2009582: 173
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 11
- 2403344: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
- 2403346: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 20
- 2403347: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 9
- 2403343: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 8
- 2403349: 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 13
- 2400027: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 12
- 2403345: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 13: 10
- 2403312: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 10
- 2403342: 10
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 52
- 2024766: 52
- GPL SNMP request udp: 21
- 2101417: 21
- GPL SNMP public access udp: 19
- 2101411: 19
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake: 13
- 2010908: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 12
- 2403348: 12

Users / login attempts:
- 345gs5662d34/345gs5662d34: 30
- root/3245gs5662d34: 10
- root/cashout: 3
- root/casona83: 4
- root/cbcbankadmin1: 4
- root/cbi1212--: 4
- root/bismillah1: 3
- root/Admin123: 2
- user/suporte: 2
- root/brian123: 2
- ainhoa/ainhoa: 2
- root/222: 2
- sa/: 4
- dsg/dsg: 3
- syncUser/syncUser: 3
- moodle/moodle@123: 2
- dsg/3245gs5662d34: 2
- thu/thu: 2
- sammy/1: 2
- raka/raka: 2

Files uploaded/downloaded:
- discovery: 2
- ?format=json: 2
- soap-envelope: 1
- soap-encoding: 1
- addressing: 1
- a:ReplyTo><a:To: 1
- wsdl: 1
- ): 1

HTTP User-Agents:
- None

SSH clients and servers:
- SSH Clients: None
- SSH Servers: None

Top attacker AS organizations:
- None

Key Observations and Anomalies:
- A large number of commands executed are related to establishing a persistent SSH connection by adding a public key to `authorized_keys`.
- The IP address 109.205.211.9 was consistently the most active attacker across all three log files.
- The targeting of port 445 (SMB) by a single IP (180.232.204.50) accounted for a significant portion of the total attacks in the last log file.
- The CVEs observed are relatively old, suggesting that attackers are targeting unpatched or legacy systems.
- The lack of HTTP User-Agents, SSH clients/servers and AS organization data suggests that these fields are not being populated by the honeypots that are currently most active.
