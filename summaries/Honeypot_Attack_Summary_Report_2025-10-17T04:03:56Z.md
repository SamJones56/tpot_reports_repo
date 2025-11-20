Honeypot Attack Summary Report
Report Generation Time: 2025-10-17T04:02:33Z
Files Used to Generate Report:
- agg_log_20251017T032002Z.json
- agg_log_20251017T034001Z.json
- agg_log_20251017T040001Z.json

Executive Summary
A total of 14091 attacks were detected across the honeypot network in the last 6 minutes. The most targeted honeypot was Cowrie, a medium and high interaction SSH and Telnet honeypot. The majority of attacks originated from a diverse set of IP addresses, with a significant concentration from a few specific IPs. Attackers primarily targeted ports 5060 (SIP), 22 (SSH), and 445 (SMB). Several CVEs were exploited, and a variety of commands were executed on the compromised systems, indicating a mix of automated and manual attack techniques. No significant data exfiltration was observed.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 4844
- Honeytrap: 3035
- Suricata: 1549
- Ciscoasa: 1570
- Sentrypeer: 1277
- Mailoney: 1055
- Dionaea: 460
- Wordpot: 151
- H0neytr4p: 25
- Dicompot: 27
- Tanner: 35
- ConPot: 26
- Redishoneypot: 16
- Honeyaml: 14
- ElasticPot: 4
- Adbhoney: 2
- Ipphoney: 1

Top attacking IPs:
- 143.198.96.196
- 176.65.141.119
- 172.86.95.115
- 172.86.95.98
- 113.167.129.176
- 212.19.117.204
- 107.170.36.5
- 185.233.3.95
- 125.63.66.38
- 103.171.84.20

Top targeted ports/protocols:
- 5060
- 22
- 25
- 445
- 5903
- 80
- 8333
- 23
- 5901
- TCP/445

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2001-0414
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2009-2765
- CVE-2019-11500 CVE-2019-11500

Commands attempted by attackers:
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- lockr -ia .ssh
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- uname
- top
- cat /proc/cpuinfo | grep model | grep name | wc -l

Signatures triggered:
- 2402000
- ET DROP Dshield Block Listed Source group 1
- 2009582
- ET SCAN NMAP -sS window 1024
- 2023753
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2002752
- ET INFO Reserved Internal IP Traffic
- 2024766
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication

Users / login attempts:
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/123@@@
- root/Qaz123qaz
- root/P@ssw0rd
- debian/debian2018
- operator/operator2022
- ftpuser/ftppassword
- unknown/unknown2022
- root/

Files uploaded/downloaded:
- ?format=json
- nse.html)
- Mozi.m
- )

HTTP User-Agents:
- No HTTP User-Agents were logged in this period.

SSH clients:
- No SSH clients were logged in this period.

SSH servers:
- No SSH servers were logged in this period.

Top attacker AS organizations:
- No attacker AS organizations were logged in this period.

Key Observations and Anomalies
- A large number of commands related to disabling security measures and setting up SSH keys were observed, indicating that attackers are attempting to establish persistent access to the compromised systems.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was executed multiple times, which is a clear indicator of an attempt to install a backdoor.
- The presence of `Mozi.m` in the uploaded files suggests activity from the Mozi botnet.
- The high number of attacks on port 5060 (SIP) suggests a focus on VoIP-related targets.
