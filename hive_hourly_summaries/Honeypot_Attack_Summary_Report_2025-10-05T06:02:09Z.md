Honeypot Attack Summary Report

Report Generation Time: 2025-10-05T06:01:42Z
Timeframe: 2025-10-05T05:20:01Z to 2025-10-05T06:00:01Z
Files Used: agg_log_20251005T052001Z.json, agg_log_20251005T054001Z.json, agg_log_20251005T060001Z.json

Executive Summary
This report summarizes 12,451 malicious events captured by the honeypot network. The majority of attacks were detected by the Suricata honeypot, with a significant number of events also captured by Cowrie and Honeytrap. The most frequent attacks were SMB exploits targeting TCP port 445, likely related to the DoublePulsar backdoor. A wide range of CVEs were targeted, with CVE-2005-4050 being the most common.

Detailed Analysis:

Attacks by honeypot:
- Suricata: 4448
- Cowrie: 3034
- Honeytrap: 1625
- Ciscoasa: 1543
- Mailoney: 874
- Sentrypeer: 553
- Tanner: 150
- Dionaea: 72
- H0neytr4p: 60
- Adbhoney: 21
- Redishoneypot: 21
- Miniprint: 18
- Heralding: 16
- Honeyaml: 12
- ElasticPot: 4

Top attacking IPs:
- 193.239.25.171
- 113.45.38.160
- 196.251.88.103
- 176.65.141.117
- 50.6.225.98
- 172.86.95.98
- 125.17.108.32
- 198.12.68.114

Top targeted ports/protocols:
- TCP/445
- 25
- 22
- 5060
- TCP/5900
- 80
- UDP/5060
- TCP/80

Most common CVEs:
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0517
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2024-3721 CVE-2024-3721

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- uname -s -v -n -r -m
- cat /proc/cpuinfo | grep name | wc -l
- whoami
- uname -a

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- 2400040
- ET SCAN NMAP -sS window 1024
- 2009582

Users / login attempts:
- sa/!@#$%^&*()
- sa/
- root/Hannan@123
- wang/wang
- elasticsearch/elasticsearch
- docker/docker123
- root/passwd
- app/app
- root/1q2w3e4r
- root/root@123

Files uploaded/downloaded:
- sh
- Help:Contents
- a>

HTTP User-Agents:
- No user agents recorded in this period.

SSH clients and servers:
- No SSH clients or servers recorded in this period.

Top attacker AS organizations:
- No AS organizations recorded in this period.

Key Observations and Anomalies
- The high number of SMB exploits suggests a targeted campaign against Windows systems, possibly by a botnet.
- The variety of CVEs targeted indicates that attackers are attempting to exploit a wide range of vulnerabilities.
- The commands attempted by attackers show a clear pattern of reconnaissance and attempts to establish persistent access.
- The lack of HTTP user agents, SSH clients/servers, and AS organization data may indicate that the attacks were primarily automated and did not involve more sophisticated actors.
