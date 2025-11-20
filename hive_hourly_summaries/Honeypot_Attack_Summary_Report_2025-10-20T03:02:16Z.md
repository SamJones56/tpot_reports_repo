Honeypot Attack Summary Report

Report generated on 2025-10-20T03:01:42Z for the last 6 minutes of activity.
Files used to generate this report: agg_log_20251020T022001Z.json, agg_log_20251020T024001Z.json, agg_log_20251020T030001Z.json

Executive Summary

This report summarizes 8931 attacks recorded by the honeypot network. The majority of attacks were detected by the Suricata, Cowrie, and Honeytrap honeypots. The most targeted service was SMB on TCP port 445, followed by SSH on port 22. A significant number of attacks originated from IP addresses 61.152.89.39 and 14.0.17.77, which were responsible for a large volume of SMB exploit attempts. Multiple CVEs were targeted, with a high occurrence of the DoublePulsar backdoor installation.

Detailed Analysis

Attacks by honeypot:
- Suricata: 3553
- Cowrie: 3007
- Honeytrap: 1502
- Ciscoasa: 492
- Sentrypeer: 114
- Dionaea: 65
- Tanner: 59
- H0neytr4p: 45
- Mailoney: 35
- ConPot: 30
- Adbhoney: 11
- Redishoneypot: 11
- Ipphoney: 3
- Dicompot: 3
- Honeyaml: 1

Top attacking IPs:
- 61.152.89.39
- 14.0.17.77
- 72.146.232.13
- 36.66.16.233
- 203.190.53.154
- 8.217.43.4
- 36.50.54.8
- 43.173.120.195
- 118.193.38.97
- 187.16.96.250

Top targeted ports/protocols:
- TCP/445
- 22
- 8333
- 5060

Most common CVEs:
- CVE-2001-0414
- CVE-2002-0953
- CVE-2016-20016
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-41773
- CVE-2021-42013
- CVE-2024-4577

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- echo -e "Password01\nDBNqPY9bGbKg\nDBNqPY9bGbKg"|passwd|bash
- echo "Password01\nDBNqPY9bGbKg\nDBNqPY9bGbKg\n"|passwd

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET SCAN Potential SSH Scan
- ET SCAN Suspicious inbound to MSSQL port 1433

Users / login attempts:
- 345gs5662d34/345gs5662d34
- user01/Password01
- root/9820086
- root/aini1314520
- x/x123
- bender/123
- root/server@1
- wahid/3245gs5662d34
- root/987249129
- develop/123
- root/987654
- eugene/1234
- lighthouse/lighthouse123
- root/9942fab
- readonly/readonly123
- root/MoeClub.org
- root/99453878
- postgres/postgres@2025
- root/HuaWei@123

Files uploaded/downloaded:
- sh
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

HTTP User-Agents:
- N/A

SSH clients:
- N/A

SSH servers:
- N/A

Top attacker AS organizations:
- N/A

Key Observations and Anomalies

- The high number of attacks on port 445 (SMB) and the triggering of the DoublePulsar backdoor signature suggest a coordinated campaign targeting Windows systems.
- Attackers are attempting to download and execute malicious binaries, as seen in the `files_uploaded_downloaded` and `commands` sections, with a focus on IoT devices (arm, mips architectures).
- A common tactic observed is the attempt to add an SSH key to the authorized_keys file for persistent access.
- There are no observed attacks using HTTP or targeting SSH clients/servers in this period.
- The lack of AS organization data might indicate that the IP addresses are not associated with well-known organizations or that the geolocation data is not available.
