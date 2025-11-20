Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T10:01:33Z
**Timeframe:** 2025-09-30T09:20:01Z to 2025-09-30T10:00:01Z
**Files Used:**
- agg_log_20250930T092001Z.json
- agg_log_20250930T094001Z.json
- agg_log_20250930T100001Z.json

**Executive Summary**

This report summarizes 16,136 malicious events targeting the honeypot infrastructure over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. A significant number of events were also logged by Sentrypeer and Honeytrap. The most prominent attack vector appears to be automated scripts attempting to gain initial access and perform system reconnaissance. Several CVEs were targeted, with a focus on older vulnerabilities.

**Detailed Analysis**

***Attacks by honeypot:***
- Cowrie: 8,374
- Honeytrap: 2,554
- Sentrypeer: 1,811
- Suricata: 1,590
- Ciscoasa: 1,450
- Heralding: 106
- Dionaea: 42
- Miniprint: 39
- Mailoney: 48
- H0neytr4p: 33
- ConPot: 27
- Adbhoney: 22
- Redishoneypot: 17
- Tanner: 17
- ElasticPot: 4
- Wordpot: 1
- Honeyaml: 1

***Top attacking IPs:***
- 129.212.189.55
- 194.50.16.131
- 118.194.230.211
- 45.10.175.246
- 43.225.158.169
- 185.156.73.166
- 185.156.73.167
- 92.63.197.55
- 92.63.197.59
- 34.80.91.161
- 5.141.80.212
- 109.206.241.199
- 177.75.160.94
- 94.102.4.12
- 14.103.41.249
- 45.78.192.214
- 112.165.151.121
- 209.38.21.236
- 14.152.66.29
- 34.77.62.170

***Top targeted ports/protocols:***
- 5060
- 22
- 8333
- 23
- TCP/1080
- TCP/22
- 25
- 9100
- 443
- 8888
- UDP/53
- 80
- socks5/1080
- 8090
- 3001
- 27018
- 10801
- 27017
- 29092
- 8085

***Most common CVEs:***
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-1999-0183

***Commands attempted by attackers:***
- uname -s -v -n -r -m
- cat /proc/cpuinfo | grep name | wc -l
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
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

***Signatures triggered:***
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- GPL INFO SOCKS Proxy attempt
- 2100615
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- 2403346
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- 2403347
- ET CINS Active Threat Intelligence Poor Reputation IP group 40
- 2403339
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- 2400031
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO CURL User Agent
- 2002824

***Users / login attempts:***
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/nPSpP4PBW0
- root/root123
- foundry/foundry
- ftp/ftp123
- oscar/oscar
- root/Aa123456
- root/Ac123456
- user/user
- nginx/nginx123
- root/!QAZ2wsx
- root/toor
- root/1Q2w3e4r
- postgres/postgres123
- test/test123
- root/1234567890
- nexus/nexus
- root/12345
- superadmin/admin123

***Files uploaded/downloaded:***
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

***HTTP User-Agents:***
- No user agents were recorded in this timeframe.

***SSH clients and servers:***
- No specific SSH clients or servers were identified in this timeframe.

***Top attacker AS organizations:***
- No AS organizations were identified in this timeframe.

**Key Observations and Anomalies**

- A large number of commands are focused on system reconnaissance, such as checking CPU information, memory, and running processes.
- A recurring command involves manipulating the `.ssh/authorized_keys` file, indicating a common tactic to establish persistent access.
- Attackers attempted to download and execute multiple versions of the `urbotnetisass` malware, targeting various architectures (ARM, x86, MIPS), which is indicative of an automated, widespread campaign.
- The most frequently triggered Suricata signature is related to the Dshield Block List, suggesting that many attacking IPs are known bad actors.
- There is a high volume of brute-force attempts with common and default credentials, as seen in the login attempts list.
- A significant number of attacks on port 5060 (SIP) were observed, primarily captured by the Sentrypeer honeypot. This suggests a focus on VoIP-related vulnerabilities.
