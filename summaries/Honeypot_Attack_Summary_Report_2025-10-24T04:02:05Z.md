Honeypot Attack Summary Report

Report Generated: 2025-10-24T04:01:31Z
Timeframe: 2025-10-24T03:20:01Z to 2025-10-24T04:00:01Z
Log Files:
- agg_log_20251024T032001Z.json
- agg_log_20251024T034002Z.json
- agg_log_20251024T040001Z.json

Executive Summary:
This report summarizes 5390 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were detected by the Ciscoasa, Honeytrap, and Cowrie honeypots. The most prominent attack vector appears to be SSH, with a high number of login attempts and command executions. The top attacking IP, 80.94.95.238, was responsible for a significant portion of the traffic.

Detailed Analysis:

Attacks by honeypot:
- Ciscoasa: 1695
- Honeytrap: 1491
- Cowrie: 1255
- Suricata: 730
- Sentrypeer: 114
- Adbhoney: 38
- Redishoneypot: 11
- Dionaea: 17
- Dicompot: 9
- H0neytr4p: 12
- Tanner: 10
- Ipphoney: 4
- Honeyaml: 2
- Wordpot: 1
- ConPot: 1

Top attacking IPs:
- 80.94.95.238: 432
- 103.181.143.216: 218
- 103.250.10.217: 202
- 81.192.46.45: 208
- 168.227.224.196: 104
- 107.170.36.5: 146
- 167.172.43.167: 99
- 137.184.156.141: 81
- 68.183.149.135: 106
- 141.52.36.57: 85
- 185.243.5.144: 63
- 129.13.189.202: 62
- 167.250.224.25: 71
- 45.56.66.254: 44
- 177.253.57.111: 38
- 183.63.103.84: 45
- 134.209.158.3: 45
- 45.156.87.209: 39
- 2.57.121.112: 29
- 101.89.148.7: 26

Top targeted ports/protocols:
- 22: 164
- 8333: 149
- 5060: 114
- 5905: 74
- 5904: 72
- 5901: 42
- 5902: 36
- 5903: 36
- TCP/22: 28
- 2062: 51
- TCP/8080: 15
- 6379: 11
- 1024: 12
- 8092: 14
- 30080: 11

Most common CVEs:
- No CVEs were reported in this timeframe.

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- whoami
- Enter new UNIX password:
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
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- history | tail -5
- echo "root:V5BuFZs1OUuL"|chpasswd|bash
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- env | head -10
- uname -s -v -n -r -m
- echo -e "roundcube\\n1hLabjcs0ROd\\n1hLabjcs0ROd"|passwd|bash
- echo "roundcube\\n1hLabjcs0ROd\\n1hLabjcs0ROd\\n"|passwd

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- 2403342
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- 2403350
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- 2403349
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- 2403346
- ET INFO CURL User Agent
- 2002824
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- 2403343
- ET SCAN Potential SSH Scan
- 2001219
- ET DROP Spamhaus DROP Listed Traffic Inbound group 14
- 2400013
- ET CINS Active Threat Intelligence Poor Reputation IP group 84
- 2403383
- ET CINS Active Threat Intelligence Poor Reputation IP group 52
- 2403351
- ET CINS Active Threat Intelligence Poor Reputation IP group 14
- 2403313
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- 2400031
- ET DROP Spamhaus DROP Listed Traffic Inbound group 34
- 2400033
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- 2403341

Users / login attempts:
- 345gs5662d34/345gs5662d34
- tmpuser/tmpuser
- tmpuser/3245gs5662d34
- db2fenc1/db2fenc1
- db2fenc1/3245gs5662d34
- root/dany2004
- tpatel/tpatel123
- root/4444444
- akber/akber
- root/dare
- astra/astra
- root/444444
- root/Aa123456789!
- root/QWERzxcv1234
- django/1234
- dasha/dasha
- cambodia/cambodia
- cambodia/3245gs5662d34
- root/adminpass
- fiscal/fiscal123
- root/darklord13
- root/data
- root/r00t111
- sincroniza/sincroniza
- root/44444444
- root/234567
- root/Root@123!
- root/3245gs5662d34
- usuario/usuario123
- root/444444444
- apache/apache@123
- root/new@1234
- wsuser/wsuser
- intern/intern
- user/tntest@9527
- user/thyc@TEST2024
- user/thyc@2020
- user/test@yunwei.2021!
- rmg/rmg123
- root/Datab11
- root/datacom
- evita/evita
- ne/ne
- root/55
- tobia/tobia
- root/
- test/Admin123
- support/pass!
- root/abc1
- debian/1q2q3q4q5q6q
- user/tc191@123
- user/szly2024
- root/silvia
- user/szhot.com@2023
- user/surfilter@rzx
- user/surfilter@2018
- root/qaz@12345678
- nagios/nag1os
- vpn/123.com

Files uploaded/downloaded:
- ?format=json
- perl|perl

HTTP User-Agents:
- No HTTP user agents were reported in this timeframe.

SSH clients and servers:
- No SSH clients or servers were reported in this timeframe.

Top attacker AS organizations:
- No attacker AS organizations were reported in this timeframe.

Key Observations and Anomalies:
- A large number of commands are related to enumerating the system (`uname`, `lscpu`, `whoami`) and attempting to install a public SSH key in `authorized_keys`.
- The attacker at 137.184.112.170 attempted to download and execute a perl script.
- The command `echo "root:V5BuFZs1OUuL"|chpasswd|bash` suggests an attempt to change the root password.
- No CVEs were targeted, which is unusual. This could indicate that the attacks were opportunistic and not targeted at specific vulnerabilities.
- A wide variety of usernames and passwords were used, indicating a brute-force or credential stuffing attack.
- The most common signatures triggered are related to blocklisted IPs and port scanning, which is consistent with the observed activity.
- The honeypots that detected the most attacks were Ciscoasa, Honeytrap, and Cowrie, which suggests that attackers are targeting a wide range of services.
- There is a high volume of traffic on port 8333, which is the default port for Bitcoin.
- The activity on ports 5901-5905 indicates that VNC is also a target.
- The commands `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` are indicative of an attempt to remove competing malware and disable security measures.
- The command `echo -e "roundcube\\n1hLabjcs0ROd\\n1hLabjcs0ROd"|passwd|bash` is an attempt to change the password for the user `roundcube`.
- The command `chmod 0755 /data/local/tmp/nohup` and `chmod 0755 /data/local/tmp/log` are likely related to setting up a persistent backdoor on Android devices.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a clear attempt to install a public key for persistent access.

This concludes the Honeypot Attack Summary Report.
