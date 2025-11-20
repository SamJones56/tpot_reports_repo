Honeypot Attack Summary Report

Report generated on: 2025-10-28T12:01:32Z
Timeframe of logs: 2025-10-28T11:20:01Z to 2025-10-28T12:00:01Z
Files used to generate this report:
- agg_log_20251028T112001Z.json
- agg_log_20251028T114002Z.json
- agg_log_20251028T120001Z.json

Executive Summary

This report summarizes 13,873 events collected from the T-Pot honeypot network over approximately 40 minutes. The majority of attacks were detected by the Suricata, Honeytrap, and Cowrie honeypots. A significant portion of the traffic involved SMB probes, likely related to the DoublePulsar backdoor, as evidenced by the most frequently triggered Suricata signature. Attackers were observed attempting to gain access via SSH, with numerous login attempts and commands aimed at adding their own SSH keys to the system.

Detailed Analysis

Attacks by honeypot:
- Honeytrap: 4196
- Suricata: 3774
- Cowrie: 2743
- Ciscoasa: 1906
- Sentrypeer: 974
- Mailoney: 92
- Dionaea: 58
- Adbhoney: 45
- H0neytr4p: 29
- ConPot: 22
- Redishoneypot: 15
- Tanner: 12
- ElasticPot: 3
- Dicompot: 3
- Ipphoney: 1

Top attacking IPs:
- 103.208.200.170: 1381
- 170.155.12.1: 1350
- 45.134.26.20: 1001
- 144.172.108.231: 705
- 45.134.26.62: 500
- 45.140.17.144: 500
- 45.130.202.25: 498
- 152.32.254.184: 352
- 205.185.115.224: 283
- 161.132.49.155: 252

Top targeted ports/protocols:
- TCP/445: 2778
- 5060: 974
- 5038: 498
- 22: 351
- 5901: 273
- 8333: 155
- TCP/22: 77
- 25: 92
- 5902: 38
- 5903: 64

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2025-57819 CVE-2025-57819
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- w
- top

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2771
- ET DROP Dshield Block Listed Source group 1: 270
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 134
- ET SCAN NMAP -sS window 1024: 133
- ET HUNTING RDP Authentication Bypass Attempt: 37
- ET INFO Reserved Internal IP Traffic: 49

Users / login attempts:
- 345gs5662d34/345gs5662d34
- atl/P@ssw0rd123
- root/kyrollos.farah
- admin/tazdevil
- root/ay123456
- efrain/efrain
- cs/1q2w3e4r
- root/KzOgPzushW
- alin/alin

Files uploaded/downloaded:
- wget.sh;
- w.sh;
- c.sh;

HTTP User-Agents:
- None observed

SSH clients and servers:
- None observed

Top attacker AS organizations:
- None observed

Key Observations and Anomalies

- The high number of events related to the DoublePulsar backdoor (indicated by the top Suricata signature) suggests a continued threat from legacy malware.
- The commands attempted on the Cowrie honeypot show a clear pattern of attackers trying to secure their access by adding their own SSH keys.
- A wide variety of usernames and passwords were used, indicating that attackers are using large dictionaries of credentials.
- The downloaded files (wget.sh, w.sh, c.sh) suggest that attackers are attempting to download and execute malicious scripts on compromised systems.
- Despite the high volume of traffic, no successful breaches of the honeypots were observed.
