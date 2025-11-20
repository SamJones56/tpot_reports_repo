Honeypot Attack Summary Report

Report Generated: 2025-10-22T16:01:34Z
Timeframe: 2025-10-22T15:20:01Z to 2025-10-22T16:00:02Z
Files: agg_log_20251022T152001Z.json, agg_log_20251022T154001Z.json, agg_log_20251022T160002Z.json

Executive Summary:
This report summarizes 16,808 events collected from the honeypot network. The majority of attacks were SIP protocol scans targeting port 5060, primarily from the IP address 2.57.121.61. A significant number of SMB probes on port 445 were also observed. Attackers attempted to exploit several vulnerabilities, with CVE-2021-44228 (Log4Shell) being the most frequent. A variety of shell commands were executed, indicating attempts to establish persistence and gather system information.

Detailed Analysis:

Attacks by Honeypot:
- Sentrypeer: 9149
- Cowrie: 2149
- Honeytrap: 1365
- Dionaea: 1295
- Ciscoasa: 1159
- Suricata: 865
- Mailoney: 222
- Heralding: 179
- H0neytr4p: 76
- Redishoneypot: 64
- Tanner: 53
- Adbhoney: 12
- Honeyaml: 9
- ConPot: 3
- ElasticPot: 2

Top Attacking IPs:
- 2.57.121.61
- 182.8.161.75
- 116.196.106.74
- 176.65.141.119
- 74.243.236.86
- 124.226.219.166
- 185.156.174.178
- 185.243.5.146
- 107.170.36.5
- 202.157.177.161

Top Targeted Ports/Protocols:
- 5060
- 445
- 22
- 25
- vnc/5900
- 8333
- 5903
- TCP/21
- 6379
- TCP/80

Most Common CVEs:
- CVE-2021-44228
- CVE-2016-20016
- CVE-2021-3449
- CVE-2019-11500
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
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

Signatures Triggered:
- ET INFO VNC Authentication Failure
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET FTP FTP CWD command attempt without login
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET FTP FTP PWD command attempt without login
- ET INFO Reserved Internal IP Traffic
- ET EXPLOIT MVPower DVR Shell UCE
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- root/BroqueVille249
- root/brremoto
- root/brs333
- root/brU5ujEC
- postgres/postgres
- root/bsadrv28091977
- openproject/openproject
- fsf/fsf
- jack/1234
- root/!Q2w3e4r
- redis/1qaz2wsx
- root/Windows1
- test/test
- thiago/thiago
- admin/adm1
- gpadmin/gpadmin

Files Uploaded/Downloaded:
- null+2>&1
- shadow.x86_64
- shadow.x86
- shadow.arm64
- shadow.arm7
- shadow.arm6
- shadow.arm5
- shadow.arm
- shadow.mips
- shadow.mipsel
- shadow.ppc
- shadow.sparc
- shadow.m68k
- shadow.sh4
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

HTTP User-Agents:
- No user agents were logged in this timeframe.

SSH Clients and Servers:
- No SSH clients or servers were logged in this timeframe.

Top Attacker AS Organizations:
- No AS organizations were logged in this timeframe.

Key Observations and Anomalies:
- The overwhelming majority of events are from a single IP (2.57.121.61) targeting the SIP port 5060, suggesting a large-scale automated scan for VoIP servers.
- A significant number of commands are related to establishing SSH persistence by adding a public key to `authorized_keys`.
- The variety of architectures in the downloaded `shadow` files indicates that attackers are attempting to compromise a wide range of devices.
- The presence of VNC, RDP, and FTP signatures suggests that attackers are also scanning for remote access and file transfer services.
