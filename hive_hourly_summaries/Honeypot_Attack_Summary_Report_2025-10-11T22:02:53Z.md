
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T22:01:16Z
**Timeframe:** 2025-10-11T21:20:01Z to 2025-10-11T22:00:01Z
**Files Used:** agg_log_20251011T212001Z.json, agg_log_20251011T214001Z.json, agg_log_20251011T220001Z.json

## Executive Summary

This report summarizes honeypot activity over the past hour, based on logs from three separate 2-minute intervals. A total of 20513 attacks were recorded. The majority of attacks were against the Cowrie honeypot. The most active attacking IP was 185.144.27.63. A variety of CVEs were targeted, and numerous commands were attempted by attackers, primarily focused on reconnaissance and establishing persistence.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 13006, Honeytrap: 3823, Ciscoasa: 1796, Suricata: 1386, Dionaea: 89, Sentrypeer: 110, Mailoney: 114, Adbhoney: 58, ElasticPot: 51, Tanner: 27, H0neytr4p: 14, ConPot: 5, Redishoneypot: 23, Wordpot: 2, Honeyaml: 4, Dicompot: 3, ssh-rsa: 2

### Top Attacking IPs
- 185.144.27.63: 7286, 198.186.131.155: 1146, 45.128.199.212: 845, 45.78.199.107: 275, 180.106.83.59: 271, 147.45.50.147: 283, 144.126.204.2: 289, 85.209.134.43: 213, 27.111.32.174: 284, 115.190.9.96: 247

### Top Targeted Ports/Protocols
- 22: 2358, 5903: 190, 5038: 873, 25: 114, TCP/22: 76, 5060: 110, 8333: 95, 5909: 82, 5908: 82, 5901: 77

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 2, CVE-2019-11500 CVE-2019-11500: 2, CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2, CVE-2006-2369: 1

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 23, cd ~; chattr -ia .ssh; lockr -ia .ssh: 23, lockr -ia .ssh: 23, cat /proc/cpuinfo | grep model | grep name | wc -l: 19, cat /proc/cpuinfo | grep name | wc -l: 18, uname -m: 18, w: 18, crontab -l: 18, which ls: 18, ls -lh $(which ls): 18

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 429, 2402000: 429, ET SCAN NMAP -sS window 1024: 162, 2009582: 162, ET INFO Reserved Internal IP Traffic: 61, 2002752: 61, ET SCAN Potential SSH Scan: 50, 2001219: 50, ET SCAN MS Terminal Server Traffic on Non-standard Port: 47, 2023753: 47

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 22, root/qwe123!@#: 6, user/user12: 6, config/config33: 6, admin/password01!: 6, ubnt/p@ssw0rd: 6, root/abc@123: 6, root/378a@dmin: 4, root/root2023: 4, root/Sd@123: 4

### Files Uploaded/Downloaded
- i;: 12, pen.sh;: 4, wget.sh;: 4, arc.nn;: 3, arc.nn;cat: 3, x86.nn;: 3, x86.nn;cat: 3, x86_64.nn;: 3, x86_64.nn;cat: 3, i686.nn;: 3

### HTTP User-Agents
- No HTTP user-agents were recorded in this period.

### SSH Clients and Servers
- No SSH clients or servers were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

- A significant number of commands were aimed at gathering system information, such as CPU and memory details.
- Attackers frequently attempted to add their SSH keys to the `authorized_keys` file for persistent access.
- Several commands involved downloading and executing scripts from remote servers, indicating attempts to install malware or establish botnet clients.
- The IP address 185.144.27.63 was consistently the most active attacker across all three log files.
- The Cowrie honeypot was the most targeted, indicating a high volume of SSH-based attacks.
- A number of Suricata signatures were triggered, with "ET DROP Dshield Block Listed Source group 1" being the most common, indicating that many of the attacking IPs are on known blocklists.
