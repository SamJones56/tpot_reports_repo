# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T01:01:30Z
**Timeframe:** 2025-10-22T00:20:01Z to 2025-10-22T01:00:01Z
**Files Used:**
- agg_log_20251022T002001Z.json
- agg_log_20251022T004001Z.json
- agg_log_20251022T010001Z.json

## Executive Summary

This report summarizes 7,648 attacks recorded by the honeypot network. The majority of attacks were captured by the Honeytrap, Cowrie, and Ciscoasa honeypots. The most frequent attacks targeted SSH (port 22) and SIP (port 5060). A high volume of attacks originated from the IP address 72.146.232.13. Several commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Honeytrap:** 2255
- **Cowrie:** 2095
- **Ciscoasa:** 1724
- **Suricata:** 1072
- **Sentrypeer:** 228
- **Tanner:** 91
- **Mailoney:** 81
- **Dionaea:** 48
- **Adbhoney:** 20
- **ConPot:** 12
- **H0neytr4p:** 12
- **Redishoneypot:** 6
- **ElasticPot:** 3
- **Wordpot:** 1

### Top Attacking IPs
- 72.146.232.13
- 64.225.67.101
- 107.170.36.5
- 41.214.61.216
- 152.42.216.249
- 194.107.115.11
- 182.18.161.232
- 130.33.50.71
- 88.210.63.16
- 68.183.149.135

### Top Targeted Ports/Protocols
- 22
- 5060
- 5903
- 80
- 25
- 5901
- 5905
- 5904
- 7443

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
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
- cat /proc/uptime 2 > /dev/null | cut -d. -f1
- echo -e "123\n8ZCifaWqFPI2\n8ZCifaWqFPI2"|passwd|bash
- Enter new UNIX password:
- echo "123\n8ZCifaWqFPI2\n8ZCifaWqFPI2\n"|passwd

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752

### Users / Login Attempts
- root/Ay21056
- root/Ayam123456abc
- root/Admin!!!
- root/aym1983
- packer/123
- vncuser/123
- root/banana123
- root/opera
- root/temp1234
- md/md
- sa/
- ems/123
- 345gs5662d34/345gs5662d34
- ems/3245gs5662d34
- demo/demo!@#
- james/james
- user12/123
- admin/princess
- pam/pam
- fleek/123
- root/az09sx12b
- root/Azar123
- root/gavriel
- root/123123
- root/abc123
- root/password1
- ventas01/ventas01
- root/admin123
- root/000000
- root/1234567890
- root/555555
- root/654321
- 111111/111111
- root/123321
- root/7777777
- root/welcome
- root/passw0rd
- root/123qwe
- root/Azuluaga10085927
- root/changeme
- root/AzV1tt0r1a15
- admin/555555
- admin/654321
- admin/123321
- admin/7777777
- admin/welcome
- user1/1
- admin/passw0rd
- admin/123qwe
- admin/1q2w3e4r
- root/
- admin/123abc
- admin/123456a
- admin/123456b
- root/ubuntu
- admin/123456c
- root/debian

### Files Uploaded/Downloaded
- )

### HTTP User-Agents
- None

### SSH Clients and Servers
- **SSH Clients:** None
- **SSH Servers:** None

### Top Attacker AS Organizations
- None

## Key Observations and Anomalies

- The high number of attacks from a single IP (72.146.232.13) suggests a targeted or persistent attacker.
- The commands executed indicate an attempt to gather system information and establish a foothold using SSH keys.
- The presence of CVEs related to older vulnerabilities suggests that some attackers are still using old exploits.
- The variety of login attempts shows a brute-force approach with common and default credentials.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organization data might indicate that these fields are not being logged or that the attacks are not of a nature that would populate this information.
