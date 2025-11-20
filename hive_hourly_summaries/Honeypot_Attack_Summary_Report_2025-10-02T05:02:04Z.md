Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T05:01:22Z
**Timeframe:** 2025-10-02T04:20:01Z to 2025-10-02T05:00:01Z
**Files Used:**
- agg_log_20251002T042001Z.json
- agg_log_20251002T044001Z.json
- agg_log_20251002T050001Z.json

### Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 16,524 attacks were recorded across various honeypots. The most targeted services were SMB (port 445) and SMTP (port 25). The majority of attacks originated from a small number of IP addresses, with `46.149.176.177` and `103.220.207.174` being the most persistent threats. A number of CVEs were targeted, with `CVE-2002-0013` and `CVE-2002-0012` being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- **Dionaea:** 4,507
- **Honeytrap:** 4,095
- **Cowrie:** 3,684
- **Mailoney:** 1,653
- **Suricata:** 1,387
- **Ciscoasa:** 1,053
- **Sentrypeer:** 31
- **Tanner:** 29
- **Redishoneypot:** 24
- **H0neytr4p:** 21
- **Honeyaml:** 14
- **Adbhoney:** 12
- **ConPot:** 9
- **ElasticPot:** 4
- **Ipphoney:** 1

**Top Attacking IPs:**
- 46.149.176.177
- 103.220.207.174
- 176.65.141.117
- 81.183.253.80
- 51.52.232.248
- 157.66.144.17
- 129.212.187.81
- 92.63.197.55
- 185.156.73.166
- 92.63.197.59

**Top Targeted Ports/Protocols:**
- 445
- 25
- 22
- TCP/1433
- 1433
- 5901
- 8333
- 23
- 5060
- 80

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- 2403348

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/LeitboGi0ro
- foundry/foundry
- test/zhbjETuyMffoL8F
- root/3245gs5662d34
- sa/1qaz2wsx
- minecraft/3245gs5662d34
- root/nPSpP4PBW0
- root/2glehe5t24th1issZs
- superadmin/admin123

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- python-requests/2.18.4

**SSH Clients:**
- *No data recorded in this period.*

**SSH Servers:**
- *No data recorded in this period.*

**Top Attacker AS Organizations:**
- *No data recorded in this period.*

### Key Observations and Anomalies

- A significant amount of scanning and exploitation activity was observed from a concentrated set of IP addresses, suggesting a targeted campaign.
- The high volume of attacks on port 445 (SMB) indicates a continued focus on exploiting vulnerabilities in this service.
- The commands attempted by attackers show a clear pattern of attempting to gain information about the system, establish persistence through SSH keys, and remove traces of their activity.
- The downloaded files, such as `arm.urbotnetisass`, are likely malware payloads intended for various architectures, indicating that the attackers are attempting to compromise a wide range of devices.
- The presence of `python-requests/2.18.4` as a user agent suggests that some of the attacks are being automated using Python scripts.
- The lack of data for SSH clients/servers and AS organizations may indicate that the honeypots used for capturing this information did not receive any relevant traffic during this period, or that the data was not logged.
