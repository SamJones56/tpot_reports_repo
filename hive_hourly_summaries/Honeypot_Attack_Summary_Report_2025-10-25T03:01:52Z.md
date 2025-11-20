# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T03:01:23Z
**Timeframe:** 2025-10-25T02:20:02Z to 2025-10-25T03:00:01Z

**Files Used:**
- `agg_log_20251025T022002Z.json`
- `agg_log_20251025T024001Z.json`
- `agg_log_20251025T030001Z.json`

## Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three log files. A total of 17,613 events were recorded across various honeypots. The most active honeypots were Cowrie, Suricata, and Honeytrap. The majority of attacks originated from IP addresses `109.205.211.9` and `8.210.214.44`. The most frequently targeted ports were 22 (SSH) and 445 (SMB), with a significant number of scans for MS Terminal Server on non-standard ports. A wide range of CVEs were targeted, with a focus on older vulnerabilities. Attackers attempted numerous commands, primarily related to establishing SSH backdoors and gathering system information.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5755
- **Honeytrap:** 4463
- **Suricata:** 4235
- **Ciscoasa:** 1822
- **Dionaea:** 672
- **Sentrypeer:** 239
- **Tanner:** 189
- **Mailoney:** 132
- **ConPot:** 41
- **Miniprint:** 17
- **Ipphoney:** 11
- **Redishoneypot:** 12
- **H0neytr4p:** 12
- **ElasticPot:** 4
- **Heralding:** 3
- **Honeyaml:** 6

### Top Attacking IPs
- `109.205.211.9`: 2493
- `80.94.95.238`: 1509
- `8.210.214.44`: 1233
- `114.47.12.143`: 552
- `156.246.91.141`: 303
- `188.166.126.51`: 333
- `103.149.86.230`: 290
- `196.251.71.24`: 266
- `107.170.36.5`: 249
- `154.221.27.234`: 295

### Top Targeted Ports/Protocols
- `22`: 892
- `445`: 554
- `5060`: 239
- `80`: 190
- `5903`: 132
- `5901`: 118
- `25`: 132
- `3306`: 75
- `23`: 76
- `8333`: 94

### Most Common CVEs
- `CVE-2002-0013 CVE-2002-0012`
- `CVE-2002-0013 CVE-2002-0012 CVE-1999-0517`
- `CVE-1999-0517`
- `CVE-2019-11500 CVE-2019-11500`
- `CVE-2021-3449 CVE-2021-3449`
- `CVE-2006-2369`
- `CVE-2024-4577 CVE-2002-0953`
- `CVE-2024-4577 CVE-2024-4577`
- `CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773`
- `CVE-2021-42013 CVE-2021-42013`
- `CVE-2018-10562 CVE-2018-10561`
- `CVE-2019-16920 CVE-2019-16920`
- `CVE-2021-35395 CVE-2021-35395`
- `CVE-2016-20017 CVE-2016-20017`
- `CVE-2024-12856 CVE-2024-12856 CVE-2024-12885`
- `CVE-2014-6271`
- `CVE-2023-52163 CVE-2023-52163`
- `CVE-2023-47565 CVE-2023-47565`
- `CVE-2023-31983 CVE-2023-31983`
- `CVE-2024-10914 CVE-2024-10914`
- `CVE-2009-2765`
- `CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051`
- `CVE-2024-3721 CVE-2024-3721`
- `CVE-2006-3602 CVE-2006-4458 CVE-2006-4542`

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -m`
- `uname -a`
- `whoami`
- `system`
- `shell`
- `enable`

### Signatures Triggered
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`
- `ET HUNTING RDP Authentication Bypass Attempt`
- `ET DROP Dshield Block Listed Source group 1`
- `ET SCAN NMAP -sS window 1024`
- `ET INFO Reserved Internal IP Traffic`
- `GPL SNMP request udp`
- `ET CINS Active Threat Intelligence Poor Reputation IP group 47`
- `ET CINS Active Threat Intelligence Poor Reputation IP group 45`
- `ET SCAN Potential SSH Scan`

### Users / Login Attempts
- `root/Elastix!!2015`
- `root/ELASTIX`
- `345gs5662d34/345gs5662d34`
- `root/3245gs5662d34`
- `cron/`
- `a2billinguser/`
- `root/eLaStIx.asteriskuser.2oo7`
- `admin/1Fuckme`
- `ubuntu/ubuntu`
- `sa/`

### Files Uploaded/Downloaded
- `sh`
- `gpon8080&ipv=0`
- `json`
- `3.253.97.195`
- `server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=`
- `rondo.dgx.sh||busybox`
- `rondo.dgx.sh||curl`

### HTTP User-Agents
- `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`

### SSH Clients
- Not available in logs.

### SSH Servers
- Not available in logs.

### Top Attacker AS Organizations
- Not available in logs.

## Key Observations and Anomalies

- **High Volume of Automated Scans:** The high number of events in a short period indicates widespread, automated scanning activity.
- **Repetitive SSH backdoor attempts:** A significant number of commands were aimed at creating or modifying SSH authorized_keys to maintain persistent access.
- **Focus on older vulnerabilities:** Many of the targeted CVEs are several years old, suggesting that attackers are targeting unpatched or legacy systems.
- **Targeting of VoIP and IoT devices:** The presence of Elastix-related credentials and various shell scripts suggests a focus on compromising VoIP servers and IoT devices.
- **Information Gathering:** A large number of commands were used for system information gathering, likely to tailor further attacks.
- **RDP Scans:** There is a high volume of scanning for Microsoft Remote Desktop Protocol on non-standard ports.

This report provides a snapshot of the threat landscape as observed by the honeypots. Continuous monitoring is recommended to identify emerging threats and attack patterns.
