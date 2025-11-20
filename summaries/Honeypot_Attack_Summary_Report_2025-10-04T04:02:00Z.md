
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T04:01:34Z
**Timeframe:** 2025-10-04T03:20:01Z to 2025-10-04T04:00:01Z
**Files Used:**
- agg_log_20251004T032001Z.json
- agg_log_20251004T034001Z.json
- agg_log_20251004T040001Z.json

## Executive Summary
This report summarizes 12,921 malicious events recorded across multiple honeypots. The primary vectors of attack were SSH (Cowrie), email services (Mailoney), and Cisco ASA appliances. A significant portion of the activity originated from IP addresses 86.54.42.238 and 176.65.141.117, focusing heavily on port 25 (SMTP). A recurring pattern of SSH-based attacks involved reconnaissance and attempts to install a malicious SSH key. Suricata network IDS triggered numerous alerts, with the "ET DROP Dshield Block Listed Source group 1" signature being the most frequent.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 5,246
- **Mailoney:** 2,477
- **Ciscoasa:** 1,877
- **Suricata:** 1,464
- **Honeytrap:** 1,243
- **Dionaea:** 278
- **Sentrypeer:** 227
- **Tanner:** 42
- **H0neytr4p:** 37
- **Redishoneypot:** 9
- **ConPot:** 7
- **Honeyaml:** 7
- **Heralding:** 3
- **Ipphoney:** 2
- **Wordpot:** 2

### Top Attacking IPs
- **86.54.42.238:** 1,641
- **176.65.141.117:** 820
- **196.251.80.29:** 384
- **51.158.120.121:** 384
- **85.209.134.43:** 363
- **139.59.46.176:** 307
- **103.165.236.27:** 302
- **185.156.73.166:** 228
- **178.128.80.162:** 270
- **103.24.63.85:** 259
- **196.188.116.41:** 257
- **190.129.122.185:** 245
- **14.103.127.58:** 170
- **14.103.118.194:** 186
- **14.103.73.80:** 164
- **46.105.87.113:** 163
- **103.118.114.22:** 189
- **118.194.250.11:** 105

### Top Targeted Ports/Protocols
- **25:** 2,477
- **22:** 734
- **5060:** 227
- **445:** 114
- **3306:** 73
- **80:** 48
- **443:** 49
- **TCP/22:** 38
- **27017:** 32

### Most Common CVEs
- **CVE-2002-0013 CVE-2002-0012:** 7
- **CVE-2021-3449 CVE-2021-3449:** 4
- **CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255:** 2
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 2
- **CVE-2019-11500 CVE-2019-11500:** 2
- **CVE-2021-35394 CVE-2021-35394:** 1

### Commands Attempted by Attackers
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~**: 38
- **lockr -ia .ssh**: 38
- **cd ~; chattr -ia .ssh; lockr -ia .ssh**: 38
- **cat /proc/cpuinfo | grep name | wc -l**: 30
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'**: 30
- **which ls**: 30
- **ls -lh $(which ls)**: 30
- **crontab -l**: 30
- **w**: 30
- **uname -m**: 30
- **top**: 30
- **uname**: 30
- **uname -a**: 30
- **whoami**: 33
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'**: 29
- **lscpu | grep Model**: 29
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}'**: 29
- **Enter new UNIX password:**: 17

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1 / 2402000:** 481
- **ET SCAN NMAP -sS window 1024 / 2009582:** 174
- **ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753:** 79
- **ET INFO Reserved Internal IP Traffic / 2002752:** 56
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44 / 2403343:** 31
- **ET HUNTING RDP Authentication Bypass Attempt / 2034857:** 23
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45 / 2403344:** 21

### Users / Login Attempts
- **a2billinguser/:** 70
- **345gs5662d34/345gs5662d34:** 34
- **root/3245gs5662d34:** 16
- **root/nPSpP4PBW0:** 11
- **root/09N1RCa1Hs31:** 7
- **superadmin/admin123:** 4
- **azureuser/azureuser@1234:** 4
- **titu/Ahgf3487@rtjhskl854hd47893@#a4nC:** 4
- **root/Kumar@123:** 4

### Files Uploaded/Downloaded
- **UnHAnaAW.mpsl;**: 4
- **UnHAnaAW.arm;**: 2
- **UnHAnaAW.arm5;**: 2
- **UnHAnaAW.arm6;**: 2
- **UnHAnaAW.arm7;**: 2
- **UnHAnaAW.m68k;**: 2
- **UnHAnaAW.mips;**: 2
- **UnHAnaAW.ppc;**: 2
- **UnHAnaAW.sh4;**: 2
- **UnHAnaAW.spc;**: 2
- **UnHAnaAW.x86;**: 2
- **?format=json**: 2
- **&currentsetting.htm=1**: 1

### HTTP User-Agents
- None recorded.

### SSH Clients and Servers
- **Clients:** None recorded.
- **Servers:** None recorded.

### Top Attacker AS Organizations
- None recorded.

## Key Observations and Anomalies
1.  **Automated SSH Exploitation:** The most notable activity is a coordinated set of commands executed in SSH sessions. Attackers consistently attempt to remove existing SSH configurations, create a new `.ssh` directory, and insert a specific public SSH key. This indicates a widespread, automated campaign to gain persistent access to compromised systems.
2.  **System Reconnaissance:** Following the SSH key attempt, attackers run a standard suite of reconnaissance commands (`uname -a`, `whoami`, `w`, `cat /proc/cpuinfo`, `free -m`, etc.) to gather information about the compromised host's architecture and resources.
3.  **Mail Service Focus:** A large volume of traffic was directed at port 25, logged by the Mailoney honeypot. This suggests broad scanning or exploitation attempts targeting SMTP services.
4.  **Dshield Hits:** The high number of "Dshield Block Listed" signature hits from Suricata indicates that many attacking IPs are already known members of blocklists, confirming their malicious reputation.
