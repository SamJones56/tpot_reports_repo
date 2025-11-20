Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T06:01:26Z
**Timeframe:** 2025-10-19T05:20:01Z to 2025-10-19T06:00:01Z
**Files Used:**
- `agg_log_20251019T052001Z.json`
- `agg_log_20251019T054001Z.json`
- `agg_log_20251019T060001Z.json`

### Executive Summary

This report summarizes 27,527 events recorded by the T-Pot honeypot network over a 40-minute period on October 19, 2025. The majority of attacks were captured by the Cowrie, Heralding, and Honeytrap honeypots. The most targeted services were VNC (port 5900), SSH (port 22), and SIP (port 5060). The top attacking IP address was 185.243.96.105, responsible for 5,189 events. A significant number of attacks attempted to exploit CVE-2005-4050, a vulnerability in MultiTech VoIP gateways. Attackers were observed attempting to add their SSH keys to the authorized_keys file for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 9,977
*   Heralding: 5,189
*   Honeytrap: 4,833
*   Suricata: 3,618
*   Sentrypeer: 1,830
*   Ciscoasa: 1,030
*   Dionaea: 624
*   ConPot: 180
*   Tanner: 99
*   Mailoney: 50
*   Honeyaml: 49
*   Miniprint: 12
*   H0neytr4p: 12
*   Redishoneypot: 9
*   ElasticPot: 5
*   Adbhoney: 5
*   Dicompot: 3
*   ssh-rsa: 2

**Top Attacking IPs:**
*   185.243.96.105: 5,189
*   38.242.213.182: 1,355
*   72.146.232.13: 1,200
*   198.23.190.58: 1,193
*   23.94.26.58: 1,164
*   134.199.204.192: 997
*   198.12.68.114: 838
*   161.132.48.14: 716
*   66.116.196.243: 700
*   104.248.206.169: 583
*   80.249.139.88: 523
*   88.210.63.16: 517

**Top Targeted Ports/Protocols:**
*   vnc/5900: 5,189
*   5060: 1,830
*   22: 1,798
*   UDP/5060: 1,374
*   8000: 1,170
*   445: 572
*   5903: 227
*   1025: 171
*   5901: 118
*   8333: 104

**Most Common CVEs:**
*   CVE-2005-4050: 1,369
*   CVE-2019-11500: 9
*   CVE-2021-3449: 4
*   CVE-2002-0013, CVE-2002-0012: 4
*   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 2
*   CVE-2021-35394: 1
*   CVE-2006-2369: 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 33
*   `lockr -ia .ssh`: 33
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 33
*   `cat /proc/cpuinfo | grep name | wc -l`: 33
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 33
*   `ls -lh $(which ls)`: 33
*   `which ls`: 33
*   `crontab -l`: 33
*   `w`: 33
*   `uname -m`: 33
*   `uname -a`: 33
*   `whoami`: 33
*   `Enter new UNIX password: `: 20
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 9
*   `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`: 2
*   `cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps`: 2
*   `curl2`: 2

**Signatures Triggered:**
*   ET VOIP MultiTech SIP UDP Overflow (2003237): 1,369
*   ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 578
*   ET DROP Dshield Block Listed Source group 1 (2402000): 471
*   ET HUNTING RDP Authentication Bypass Attempt (2034857): 264
*   ET SCAN NMAP -sS window 1024 (2009582): 175

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 33
*   /passw0rd: 23
*   /1q2w3e4r: 22
*   /Passw0rd: 15
*   /qwertyui: 13
*   /1qaz2wsx: 12
*   root/3245gs5662d34: 10
*   ftpuser/ftppassword: 10
*   root/123@Robert: 10

**Files Uploaded/Downloaded:**
*   `loader.sh|sh;#`
*   `&currentsetting.htm=1`
*   `rondo.eby.sh|sh`

**HTTP User-Agents:**
*   *No user agents recorded in this timeframe.*

**SSH Clients:**
*   *No SSH clients recorded in this timeframe.*

**SSH Servers:**
*   *No SSH servers recorded in this timeframe.*

**Top Attacker AS Organizations:**
*   *No AS organizations recorded in this timeframe.*

### Key Observations and Anomalies

*   The high number of VNC connection attempts from a single IP (185.243.96.105) suggests a targeted scan for exposed VNC servers.
*   The repeated attempts to add an SSH key to `authorized_keys` indicate a common tactic for attackers to gain persistent access to a compromised system.
*   The commands executed by attackers are primarily focused on system enumeration and reconnaissance, such as checking CPU information, memory, and running processes.
*   The presence of commands like `pkill` and modifications to `/etc/hosts.deny` suggest that some attackers are attempting to disable security measures and remove other potential threats from the compromised system.
*   The download of shell scripts (`loader.sh`, `rondo.eby.sh`) is a strong indicator of attempts to install malware or other malicious tools on the system.

This concludes the Honeypot Attack Summary Report. Further analysis of the downloaded files and the command and control infrastructure of the attacking IPs is recommended.
