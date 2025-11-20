Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T10:01:32Z
**Timeframe:** 2025-10-27T09:20:01Z to 2025-10-27T10:00:01Z
**Files Used:**
- agg_log_20251027T092001Z.json
- agg_log_20251027T094001Z.json
- agg_log_20251027T100001Z.json

**Executive Summary**

This report summarizes 23,099 events collected from the T-Pot honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. The most prominent attacking IP address was 82.118.227.114. The most frequently targeted port was 5060/UDP, commonly used for SIP in VoIP systems. A wide range of CVEs were tested, with CVE-2005-4050 being the most common. Attackers attempted to run various commands, including system reconnaissance and downloading malicious scripts.

**Detailed Analysis**

***Attacks by honeypot***
- Cowrie: 6202
- Honeytrap: 6273
- Suricata: 4552
- Sentrypeer: 2994
- Ciscoasa: 1970
- Dionaea: 503
- H0neytr4p: 149
- Tanner: 197
- Mailoney: 113
- ConPot: 66
- Adbhoney: 47
- Redishoneypot: 19
- Wordpot: 1
- Heralding: 4
- Ipphoney: 2
- ElasticPot: 5
- Dicompot: 2

***Top attacking IPs***
- 82.118.227.114: 2589
- 198.23.190.58: 2277
- 72.167.220.12: 1171
- 144.172.108.231: 1112
- 134.199.205.99: 895
- 85.208.84.167: 381
- 85.208.84.219: 368
- 85.208.84.218: 365
- 85.208.84.170: 357
- 85.208.84.169: 357
- 209.38.98.72: 552

***Top targeted ports/protocols***
- 5060: 2994
- 22: 1014
- 445: 452
- 7070: 1044
- UDP/5060: 768
- 5038: 1074

***Most common CVEs***
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-1999-0183
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2006-2369
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2017-3506 CVE-2017-3506 CVE-2017-3606
- CVE-2019-16920 CVE-2019-16920
- CVE-2021-35395 CVE-2021-35395
- CVE-2016-20017 CVE-2016-20017
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163 CVE-2023-52163
- CVE-2023-47565 CVE-2023-47565
- CVE-2023-31983 CVE-2023-31983
- CVE-2024-10914 CVE-2024-10914
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
- CVE-2009-2765
- CVE-2024-3721 CVE-2024-3721
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2018-7600 CVE-2018-7600

***Commands attempted by attackers***
- Standard reconnaissance commands (`uname`, `whoami`, `cat /proc/cpuinfo`)
- Attempts to add SSH keys
- Download and execute scripts

***Signatures triggered***
- ET VOIP MultiTech SIP UDP Overflow
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt

***Users / login attempts***
- 345gs5662d34/345gs5662d34
- root/Innoviacc
- root/02041992Ionela%^&
- oracle/Bscs@2024
- systemd/Voidsetdownload.so

***Files uploaded/downloaded***
- wget.sh
- c.sh
- arm.uhavenobotsxd
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd

***HTTP User-Agents***
- None

***SSH clients and servers***
- None

***Top attacker AS organizations***
- None

**Key Observations and Anomalies**

- A significant amount of activity is directed towards VoIP (SIP) services.
- Attackers are consistently attempting to download and execute malicious scripts, indicating automated attacks.
- The wide range of CVEs being tested for suggests broad, opportunistic scanning rather than targeted attacks.
- The commands executed post-compromise focus on reconnaissance and establishing persistence.
- No significant anomalies were detected in this reporting period; the activity is consistent with typical internet background noise.
