# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T12:15:59.240574Z
**Timeframe:** 2025-09-20T00:00:00.000Z to 2025-10-26T23:59:59.999Z

### Executive Summary

This report details the malicious activity observed across our distributed honeypot network between September 20, 2025, and October 26, 2025. During this period, the network recorded a total of **11,466,771** attacks. The activity was overwhelmingly characterized by automated, large-scale campaigns focused on exploiting legacy vulnerabilities and conducting brute-force login attempts against common services.

A central finding of this report is the stark contrast between the high-profile, sophisticated zero-day attacks reported globally during this timeframe and the reality of the traffic observed by our honeypots. While the security community was responding to critical zero-days in Chrome, Cisco, and Microsoft products, our network was overwhelmingly targeted by attackers scanning for **CVE-2006-2369**, a nearly two-decade-old vulnerability in RealVNC. This was the most prominent campaign observed, accounting for over 163,000 direct alerts and corroborated by over 6.7 million "VNC server response" NIDS signatures.

The primary sources of attacks were concentrated in the United States, Romania, and Germany, with the vast majority of malicious traffic originating from commercial hosting providers and cloud platforms. **DigitalOcean (AS14061)**, **Global Connectivity Solutions (AS215540)**, and **Unmanaged Ltd (AS47890)** were the top sources of attacks, highlighting the continued abuse of legitimate infrastructure by threat actors.

Analysis of attacker techniques revealed specific minutia pointing to organized, albeit unsophisticated, campaigns. The use of the credentials `345gs5662d34` and `3245gs5662d34` in tens of thousands of login attempts serves as a clear fingerprint for a specific botnet. Furthermore, the observation of the non-standard command `lockr -ia .ssh` provides insight into attacker TTPs for maintaining persistent access after a compromise.

In summary, no evidence of exploited zero-days or activity directly correlated to major world events was observed. Instead, the data confirms that the internet's background noise consists of a relentless, automated barrage targeting systemic weaknesses, primarily ancient vulnerabilities in remote access software and weak password hygiene.

### Detailed Analysis

#### Our IPs

| Honeypot | Private IP    | Public IP       |
|----------|---------------|-----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

#### Attacks by Honeypot

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 4,454,716    |
| Honeytrap     | 2,235,839    |
| Sentrypeer    | 1,787,155    |
| Dionaea       | 1,027,772    |
| Ciscoasa      | 999,297      |
| Mailoney      | 436,349      |
| Heralding     | 269,347      |
| Tanner        | 55,415       |
| Redishoneypot | 43,315       |
| H0neytr4p     | 34,529       |

#### Top Source Countries

| Country         | Attack Count |
|-----------------|--------------|
| United States   | 2,823,605    |
| Romania         | 895,996      |
| Germany         | 663,472      |
| China           | 549,212      |
| Hong Kong       | 463,361      |
| The Netherlands | 379,423      |
| Indonesia       | 342,415      |
| Brazil          | 317,226      |
| Ukraine         | 313,536      |
| France          | 303,430      |

#### Top Attacking IPs

| IP Address      | Attack Count |
|-----------------|--------------|
| 2.57.121.61     | 822,383      |
| 92.205.59.208   | 231,492      |
| 176.65.141.117  | 161,049      |
| 86.54.42.238    | 141,183      |
| 185.243.96.105  | 140,111      |
| 45.234.176.18   | 114,229      |
| 72.146.232.13   | 113,600      |
| 45.134.26.47    | 100,105      |
| 172.188.91.73   | 88,716       |
| 23.94.26.58     | 78,730       |

#### Top Targeted Ports/Protocols

| Port | Attack Count |
|------|--------------|
| 5060 | 1,787,155    |
| 445  | 931,944      |
| 22   | 713,786      |
| 25   | 434,483      |
| 5900 | 258,082      |
| 5038 | 96,441       |
| 5903 | 79,674       |
| 8333 | 61,908       |
| 80   | 44,763       |
| 5901 | 37,216       |

#### Most Common CVEs

| CVE                                     | Count  |
|-----------------------------------------|--------|
| CVE-2006-2369                           | 163,191|
| CVE-2005-4050                           | 36,257 |
| CVE-2002-0013 CVE-2002-0012             | 5,490  |
| CVE-2002-0013 CVE-2002-0012 CVE-1999-0517| 2,993  |
| CVE-2021-44228 CVE-2021-44228           | 2,784  |
| CVE-2022-27255 CVE-2022-27255           | 1,940  |
| CVE-2019-11500 CVE-2019-11500           | 1,858  |
| CVE-2021-3449 CVE-2021-3449             | 1,720  |
| CVE-2016-5696                           | 470    |
| CVE-1999-0265                           | 353    |

#### Commands Attempted by Attackers

| Command                                                                 | Count  |
|-------------------------------------------------------------------------|--------|
| cd ~; chattr -ia .ssh; lockr -ia .ssh                                     | 17,733 |
| lockr -ia .ssh                                                          | 17,733 |
| uname -a                                                                | 16,561 |
| cat /proc/cpuinfo | grep name | wc -l                               | 15,579 |
| cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}' | 12,841 |
| whoami                                                                  | 11,449 |
| free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'          | 10,714 |
| crontab -l                                                              | 10,206 |
| ls -lh $(which ls)                                                      | 8,492  |
| cat /proc/cpuinfo | grep model | grep name | wc -l                    | 8,156  |

#### Signatures Triggered

| Signature ID | Signature                                                            | Count     |
|--------------|----------------------------------------------------------------------|-----------|
| 2100560      | GPL INFO VNC server response                                         | 6,741,536 |
| 2100384      | GPL ICMP PING                                                        | 1,419,039 |
| 2210051      | SURICATA STREAM Packet with broken ack                               | 439,839   |
| 2024766      | ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 415,988   |
| 2402000      | ET DROP Dshield Block Listed Source group 1                          | 253,860   |
| 2023753      | ET SCAN MS Terminal Server Traffic on Non-standard Port              | 220,992   |
| 2100401      | GPL ICMP Destination Unreachable Network Unreachable                 | 159,704   |
| 2002923      | ET EXPLOIT VNC Server Not Requiring Authentication (case 2)          | 156,601   |
| 2002920      | ET INFO VNC Authentication Failure                                   | 156,550   |
| 2210027      | SURICATA STREAM ESTABLISHED SYN resend with different seq            | 118,642   |

#### Users / Login Attempts

| Username    | Count   |
|-------------|---------|
| root        | 218,213 |
| admin       | 25,107  |
| user        | 18,239  |
| 345gs5662d34| 16,728  |
| ubuntu      | 13,082  |
| test        | 9,262   |
| oracle      | 7,961   |
| postgres    | 6,796   |
| guest       | 5,445   |
| ftpuser     | 5,032   |

| Password      | Count  |
|---------------|--------|
| 123456        | 58,843 |
| 123           | 24,602 |
| 345gs5662d34  | 16,727 |
| 3245gs5662d34 | 16,700 |
|               | 10,482 |
| password      | 8,316  |
| 1234          | 3,869  |
| Password      | 3,541  |
| 12345678      | 2,682  |
| admin         | 2,471  |

#### Top Attacker AS Organizations

| ASN    | AS Organization                       | Count   |
|--------|---------------------------------------|---------|
| 14061  | DIGITALOCEAN-ASN                      | 891,252 |
| 215540 | Global Connectivity Solutions Llp     | 848,350 |
| 47890  | Unmanaged Ltd                         | 834,136 |
| 396982 | GOOGLE-CLOUD-PLATFORM                 | 428,998 |
| 8075   | MICROSOFT-CORP-MSN-AS-BLOCK           | 347,956 |
| 36352  | AS-COLOCROSSING                       | 274,126 |
| 21499  | Host Europe GmbH                      | 231,493 |
| 135377 | UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 187,143 |
| 23470  | RELIABLESITE                          | 166,612 |
| 214967 | Optibounce, LLC                       | 162,216 |

### OSINT Investigations

#### OSINT on High-Frequency IPs

*   **2.57.121.61 (AS47890 - Unmanaged Ltd, Romania):** This IP was the top attacker during the analysis period, responsible for over 822,000 events. As confirmed by OSINT, this IP belongs to a hosting provider notorious for facilitating malicious activities. Its hostname suggests it is configured as a mail server, but its primary activity observed in the honeypot was aggressive scanning, consistent with a compromised or malicious host being used as part of a larger botnet infrastructure.
*   **92.205.59.208 (AS26496 - GoDaddy.com, LLC, USA):** This IP is part of GoDaddy's hosting infrastructure. OSINT research indicates GoDaddy has suffered multi-year breaches, with their servers being co-opted for malware distribution and phishing. This IP is flagged by threat intelligence sources as malicious, and its activity is likely part of these broader abuse campaigns originating from compromised hosting accounts.

#### OSINT on CVEs

*   **CVE-2006-2369:** The most scanned-for vulnerability by an overwhelming margin. This is a critical authentication bypass in RealVNC 4.1.1. An attacker can gain full control by simply requesting an insecure connection type. Its prevalence, nearly two decades after disclosure, highlights the vast number of unpatched, internet-exposed devices (e.g., remote access systems, embedded devices) that remain vulnerable. The 6.7 million NIDS alerts for "VNC server response" directly corroborate this finding, pointing to a massive, ongoing global scan for this single point of failure.
*   **CVE-2005-4050:** The second most common CVE is a buffer overflow in Multi-Tech VoIP devices, triggered by a malformed SIP INVITE message. Its continued presence in attack traffic, combined with Port 5060 (SIP) being the most targeted port, indicates the operation of legacy botnets programmed to scan for old but effective exploits against unmanaged network hardware.

#### OSINT on Commands, Signatures, and Minutia

*   **`lockr -ia .ssh` Command:** This command is not a standard Linux utility. OSINT confirms it is part of a malicious toolset. This sequence is used to modify SSH `authorized_keys` for persistent access and then make the configuration directory immutable, locking the legitimate user out from easily removing the attacker's backdoor.
*   **DoublePulsar Signature:** The "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature was triggered over 415,000 times. DoublePulsar was a backdoor famously used with the EternalBlue exploit (MS17-010). This high number of alerts proves that automated scanning for the underlying SMB vulnerability is still a massive, ongoing phenomenon.
*   **`345gs5662d34` Credentials:** These unique strings, used as both username and password over 16,000 times, are a clear botnet fingerprint. OSINT research suggests these are likely hardcoded default credentials for a specific, widely-distributed IoT or embedded device that the botnet is relentlessly scanning for.

### General Trends and Correlation with World Events

The timeframe of this report was marked by a turbulent period in cybersecurity, with reports of actively exploited zero-days in Google Chrome (CVE-2025-10585), Cisco ASA firewalls (CVE-2025-20333), and Microsoft products (CVE-2025-24990). Ransomware attacks and major data breaches were also prominent in the news.

However, **there is no correlation between these sophisticated, high-profile events and the activity observed in our honeypot network.** The honeypot data shows no evidence of scanning or exploitation attempts related to these new vulnerabilities. This finding demonstrates a critical dichotomy in the threat landscape: while news headlines are dominated by advanced threats, the vast majority of malicious traffic on the internet is composed of low-sophistication, high-volume, automated campaigns targeting long-since-disclosed vulnerabilities. The threat actors targeting our honeypots are not leveraging zero-days; they are preying on a lack of basic patching and security hygiene.

### Key Observations and Anomalies

*   **The VNC Epidemic:** The scale of scanning for CVE-2006-2369 is the single most significant finding. The internet is being systematically scoured for insecure VNC servers on an immense scale, indicating that this is still a highly successful vector for compromise.
*   **A Tale of Two Threat Landscapes:** The complete disconnect between the zero-day exploits in the news cycle and the "ground truth" of the honeypot data is a key observation. It highlights that for many organizations, the primary threat is not a sophisticated nation-state actor, but a relentless barrage of automated tools exploiting old vulnerabilities.
*   **Botnet Fingerprints in Plain Sight:** The high-frequency use of credentials like `345gs5662d34` serves as a clear signature for specific botnet campaigns, allowing for the confident attribution of a large volume of disparate attacks to a single coordinated effort.
*   **No Evidence of Zero-Day Exploitation:** The honeypot logs show no fingerprints, commands, or payloads that would suggest the exploitation of any of the zero-day vulnerabilities that were prominent during this period. The activity is exclusively opportunistic, targeting known and dated flaws.
