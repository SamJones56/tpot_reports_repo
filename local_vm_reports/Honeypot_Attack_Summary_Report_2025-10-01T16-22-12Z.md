# In-Depth OSINT Report: Analysis of Coordinated Attacks on Honeypot Network

**Report ID:** OSINT-20251001-1
**Date of Report:** 2025-10-01
**Requestor:** Internal Security Team
**Analyst:** Info_Agent

## 1. Executive Summary
This report presents an in-depth Open-Source Intelligence (OSINT) investigation into the significant threat vectors identified during the 12-hour period of heightened attack activity on our honeypot network. The investigation confirms that our network was targeted by multiple, likely uncoordinated, but widespread automated campaigns.

Key findings indicate that threat actors are leveraging compromised cloud infrastructure, primarily from DigitalOcean (AS14061), to launch attacks. The primary goals of these campaigns appear to be the propagation of IoT-focused botnets for DDoS attacks and cryptomining, as evidenced by the consistent deployment of **`urbotnetisass`** (a Mirai variant) and **`Mozi.m`** malware.

Attackers are utilizing a two-pronged approach for initial access:
1.  **Exploitation of Known Vulnerabilities:** The high prevalence of **DoublePulsar** backdoor alerts confirms that attackers are still actively and successfully exploiting the **EternalBlue** (MS17-010) vulnerability against unpatched systems.
2.  **Credential Stuffing:** Automated brute-force attacks are targeting common services like SSH and Telnet, using lists of default and previously compromised credentials.

A notable TTP (Tactics, Techniques, and Procedures) observed is the use of a specific SSH key, bearing the comment **"mdrfckr,"** to establish persistent backdoor access. This signature is linked to the long-running "Outlaw" hacking group, known for deploying the "Dota3" malware and XMRig cryptominers.

The intelligence gathered strongly suggests that the threat is not from a single, sophisticated actor but rather from a collection of attackers using readily available, effective, and automated toolkits to exploit common security weaknesses.

## 2. Scope of Investigation
This investigation focuses on the "highlighted areas" identified in the Honeypot Attack Summary Report (2025-10-01), which include:
*   **Threat Actor Infrastructure:** Analysis of the top attacking IPs (`161.35.152.121`, `92.205.59.208`, `92.242.166.161`) and the malware Command and Control (C2) server `94.154.35.154`.
*   **Malware Campaign Analysis:** Investigation into the `urbotnetisass` and `Mozi.m` malware families.
*   **TTPs Analysis:** Examination of the specific credential pairs, persistence mechanisms (the "mdrfckr" SSH key), and the continued exploitation of EternalBlue/DoublePulsar.

## 3. Key Findings

### 3.1. Threat Actor Infrastructure Analysis

The attack infrastructure is distributed across various hosting providers, with a significant concentration in cloud services known for ease of deployment and, consequently, frequent abuse.

*   **IP `161.35.152.121` (DigitalOcean, AS14061, Netherlands):** This IP is a node within DigitalOcean's network. OSINT confirms that AS14061 is a major source of malicious traffic, including phishing, malware hosting, and C2 infrastructure for botnets like KV-Botnet (used by APT group Volt Typhoon). The high volume of SSH brute-force attacks from this IP is consistent with the established abuse patterns of this network. The actors are likely using a compromised or purpose-rented VPS.

*   **IP `92.205.59.208` (Host Europe GmbH, France):** This IP is part of a network owned by a GoDaddy subsidiary. It has been flagged on threat intelligence platforms. Its reverse DNS (`208.59.205.92.host.secureserver.net`) points to generic hosting, a common characteristic for servers used in automated scanning and attacks.

*   **IP `92.242.166.161` (SMARTNET LIMITED, AS203446, Finland):** This IP is part of a network that has been repeatedly blacklisted for spam and other network abuses. The hosting provider, SMARTNET LIMITED, offers services like DDoS mitigation, which can also be used offensively. The consistent malicious activity suggests either lax oversight or a business model that tolerates such clients.

*   **C2 Server `94.154.35.154`:** This IP was identified as the C2 server for the `urbotnetisass` malware campaign. It actively hosts and distributes various malware payloads, including `arm7.urbotnetisass` and a downloader named `mass`. This IP is a critical pivot point in the botnet's lifecycle, serving as the source for new infections. It is listed on multiple malware databases like URLhaus.

### 3.2. Malware Campaign Analysis

The primary malware families observed are geared towards compromising and controlling IoT devices.

*   **`urbotnetisass` (Mirai Variant):** This malware is a component of the Mirai botnet family, designed to infect IoT devices and recruit them into a network for launching DDoS attacks. Its infection vector, as seen in our logs, involves downloading the binary via `wget` or `curl` after gaining initial access. The various filenames (`arm.`, `arm5.`, `arm7.`, `mips.`, `x86_32.`) correspond to different CPU architectures, demonstrating the attackers' intent to target a wide array of IoT devices.

*   **`Mozi.m` (P2P Botnet):** Mozi is a sophisticated P2P botnet derived from Mirai and Gafgyt code. It uses a Distributed Hash Table (DHT) for C2 communication, making it highly resilient to takedowns. Although a "kill switch" was activated against the primary Mozi botnet in 2023, security researchers have noted a potential resurgence in 2024 and 2025, with its payloads being used by other botnets. The presence of `Mozi.m` in our logs supports this resurgence theory.

### 3.3. Tactics, Techniques, and Procedures (TTPs) Analysis

#### **Initial Access**
*   **Exploitation of Public-Facing Application (T1190):** The continued high alert rate for the **DoublePulsar** backdoor indicates that attackers are still widely scanning for and exploiting the **EternalBlue** vulnerability (MS17-010). OSINT confirms this remains a viable, high-impact attack vector in 2025 due to the prevalence of unpatched legacy Windows systems.
*   **Brute Force (T1110):** Attackers are systematically using credential stuffing attacks. The following observed credentials are of high intelligence value:
    *   **`345gs5662d34` / `345gs5662d34`**: Confirmed default credentials for Polycom CX600 IP phones. This is a targeted attack against specific, often overlooked, enterprise hardware.
    *   **`seekcy` / `Joysuch@Locate2024`**: The username `seekcy` is linked to a Chinese IoT company and is a common entry in brute-force wordlists. The password follows a known pattern (`Joysuch@Locate<YEAR>`), making it a predictable target for automated scripts.

#### **Persistence**
*   **Create or Modify System Account (T1136):** The most distinct TTP for persistence is the injection of a specific SSH public key into the `.ssh/authorized_keys` file. The key contains the comment **"mdrfckr,"** which OSINT has definitively linked to the "Outlaw" hacking group. This is a clear and reliable signature of this specific threat actor, whose primary motivation is deploying cryptominers (XMRig) and an IRC-based backdoor (Shellbot).

## 4. Attribution and Motivation
Direct attribution to a specific entity or nation-state is not possible with the current data. However, the evidence points towards multiple, financially motivated cybercriminal groups rather than a single actor.

*   The use of the "mdrfckr" key strongly suggests the involvement of the **"Outlaw" group**, whose motivation is cryptomining and resource hijacking.
*   The widespread scanning and deployment of DDoS botnets like `urbotnetisass` are characteristic of actors involved in DDoS-for-hire services.
*   The infrastructure used (rented VPS from providers like DigitalOcean) is typical of cybercriminals seeking anonymity and easily disposable assets.

The overall motivation is overwhelmingly financial, focusing on the theft of computing resources for cryptomining and the creation of botnets for rental.

## 5. Recommendations and Countermeasures
1.  **Immediate IOC Blocking:** Block all malicious IP addresses listed in the appendix at the network perimeter.
2.  **Patch Management:** Prioritize patching of the MS17-010 (EternalBlue) vulnerability on all Windows systems. Conduct a network-wide scan to identify any remaining vulnerable instances.
3.  **Credential Security:**
    *   Audit all network devices, especially VoIP phones and IoT hardware, to ensure no default credentials (`345gs5662d34`, etc.) are in use.
    *   Enforce a strong password policy and consider disabling password-based authentication for SSH in favor of public key cryptography.
4.  **SSH Hardening:**
    *   Regularly monitor `.ssh/authorized_keys` files on critical servers for any unauthorized additions.
    *   Deploy tools like `fail2ban` to automatically block IPs exhibiting brute-force behavior.
5.  **Network Segmentation:** Isolate IoT devices on a separate network VLAN to prevent lateral movement in the event of a compromise.
6.  **Egress Filtering:** Implement firewall rules to block outbound traffic to known malicious C2 servers, including `94.154.35.154`.

## 6. Conclusion
The attacks observed over the last 12 hours represent a microcosm of the current automated threat landscape. Attackers are efficiently leveraging compromised infrastructure and well-known toolkits to exploit fundamental security weaknesses. While the individual attacks are not highly sophisticated, their scale and persistence pose a significant threat. The intelligence gathered in this report provides actionable steps to mitigate these specific campaigns and improve our overall defensive posture.

## Appendix: Indicators of Compromise (IOCs)

### IP Addresses
*   `161.35.152.121` (Attacker)
*   `92.205.59.208` (Attacker)
*   `92.242.166.161` (Attacker)
*   `94.154.35.154` (Malware C2 Server)

### Malware Filenames/Hashes
*   `urbotnetisass` (and variants: `arm.`, `arm5.`, `arm7.`, `mips.`, `x86_32.`)
*   `Mozi.m`
*   `mass` (downloader)

### Credentials
*   `u: 345gs5662d34` / `p: 345gs5662d34`
*   `u: seekcy` / `p: Joysuch@Locate2024`

### Attacker Signatures
*   SSH public key with comment: "mdrfckr"
