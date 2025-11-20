# **Honeypot Attack Research Report**

**Report Generation Time:** 2025-10-29 17:09:14.397629Z
**Timeframe:** 2025-09-28 00:00:00.000 - 2025-10-28 23:59:59.999

**Files Used to Generate Report:**
*   Internal Honeypot Logs
*   Elasticsearch Database
*   Google Search Results

## **Threat Landscape Overview**

This report provides a comprehensive overview of the threat landscape as observed by our globally distributed honeypot network. The data collected reveals a high volume of automated attacks originating from various countries, with a significant focus on exploiting known vulnerabilities and weak credentials.

### **Executive Summary**

The honeypot network registered a total of **11,940,813** attacks during the reporting period. The majority of these attacks were opportunistic, targeting common services and default credentials. The United States, Romania, and Germany were the top three source countries for these attacks. The most targeted services include VNC, ICMP, and SSH, with attackers primarily attempting to gain unauthorized access through brute-force attacks and the exploitation of known vulnerabilities.

### **Key Findings**

*   **Total Attacks:** 11,940,813
*   **Top Attacking Countries:** United States (3,060,556), Romania (1,029,981), Germany (691,148)
*   **Top Attacker IP:** 2.57.121.61 (906,566 attacks)
*   **Most Common CVEs:** CVE-2006-2369, CVE-2005-4050
*   **Most Common Malware Hash:** `7dcda269d0eff7966026c7e32966dec7d09c06507bcf61e54149fec26124ce22`

### **Detailed Analysis**

#### **Attack Origins**

The majority of attacks originated from a diverse range of countries, with the United States, Romania, and Germany being the most prominent. This indicates a geographically dispersed threat landscape. The top 10 attacking countries are as follows:

1.  **United States:** 3,060,556
2.  **Romania:** 1,029,981
3.  **Germany:** 691,148
4.  **China:** 562,230
5.  **Hong Kong:** 508,307
6.  **The Netherlands:** 470,825
7.  **Brazil:** 436,971
8.  **France:** 417,356
9.  **Indonesia:** 384,632
10. **Russia:** 355,787

#### **Attacker Infrastructure**

The most active attacking IP address was **2.57.121.61**, which was responsible for **906,566** attacks. This IP address is associated with **Unmanaged Ltd** (AS47890). A significant portion of the attacks originated from cloud providers such as DigitalOcean and Google Cloud Platform, highlighting the use of compromised or anonymously provisioned servers for malicious activities.

#### **Targeted Services and Ports**

Attackers targeted a wide range of services and ports. The most frequently targeted ports varied by country, but common targets included:

*   **Port 5060 (SIP):** Heavily targeted from the United States, Romania, and France.
*   **Port 22 (SSH):** A common target across all regions, with a high volume of brute-force attempts.
*   **Port 25 (SMTP):** Targeted frequently from the United States and Germany.
*   **Port 445 (SMB):** A popular target for attacks from China, Brazil, Indonesia, and Russia.

#### **Attacker Operating Systems**

The most common operating system identified among attackers was **Windows NT kernel**, with over 30 million instances. This was followed by various versions of Linux. This data suggests that a significant number of attacking machines are running Windows-based operating systems.

#### **Credentials and Authentication**

Attackers primarily used common and default credentials in brute-force attacks. The most common usernames and passwords observed were:

*   **Usernames:** root, admin, user
*   **Passwords:** 123456, 123, password

#### **Vulnerabilities and Exploits**

The most frequently observed CVEs were:

*   **CVE-2006-2369:** A critical vulnerability in RealVNC that allows for authentication bypass.
*   **CVE-2005-4050:** A buffer overflow vulnerability in Multi-Tech Systems MultiVOIP devices.

The most common alert signature was **"GPL INFO VNC server response,"** which indicates a high volume of scanning and connection attempts to VNC servers.

#### **Malware**

The most common malware hash captured by the Adbhoney honeypot was `7dcda269d0eff7966026c7e32966dec7d09c06507bcf61e54149fec26124ce22`. This hash is associated with a malicious Microsoft Excel Add-in (XLAM) file that acts as a downloader for other malware.

The most common commands executed on the Adbhoney honeypot were related to downloading and executing malicious files, as well as attempting to remove traces of the attack.

#### **Web-Based Attacks**

The Tanner honeypot, which simulates web services, observed that the most frequently requested URI was the root directory (`/`). Other common requests included those for sensitive files such as `.env` and `.git/config`, as well as attempts to access common administrative interfaces.

### **Conclusion and Recommendations**

The data collected from our honeypot network indicates a persistent and high volume of automated attacks. Attackers are primarily focused on exploiting weak credentials and known vulnerabilities in common services. To mitigate these threats, it is recommended to:

*   **Use strong and unique passwords for all services.**
*   **Disable or restrict access to unnecessary services.**
*   **Keep all software and systems up to date with the latest security patches.**
*   **Implement network segmentation to limit the impact of a potential breach.**
*   **Monitor network traffic for suspicious activity.**

This report provides a snapshot of the threat landscape as observed by our honeypot network. The tactics and techniques used by attackers are constantly evolving, and it is essential to remain vigilant and adapt security controls accordingly.