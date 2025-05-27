# SanDan Security Agent

The SanDan Security Agent is a powerful, Python-based web application security scanner designed for comprehensive **ethical hacking** and **penetration testing**. It helps security professionals and researchers identify a wide range of common web vulnerabilities through automated checks and detailed reconnaissance.

---

## Features

SanDan offers a robust set of features to aid in security assessments:

### Vulnerability Scanning
* **Cross-Site Scripting (XSS):** Detects reflected and potential stored XSS vulnerabilities by injecting malicious scripts into URL parameters and form fields.
* **SQL Injection (SQLi):** Identifies error-based and time-based SQL injection flaws in both GET and POST requests.
* **Remote Code Execution (RCE):** Probes for RCE vulnerabilities by injecting system commands, aiming to execute code on the target server.
* **Local & Remote File Inclusion (LFI/RFI):** Checks for file inclusion flaws that could lead to sensitive data disclosure or remote code execution.
* **XML External Entity (XXE):** Tests for XXE vulnerabilities in applications that parse XML input.
* **Server-Side Template Injection (SSTI):** Discovers SSTI flaws by injecting template syntax into various input points.
* **Insecure Direct Object Reference (IDOR):** Attempts to identify IDOR issues by manipulating object IDs in URLs and POST data.
* **Server-Side Request Forgery (SSRF):** Checks for SSRF vulnerabilities, which can allow the server to make unauthorized requests to internal or external resources.
* **Open Redirect:** Detects vulnerabilities where the application redirects users to arbitrary external URLs, potentially leading to phishing.
* **Broken Authentication & Session Management (Basic):** Performs fundamental checks for common authentication and session flaws, such as predictable session IDs or unauthenticated access to sensitive areas.
* **Rate Limiting Bypass (Basic):** Attempts to circumvent rate limits using various HTTP header manipulations.
* **Sensitive Data Exposure:** Scans for commonly exposed sensitive files (e.g., backups, logs, configuration files) and directories.
* **Host Header Injection:** Tests for vulnerabilities related to the HTTP Host header, which can lead to cache poisoning or password reset flaws.
* **Clickjacking Protection:** Checks for the presence and proper configuration of `X-Frame-Options` and `Content-Security-Policy` headers to prevent UI redressing attacks.

### Reconnaissance & Information Gathering
* **Web Technology Fingerprinting:** Identifies the underlying web technologies (e.g., PHP, Nginx, Apache, JavaScript frameworks) and server configurations by analyzing headers and page content.
* **Deep Crawling & Endpoint Discovery:** Explores the website thoroughly to discover hidden pages, forms, and unique API endpoints.
* **Subdomain Enumeration:** Discovers subdomains associated with the target domain using a common wordlist and DNS queries.
* **Directory & File Brute-Forcing:** Attempts to find hidden or unlinked directories and files using a predefined wordlist.
* **Port Scanning:** Performs a basic scan for commonly open ports on the target host's IP address.
* **Security Header Analysis:** Checks for missing or misconfigured HTTP security headers like `Content-Security-Policy`, `X-Frame-Options`, and `Strict-Transport-Security`.
* **CORS Misconfiguration Checks:** Analyzes Cross-Origin Resource Sharing policies for insecure configurations that could allow cross-domain requests.
* **Defacement Check:** Records an initial content hash of the target's homepage to detect any unauthorized modifications.

---

## Installation

To get started with SanDan Security Agent, follow these steps:

1.   **Install dependencies:**
    ```bash
    pip install requests beautifulsoup4 fake-useragent dnspython
    ```

---
# Reporting
Upon completion of any scan, SanDan automatically generates a detailed JSON report. This report summarizes all findings, including detected technologies, results from crawling, and a categorized list of identified vulnerabilities by severity (critical, high, medium, low, info). The report file will be saved in the same directory where the script is executed, typically named sandan_report_yourdomain.com_TIMESTAMP.json.

# Disclaimer
IMPORTANT: The SanDan Security Agent is developed solely for ethical hacking, security research, and authorized penetration testing purposes. You must obtain explicit, written permission from the asset owner before performing any scans on target systems. Unauthorized scanning is illegal and unethical. The developers and contributors of this tool are not responsible for any misuse or damage caused by its deployment.

We welcome contributions, bug reports, and feature suggestions! Feel free to open an issue or submit a pull request.
## Usage

To run the SanDan Security Agent, execute the Python script from your terminal:

```bash
python sandan.py

The tool will prompt you to enter the target URL. Once provided, an interactive menu will appear, allowing you to choose specific vulnerability scans or initiate a comprehensive assessment.

Example Interaction:
================================================================================
   ██████  ▄▄▄       ███▄ ▄███▓ ▓█████  ▄▄▄       ███▄ ▄███▓
 ▒██    ▒ ▒████▄     ▓██▒▀█▀ ██▒ ▓█  ▀ ▒████▄     ▓██▒▀█▀ ██▒
 ░ ▓██▄   ▒██ ▀█▄   ▓██    ▓██░ ▒███   ▒██ ▀█▄   ▓██    ▓██░
  ▒  ██▒░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄ ░██▄▄▄▄██ ▒██    ▒██
 ▒██████▒▒ ▓█  ▓██▒▒██▒   ░██▒ ░▒████▒ ▓█  ▓██▒▒██▒   ░██▒
 ▒ ▒▓▒ ▒ ░ ▒▒  ▓▒█░░ ▒░   ░  ░ ░░ ▒░ ░ ▒▒  ▓▒█░░ ▒░   ░  ░
 ░ ░▒  ░ ░  ▒  ▒▒ ░░  ░        ░  ░ ░   ▒  ▒▒ ░░  ░        ░
 ░  ░  ░    ░  ▒  ░        ░        ░   ░  ▒  ░        ░
        ░       ░  ░          ░        ░      ░          ░


SanDan Agent v4.0 - KAGE Pro Mode
Advanced Web Application Security Scanner - For Authorized Testing Only
================================================================================

Enter target URL (e.g., [http://example.com](http://example.com)): [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
[SanDan][2025-05-27 18:04:37][INFO] Starting initial reconnaissance for [http://testphp.vulnweb.com](http://testphp.vulnweb.com)
[SanDan][2025-05-27 18:04:37][INFO] Starting technology fingerprinting...
... (output continues based on scan)
---
### SanDan Attack Menu
1.  XSS Scan
2.  SQL Injection
3.  RCE Test
4.  File Inclusion (LFI/RFI)
5.  XML External Entity (XXE) Test
6.  Server-Side Template Injection (SSTI) Test
7.  Insecure Direct Object Reference (IDOR) Test
8.  Check HTTP Methods
9.  Check CORS Policy
10. Check Security Headers (re-check)
11. Defacement Check (re-check)
12. Subdomain Enumeration
13. Directory/File Brute-Force
14. Port Scan
15. Server-Side Request Forgery (SSRF) Test
16. Open Redirect Test
17. Broken Authentication/Session Management Check (Basic)
18. Rate Limiting Bypass Test (Basic)
19. Sensitive Data Exposure Check (Basic)
20. Host Header Injection Test
21. Clickjacking Protection Check
------------------------------------------------------------
A. Run All Scans (Comprehensive)
Q. Exit
============================================================

