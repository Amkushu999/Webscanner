"""
Information Disclosure scanner module.

Analyzes website content to find sensitive information that might be 
disclosed unintentionally.
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Try to import trafilatura, but handle it gracefully if not available
trafilatura_module = None
try:
    import trafilatura
    trafilatura_module = trafilatura
    TRAFILATURA_AVAILABLE = True
except ImportError:
    TRAFILATURA_AVAILABLE = False

class InfoDisclosureScanner:
    """Scanner for detecting sensitive information disclosure."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the Information Disclosure scanner.
        
        Args:
            target_url (str): The target URL to scan
            timeout (int): Request timeout in seconds
            depth (int): Scan depth level
            user_agent (str): User-Agent string to use in requests
            logger: Logger instance
            verbose (bool): Enable verbose output
        """
        self.target_url = target_url
        self.timeout = timeout
        self.depth = depth
        self.logger = logger
        self.verbose = verbose
        
        self.user_agent = user_agent
        self.headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        
        # Patterns to identify sensitive information
        self.patterns = {
            'API Key': [
                r'api[-_]?key[\s"\'=:]+[a-zA-Z0-9_\-]{20,}',
                r'api[-_]?secret[\s"\'=:]+[a-zA-Z0-9_\-]{20,}',
                r'access[-_]?key[\s"\'=:]+[a-zA-Z0-9_\-]{20,}',
                r'access[-_]?secret[\s"\'=:]+[a-zA-Z0-9_\-]{20,}'
            ],
            'AWS Key': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[-_]?key[\s"\'=:]+[A-Za-z0-9/\+=]{40}',
                r'aws[-_]?secret[\s"\'=:]+[A-Za-z0-9/\+=]{40}'
            ],
            'Private Key': [
                r'-----BEGIN[ A-Z]+ PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----'
            ],
            'Password': [
                r'password[\s"\'=:]+[a-zA-Z0-9_\-\.\$\!\@\#]{6,}',
                r'passwd[\s"\'=:]+[a-zA-Z0-9_\-\.\$\!\@\#]{6,}',
                r'pwd[\s"\'=:]+[a-zA-Z0-9_\-\.\$\!\@\#]{6,}'
            ],
            'Database Connection String': [
                r'(?i)(?:jdbc|odbc|sqloledb):.*?(?:server|host)=[\w\.-]+;.*?(?:user|uid|username)=',
                r'(?i)(?:Data Source|Server)=[\w\.-]+;.*?(?:User ID|UID)=',
                r'(?i)mongodb(?:(\+srv)?):\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.\-]+(?::[0-9]+)?\/[a-zA-Z0-9-]+'
            ],
            'Token': [
                r'token[\s"\'=:]+[a-zA-Z0-9_\-\.]{10,}',
                r'jwt[\s"\'=:]+[a-zA-Z0-9_\-\.]{10,}',
                r'bearer[\s"\'=:]+[a-zA-Z0-9_\-\.]{10,}'
            ],
            'Email': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            'Social Security Number': [
                r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
            ],
            'Credit Card': [
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'
            ],
            'Phone Number': [
                r'\b(?:\+\d{1,3}[-\s])?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b'
            ],
            'IP Address': [
                r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ],
            'Stack Trace': [
                r'(?i)(?:Exception|Error|Stack trace|at [a-zA-Z0-9_$.]+\([a-zA-Z0-9_$.]+\.java:\d+\))',
                r'(?i)(?:Traceback \(most recent call last\)|File ".*?", line \d+, in)',
                r'(?i)(?:Warning|Fatal error|Parse error):.+? in .+? on line \d+'
            ],
            'Version Information': [
                r'(?i)(?:version|v)[\s"\'=:]+\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?'
            ],
            'Internal Path': [
                r'(?i)(?:\/var\/www\/|\/home\/\w+\/|C:\\inetpub\\wwwroot\\|C:\\Windows\\|\/etc\/|\/usr\/local\/)'
            ],
            'Comment': [
                r'(?i)(?:TODO|FIXME|HACK|XXX|BUG|NOTE)[\s:]+.{10,}',
                r'(?i)<!--[\s\S]*?-->'
            ]
        }
        
        # Compile regexes for efficiency
        self.compiled_patterns = {}
        for category, patterns in self.patterns.items():
            self.compiled_patterns[category] = [re.compile(pattern) for pattern in patterns]
    
    def _extract_page_content(self, url):
        """
        Extract the content of a webpage using trafilatura if available,
        otherwise just use the raw HTML.
        
        Args:
            url (str): The URL to extract content from
            
        Returns:
            tuple: (raw_html, extracted_text) or (None, None) if error
        """
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout,
                verify=False  # Ignore SSL cert validation for scanning purposes
            )
            response.raise_for_status()
            
            # Get raw HTML content
            raw_html = response.text
            
            # Try to use trafilatura to extract main content
            if TRAFILATURA_AVAILABLE and trafilatura_module:
                try:
                    downloaded = trafilatura_module.fetch_url(url)
                    extracted_text = trafilatura_module.extract(downloaded) or ""
                except Exception as e:
                    if self.logger and self.verbose:
                        self.logger.warning(f"Error using trafilatura: {str(e)}")
                    # Fallback to BeautifulSoup extraction
                    soup = BeautifulSoup(raw_html, 'html.parser')
                    # Remove script and style elements
                    for script in soup(["script", "style", "meta", "link"]):
                        script.extract()
                    extracted_text = soup.get_text(separator=' ', strip=True)
            else:
                # Fallback to BeautifulSoup extraction if trafilatura isn't available
                if self.logger and self.verbose:
                    self.logger.info("Trafilatura not available, using BeautifulSoup for text extraction")
                soup = BeautifulSoup(raw_html, 'html.parser')
                # Remove script and style elements
                for script in soup(["script", "style", "meta", "link"]):
                    script.extract()
                extracted_text = soup.get_text(separator=' ', strip=True)
            
            return raw_html, extracted_text
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error extracting content from {url}: {str(e)}")
            return None, None
    
    def _extract_links(self, url, html):
        """
        Extract all links from the HTML content.
        
        Args:
            url (str): The base URL
            html (str): HTML content
            
        Returns:
            list: List of absolute URLs found
        """
        if not html:
            return []
            
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(url, href)
                
                # Filter out external links, mailto, javascript, etc.
                parsed_url = urlparse(absolute_url)
                parsed_base = urlparse(url)
                
                if (parsed_url.netloc == parsed_base.netloc and
                    not parsed_url.path.endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx'))):
                    links.append(absolute_url)
            
            return links
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error extracting links from {url}: {str(e)}")
            return []
    
    def _scan_content(self, url, html, text):
        """
        Scan page content for sensitive information.
        
        Args:
            url (str): The URL being scanned
            html (str): Raw HTML content
            text (str): Extracted text content
            
        Returns:
            list: List of findings
        """
        findings = []
        
        # First check HTML
        if html:
            for category, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    matches = pattern.findall(html)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]  # Some regex groups return tuples
                        
                        # Skip very short matches that are likely false positives
                        if len(str(match)) < 5:
                            continue
                            
                        # For sensitive data, truncate and add asterisks
                        display_match = str(match)
                        if category in ['API Key', 'AWS Key', 'Password', 'Token', 'Private Key', 'Credit Card']:
                            if len(display_match) > 10:
                                display_match = display_match[:4] + '****' + display_match[-4:]
                        
                        finding = {
                            'type': f'Information Disclosure - {category}',
                            'url': url,
                            'evidence': display_match,
                            'details': f"Found possible {category} in page source",
                            'severity': self._determine_severity(category)
                        }
                        
                        # Check for duplicates
                        if not any(f['evidence'] == finding['evidence'] and f['type'] == finding['type'] for f in findings):
                            findings.append(finding)
        
        # Then check extracted text if it's different enough
        if text and html and len(text) < len(html) * 0.8:  # Only check text if it's different from HTML
            for category, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    matches = pattern.findall(text)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                            
                        # Skip very short matches
                        if len(str(match)) < 5:
                            continue
                        
                        # For sensitive data, truncate and add asterisks
                        display_match = str(match)
                        if category in ['API Key', 'AWS Key', 'Password', 'Token', 'Private Key', 'Credit Card']:
                            if len(display_match) > 10:
                                display_match = display_match[:4] + '****' + display_match[-4:]
                        
                        finding = {
                            'type': f'Information Disclosure - {category}',
                            'url': url,
                            'evidence': display_match,
                            'details': f"Found possible {category} in page content",
                            'severity': self._determine_severity(category)
                        }
                        
                        # Check for duplicates
                        if not any(f['evidence'] == finding['evidence'] and f['type'] == finding['type'] for f in findings):
                            findings.append(finding)
        
        return findings
    
    def _determine_severity(self, category):
        """
        Determine the severity level based on the finding category.
        
        Args:
            category (str): The finding category
            
        Returns:
            str: Severity level (Critical, High, Medium, Low, Info)
        """
        critical_categories = ['API Key', 'AWS Key', 'Private Key', 'Database Connection String']
        high_categories = ['Password', 'Token', 'Credit Card', 'Social Security Number']
        medium_categories = ['Email', 'Phone Number', 'Stack Trace', 'Internal Path']
        
        if category in critical_categories:
            return 'Critical'
        elif category in high_categories:
            return 'High'
        elif category in medium_categories:
            return 'Medium'
        else:
            return 'Low'
    
    def scan(self):
        """
        Start the information disclosure scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        scanned_urls = set()
        urls_to_scan = [self.target_url]
        
        if self.logger:
            self.logger.info(f"Starting information disclosure scan on {self.target_url}")
        
        scan_depth = min(self.depth, 3)  # Limit depth to avoid excessive scanning
        current_depth = 0
        
        while urls_to_scan and current_depth < scan_depth:
            next_urls = []
            
            for url in urls_to_scan:
                if url in scanned_urls:
                    continue
                    
                if self.verbose and self.logger:
                    self.logger.info(f"Scanning for information disclosure on {url}")
                
                html, text = self._extract_page_content(url)
                scanned_urls.add(url)
                
                if html:
                    # Scan the content
                    findings = self._scan_content(url, html, text)
                    vulnerabilities.extend(findings)
                    
                    # Extract links for next depth level
                    if current_depth < scan_depth - 1:
                        links = self._extract_links(url, html)
                        for link in links:
                            if link not in scanned_urls and link not in next_urls:
                                next_urls.append(link)
                
                # Limit the number of findings to avoid excessive outputs
                if len(vulnerabilities) >= 20:
                    if self.logger:
                        self.logger.info("Limiting information disclosure findings to avoid excessive output")
                    break
            
            urls_to_scan = next_urls
            current_depth += 1
            
            # Limit the number of URLs to scan per depth level
            max_urls_per_level = 10
            if len(urls_to_scan) > max_urls_per_level:
                if self.logger:
                    self.logger.info(f"Limiting to {max_urls_per_level} URLs at depth {current_depth}")
                urls_to_scan = urls_to_scan[:max_urls_per_level]
        
        if self.logger:
            self.logger.info(f"Information disclosure scan completed. Found {len(vulnerabilities)} potential issues.")
        
        return vulnerabilities