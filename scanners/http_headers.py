"""
HTTP Headers scanner module.

Analyzes HTTP response headers to identify missing security headers
and other security issues.
"""

import requests
from urllib.parse import urlparse

class HTTPHeaderScanner:
    """Scanner for detecting HTTP header security issues."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the HTTP Headers scanner.
        
        Args:
            target_url (str): The target URL to scan
            timeout (int): Request timeout in seconds
            depth (int): Not used for header scanning but required for consistency
            user_agent (str): User-Agent string to use in requests
            logger: Logger instance
            verbose (bool): Enable verbose output
        """
        self.target_url = target_url
        self.timeout = timeout
        self.headers = {'User-Agent': user_agent}
        self.logger = logger
        self.verbose = verbose
        
        # Security headers that should be present
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'HTTP Strict Transport Security (HSTS) header is missing. This header helps to protect against protocol downgrade attacks and cookie hijacking.',
                'severity': 'Medium',
                'recommendation': 'Add the header with a value like "max-age=31536000; includeSubDomains".'
            },
            'Content-Security-Policy': {
                'description': 'Content Security Policy (CSP) header is missing. This header helps to prevent Cross-Site Scripting (XSS) and data injection attacks.',
                'severity': 'Medium',
                'recommendation': 'Implement a proper Content Security Policy that restricts resource loading.'
            },
            'X-Content-Type-Options': {
                'description': 'X-Content-Type-Options header is missing. This header prevents MIME-sniffing a response away from the declared content-type.',
                'severity': 'Low',
                'recommendation': 'Add the header with the value "nosniff".'
            },
            'X-Frame-Options': {
                'description': 'X-Frame-Options header is missing. This header protects against clickjacking attacks.',
                'severity': 'Medium',
                'recommendation': 'Add the header with a value like "SAMEORIGIN" or "DENY".'
            },
            'X-XSS-Protection': {
                'description': 'X-XSS-Protection header is missing. This header enables the cross-site scripting filter in browsers.',
                'severity': 'Low',
                'recommendation': 'Add the header with a value like "1; mode=block".'
            },
            'Referrer-Policy': {
                'description': 'Referrer-Policy header is missing. This header controls how much referrer information should be included with requests.',
                'severity': 'Low',
                'recommendation': 'Add the header with a value like "strict-origin-when-cross-origin".'
            },
            'Permissions-Policy': {
                'description': 'Permissions-Policy header is missing. This header restricts which browser features can be used.',
                'severity': 'Info',
                'recommendation': 'Consider adding this header to restrict access to browser features.'
            },
            'Cache-Control': {
                'description': 'Cache-Control header is missing. This header directs browsers and other intermediaries how to cache the response.',
                'severity': 'Low',
                'recommendation': 'Add cache control directives appropriate for your content.'
            }
        }
        
        # Headers that should be analyzed for weak values
        self.analyze_headers = {
            'Server': {
                'description': 'Server header reveals detailed server information.',
                'severity': 'Low',
                'recommendation': 'Configure your web server to remove or minimize server information.'
            },
            'X-Powered-By': {
                'description': 'X-Powered-By header reveals technology information.',
                'severity': 'Low',
                'recommendation': 'Configure your web server or application to remove this header.'
            },
            'X-AspNet-Version': {
                'description': 'X-AspNet-Version header reveals ASP.NET version.',
                'severity': 'Low',
                'recommendation': 'Configure your web server to remove this header.'
            },
            'X-AspNetMvc-Version': {
                'description': 'X-AspNetMvc-Version header reveals ASP.NET MVC version.',
                'severity': 'Low',
                'recommendation': 'Configure your web server to remove this header.'
            },
            'Access-Control-Allow-Origin': {
                'description': 'Access-Control-Allow-Origin header has an overly permissive value.',
                'severity': 'Medium',
                'recommendation': 'Restrict CORS to specific origins instead of using wildcard (*).'
            }
        }
        
        # Cookie security attributes to check
        self.cookie_attributes = [
            ('HttpOnly', 'Cookie missing HttpOnly flag, which helps mitigate the risk of client-side script accessing the cookie.', 'Medium'),
            ('Secure', 'Cookie missing Secure flag, which ensures the cookie is only sent over HTTPS.', 'Medium'),
            ('SameSite', 'Cookie missing SameSite attribute, which helps mitigate CSRF attacks.', 'Low')
        ]
    
    def _analyze_cookie_security(self, cookies):
        """
        Analyze cookie security based on missing security attributes.
        
        Args:
            cookies (list): List of cookies from response
            
        Returns:
            list: Vulnerabilities found in cookies
        """
        vulnerabilities = []
        
        for cookie in cookies:
            cookie_name = cookie.name
            missing_attributes = []
            
            # Check for missing security attributes
            for attr_name, description, severity in self.cookie_attributes:
                if attr_name.lower() == 'httponly' and not cookie.has_nonstandard_attr('HttpOnly'):
                    missing_attributes.append(('HttpOnly', description, severity))
                elif attr_name.lower() == 'secure' and not cookie.secure:
                    missing_attributes.append(('Secure', description, severity))
                elif attr_name.lower() == 'samesite' and not any(a.startswith('SameSite') for a in cookie._rest.keys()):
                    missing_attributes.append(('SameSite', description, severity))
            
            # Report each missing attribute as a separate vulnerability
            for attr_name, description, severity in missing_attributes:
                vulnerability = {
                    'type': 'Insecure Cookie',
                    'url': self.target_url,
                    'cookie_name': cookie_name,
                    'missing_attribute': attr_name,
                    'details': f"Cookie '{cookie_name}' is missing the {attr_name} attribute. {description}",
                    'severity': severity,
                    'recommendation': f"Add the {attr_name} attribute to the cookie."
                }
                
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Insecure cookie found: '{cookie_name}' missing {attr_name}")
        
        return vulnerabilities
    
    def _analyze_header_values(self, headers):
        """
        Analyze header values for potential security issues.
        
        Args:
            headers (dict): Response headers
            
        Returns:
            list: Vulnerabilities found in header values
        """
        vulnerabilities = []
        
        for header_name, header_info in self.analyze_headers.items():
            if header_name in headers:
                header_value = headers[header_name]
                
                if header_name == 'Server' and header_value and len(header_value) > 4:
                    # Check if server header reveals detailed information
                    server_parts = header_value.split('/')
                    if len(server_parts) > 1 or any(s in header_value.lower() for s in ['apache', 'nginx', 'iis', 'version']):
                        vulnerability = {
                            'type': 'Information Disclosure',
                            'url': self.target_url,
                            'header': header_name,
                            'value': header_value,
                            'details': f"{header_info['description']} Value: '{header_value}'",
                            'severity': header_info['severity'],
                            'recommendation': header_info['recommendation']
                        }
                        vulnerabilities.append(vulnerability)
                
                elif header_name == 'X-Powered-By' or header_name == 'X-AspNet-Version' or header_name == 'X-AspNetMvc-Version':
                    # These headers should ideally be removed
                    vulnerability = {
                        'type': 'Information Disclosure',
                        'url': self.target_url,
                        'header': header_name,
                        'value': header_value,
                        'details': f"{header_info['description']} Value: '{header_value}'",
                        'severity': header_info['severity'],
                        'recommendation': header_info['recommendation']
                    }
                    vulnerabilities.append(vulnerability)
                
                elif header_name == 'Access-Control-Allow-Origin' and header_value == '*':
                    # Check for overly permissive CORS
                    vulnerability = {
                        'type': 'Insecure CORS Configuration',
                        'url': self.target_url,
                        'header': header_name,
                        'value': header_value,
                        'details': f"{header_info['description']} Value: '{header_value}'",
                        'severity': header_info['severity'],
                        'recommendation': header_info['recommendation']
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _check_ssl_redirect(self, headers, url):
        """
        Check if HTTP redirects to HTTPS properly.
        
        Args:
            headers (dict): Response headers
            url (str): The URL that was tested
            
        Returns:
            dict or None: Vulnerability if HTTP doesn't redirect to HTTPS, None otherwise
        """
        parsed_url = urlparse(url)
        
        # Only check for HTTP URLs
        if parsed_url.scheme != 'http':
            return None
        
        # Check for redirect to HTTPS
        if headers.get('Location', '').startswith('https://'):
            return None
        
        # No redirect to HTTPS found
        return {
            'type': 'Missing HTTPS Redirect',
            'url': url,
            'details': 'HTTP does not redirect to HTTPS. This can allow attackers to intercept data in transit.',
            'severity': 'Medium',
            'recommendation': 'Configure the server to redirect all HTTP traffic to HTTPS.'
        }
    
    def scan(self):
        """
        Start the HTTP header security scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting HTTP header scan on {self.target_url}")
        
        try:
            # Make the request to the target URL
            response = requests.get(
                self.target_url, 
                headers=self.headers, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Check for missing security headers
            for header_name, header_info in self.security_headers.items():
                if header_name not in response.headers:
                    vulnerability = {
                        'type': 'Missing Security Header',
                        'url': self.target_url,
                        'header': header_name,
                        'details': header_info['description'],
                        'severity': header_info['severity'],
                        'recommendation': header_info['recommendation']
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Missing security header: {header_name}")
            
            # Analyze header values for security issues
            header_vulnerabilities = self._analyze_header_values(response.headers)
            vulnerabilities.extend(header_vulnerabilities)
            
            # Check cookie security
            if response.cookies:
                cookie_vulnerabilities = self._analyze_cookie_security(response.cookies)
                vulnerabilities.extend(cookie_vulnerabilities)
            
            # Check HTTP to HTTPS redirect
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme == 'http':
                # Try the HTTP version to see if it redirects to HTTPS
                redirect_vulnerability = self._check_ssl_redirect(response.headers, self.target_url)
                if redirect_vulnerability:
                    vulnerabilities.append(redirect_vulnerability)
            else:
                # Try the HTTP version of the site if the target is HTTPS
                http_url = self.target_url.replace('https://', 'http://')
                try:
                    http_response = requests.get(
                        http_url, 
                        headers=self.headers, 
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    redirect_vulnerability = self._check_ssl_redirect(http_response.headers, http_url)
                    if redirect_vulnerability:
                        vulnerabilities.append(redirect_vulnerability)
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing HTTP redirect: {str(e)}")
            
            if self.logger:
                self.logger.info(f"HTTP header scan completed. Found {len(vulnerabilities)} issues.")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during HTTP header scan: {str(e)}")
        
        return vulnerabilities
