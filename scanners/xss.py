"""
Cross-Site Scripting (XSS) scanner module.

Tests for reflected and stored XSS vulnerabilities by injecting payloads
and analyzing responses.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re

class XSSScanner:
    """Scanner for detecting Cross-Site Scripting vulnerabilities."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the XSS scanner.
        
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
        
        # XSS payloads to test
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "<img src=\"javascript:alert('XSS')\">",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<input type=\"text\" onfocus=\"alert('XSS')\">",
            "<details open ontoggle=\"alert('XSS')\">",
            "<marquee onstart=\"alert('XSS')\">",
            "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert('XSS')\">Click me</maction></math>"
        ]
    
    def _extract_forms(self, url):
        """
        Extract all forms from a URL.
        
        Args:
            url (str): The URL to extract forms from
            
        Returns:
            list: List of dictionaries containing form details
        """
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code != 200:
                return []
                
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_details = {}
                action = form.get('action', '')
                form_details['action'] = urljoin(url, action) if action else url
                form_details['method'] = form.get('method', 'get').lower()
                form_details['inputs'] = []
                
                for input_tag in form.find_all(['input', 'textarea']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')
                    input_value = input_tag.get('value', '')
                    
                    if input_name:  # Only include inputs with names
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name,
                            'value': input_value
                        })
                
                forms.append(form_details)
            
            return forms
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error extracting forms from {url}: {str(e)}")
            return []
    
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
    
    def _extract_links(self, url):
        """
        Extract all links from a URL.
        
        Args:
            url (str): The URL to extract links from
            
        Returns:
            list: List of links found
        """
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code != 200:
                return []
                
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = urlparse(url).scheme + "://" + urlparse(url).netloc
            links = []
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                
                # Only include links from the same domain
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    links.append(full_url)
            
            return links
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error extracting links from {url}: {str(e)}")
            return []
    
    def _scan_get_parameters(self, url):
        """
        Test URL GET parameters for XSS vulnerabilities.
        
        Args:
            url (str): The URL to test
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        parameters = self._extract_parameters(url)
        if not parameters:
            return vulnerabilities
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing GET parameters in URL: {url}")
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        for param_name, param_values in parameters.items():
            for payload in self.payloads:
                test_url = f"{base_url}?{param_name}={payload}"
                
                # Add other parameters back
                for p_name, p_values in parameters.items():
                    if p_name != param_name:
                        test_url += f"&{p_name}={p_values[0]}"
                
                try:
                    if self.verbose and self.logger:
                        self.logger.info(f"Testing payload on parameter '{param_name}': {payload}")
                    
                    response = requests.get(
                        test_url, 
                        headers=self.headers, 
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    # Check if the payload is reflected in the response
                    if self._is_xss_successful(response.text, payload):
                        detail = f"Parameter '{param_name}' is vulnerable to XSS using payload: {payload}"
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'method': 'GET',
                            'parameter': param_name,
                            'payload': payload,
                            'details': detail,
                            'severity': 'High'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"XSS found: {detail}")
                        
                        # No need to test more payloads for this parameter
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing GET parameter '{param_name}': {str(e)}")
        
        return vulnerabilities
    
    def _scan_form(self, form_details, url):
        """
        Test a form for XSS vulnerabilities.
        
        Args:
            form_details (dict): Form details including inputs
            url (str): The URL containing the form
            
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        if not form_details['inputs']:
            return vulnerabilities
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing form on URL: {url}, Action: {form_details['action']}")
        
        for payload in self.payloads:
            # We'll test each input field one by one
            for input_field in form_details['inputs']:
                # Skip non-text inputs (checkboxes, submit buttons, etc.)
                if input_field['type'] not in ['text', 'search', 'email', 'url', 'password', 'hidden', '', 'textarea']:
                    continue
                
                # Prepare data for the form submission
                data = {}
                for input_tag in form_details['inputs']:
                    if input_tag['name'] == input_field['name']:
                        data[input_tag['name']] = payload
                    elif input_tag['type'] != 'submit':  # Handle other non-submit inputs
                        data[input_tag['name']] = input_tag['value']
                
                if self.verbose and self.logger:
                    self.logger.info(f"Testing form field '{input_field['name']}' with payload: {payload}")
                
                try:
                    if form_details['method'] == 'post':
                        response = requests.post(
                            form_details['action'],
                            data=data,
                            headers=self.headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:  # GET
                        response = requests.get(
                            form_details['action'],
                            params=data,
                            headers=self.headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    
                    # Check if the payload is reflected in the response
                    if self._is_xss_successful(response.text, payload):
                        detail = f"Form field '{input_field['name']}' is vulnerable to XSS using payload: {payload}"
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'method': form_details['method'].upper(),
                            'form_action': form_details['action'],
                            'parameter': input_field['name'],
                            'payload': payload,
                            'details': detail,
                            'severity': 'High'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"XSS found: {detail}")
                        
                        # No need to test more payloads for this field
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing form field '{input_field['name']}': {str(e)}")
        
        return vulnerabilities
    
    def _is_xss_successful(self, response_content, payload):
        """
        Check if XSS payload was successfully injected.
        
        Args:
            response_content (str): The response content to check
            payload (str): The XSS payload that was injected
            
        Returns:
            bool: True if XSS is successful, False otherwise
        """
        # This is a simplified check. In a real-world scenario, 
        # more sophisticated checks would be needed
        return payload in response_content
    
    def _can_escape_context(self, response_content, payload):
        """
        Check if payload can escape the current context.
        
        Args:
            response_content (str): The response content to check
            payload (str): The XSS payload that was injected
            
        Returns:
            bool: True if payload can escape context, False otherwise
        """
        # Look for payload in dangerous contexts (simplified)
        soup = BeautifulSoup(response_content, 'html.parser')
        
        # Check if payload is in script tag
        for script in soup.find_all('script'):
            if payload in script.text:
                return True
        
        # Check if payload is in attribute values
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if isinstance(value, str) and payload in value:
                    return True
        
        # Check if payload is directly in HTML
        if re.search(re.escape(payload), str(soup), re.IGNORECASE):
            return True
        
        return False
    
    def scan(self):
        """
        Start the XSS vulnerability scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting XSS scan on {self.target_url}")
        
        # Test GET parameters in the main URL
        vulnerabilities.extend(self._scan_get_parameters(self.target_url))
        
        # Extract and test forms
        forms = self._extract_forms(self.target_url)
        for form in forms:
            vulnerabilities.extend(self._scan_form(form, self.target_url))
        
        # If depth > 1, crawl the site and test additional pages
        if self.depth > 1 and self.logger:
            self.logger.info(f"Crawling for additional links (depth: {self.depth})")
            
            # Simple crawling implementation (limited for brevity)
            links_to_visit = self._extract_links(self.target_url)
            visited_links = {self.target_url}
            
            current_depth = 1
            while current_depth < self.depth and links_to_visit:
                new_links = []
                
                for link in links_to_visit:
                    if link not in visited_links:
                        visited_links.add(link)
                        
                        # Test GET parameters in this link
                        vulnerabilities.extend(self._scan_get_parameters(link))
                        
                        # Extract and test forms in this link
                        link_forms = self._extract_forms(link)
                        for form in link_forms:
                            vulnerabilities.extend(self._scan_form(form, link))
                        
                        # Extract new links for the next depth level
                        if current_depth + 1 < self.depth:
                            new_links.extend([l for l in self._extract_links(link) if l not in visited_links])
                
                links_to_visit = new_links
                current_depth += 1
        
        if self.logger:
            self.logger.info(f"XSS scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        
        return vulnerabilities
