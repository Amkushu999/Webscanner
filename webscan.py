#!/usr/bin/env python3
"""
WebScan - Advanced Website Vulnerability Scanner

A comprehensive command-line tool for detecting various web vulnerabilities,
with multi-threaded scanning capabilities and detailed reporting.
"""

import argparse
import concurrent.futures
import sys
import time
import os
from urllib.parse import urlparse

from colorama import init, Fore, Style

from scanners.sql_injection import SQLInjectionScanner
from scanners.xss import XSSScanner
from scanners.port_scan import PortScanner
from scanners.directory_traversal import DirectoryTraversalScanner
from scanners.sensitive_files import SensitiveFileScanner
from scanners.http_headers import HTTPHeaderScanner
from scanners.ssl_tls import SSLTLSScanner
from scanners.info_disclosure import InfoDisclosureScanner

from utils.logger import setup_logger
from utils.reporter import Reporter
from utils.http_utils import is_url_accessible

# Initialize colorama
init(autoreset=True)

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
    
    logger = setup_logger(args.log_file, args.verbose)
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
