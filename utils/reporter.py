"""
Reporter utility for WebScan.

Generates detailed vulnerability reports in various formats.
"""

import os
import json
from datetime import datetime

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
