"""
Port scanner module.

Scans for open ports on the target host using socket connections.
"""

import socket
import concurrent.futures
from urllib.parse import urlparse
import time

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
        self.timeout = min(timeout, 3)  # Cap timeout for port scanning
        self.depth = depth
        self.logger = logger
        self.verbose = verbose
        
        # Parse the target URL to get the hostname
        parsed_url = urlparse(target_url)
        self.target_host = parsed_url.netloc.split(':')[0]  # Remove port if present
        
        # Define port ranges based on scan depth
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.extended_ports = self.common_ports + list(range(1, 1024))
        self.full_scan_range = 100  # For depth 3, scan more ports in batches (simplified for demo)
    
    def _scan_port(self, port):
        """
        Check if a specific port is open on the target host.
        
        Args:
            port (int): The port number to scan
            
        Returns:
            tuple: (port, is_open, service_name) or None if error
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target_host, port))
            sock.close()
            
            if result == 0:  # Port is open
                try:
                    service_name = socket.getservbyport(port)
                except:
                    service_name = "unknown"
                
                if self.verbose and self.logger:
                    self.logger.info(f"Port {port} is open ({service_name})")
                
                return (port, True, service_name)
            return None
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error scanning port {port}: {str(e)}")
            return None
    
    def _get_ports_to_scan(self):
        """
        Determine which ports to scan based on scan depth.
        
        Returns:
            list: List of port numbers to scan
        """
        if self.depth == 1:
            return self.common_ports
        elif self.depth == 2:
            return self.extended_ports
        else:  # depth >= 3
            # For a more comprehensive scan (simplified for this implementation)
            return list(range(1, 10000))[:self.full_scan_range]
    
    def scan(self):
        """
        Start the port scanning process.
        
        Returns:
            list: List of open port vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting port scan on {self.target_host}")
        
        ports_to_scan = self._get_ports_to_scan()
        open_ports = []
        
        # Use multi-threading for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(ports_to_scan))) as executor:
            future_to_port = {executor.submit(self._scan_port, port): port for port in ports_to_scan}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    port, is_open, service_name = result
                    open_ports.append((port, service_name))
        
        # Create vulnerability entries for open ports
        for port, service_name in open_ports:
            # Determine severity based on the service
            severity = "Medium"  # Default
            details = f"Port {port} ({service_name}) is open"
            
            # Adjust severity based on service/port
            if port in [21, 23, 1433, 3306, 3389]:  # FTP, Telnet, MSSQL, MySQL, RDP
                severity = "High"
                details += ". This service may allow unauthorized access if not properly secured."
            elif port in [22, 443, 8443]:  # SSH, HTTPS
                severity = "Low"
                details += ". Ensure this service is properly secured."
            elif port in [2049, 111, 445]:  # NFS, RPC, SMB
                severity = "High"
                details += ". This network service could expose sensitive data if not properly configured."
            
            vulnerability = {
                'type': 'Open Port',
                'url': self.target_url,
                'port': port,
                'service': service_name,
                'details': details,
                'severity': severity
            }
            
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning(f"Open port found: {port} ({service_name})")
        
        if self.logger:
            self.logger.info(f"Port scan completed. Found {len(vulnerabilities)} open ports.")
        
        return vulnerabilities
