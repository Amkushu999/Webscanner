"""
SSL/TLS scanner module.

Tests for SSL/TLS configuration issues, weak ciphers, and known vulnerabilities.
"""

import socket
import ssl
import re
from urllib.parse import urlparse

class SSLTLSScanner:
    """Scanner for detecting SSL/TLS configuration issues and vulnerabilities."""
    
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
        
        # Parse the target URL
        parsed_url = urlparse(target_url)
        self.hostname = parsed_url.netloc.split(':')[0]  # Remove port if present
        
        # If port is specified in the URL, use it; otherwise, use default HTTPS port
        if ':' in parsed_url.netloc:
            self.port = int(parsed_url.netloc.split(':')[1])
        else:
            self.port = 443
        
        # SSL/TLS protocols to test
        self.protocols = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),
            ('SSLv3', ssl.PROTOCOL_SSLv23),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2)
        ]
        
        # Add TLSv1.3 if available (Python 3.7+)
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            self.protocols.append(('TLSv1.3', ssl.PROTOCOL_TLSv1_3))
        
        # Weak ciphers to check for
        self.weak_ciphers = [
            'NULL',
            'EXPORT',
            'DES',
            '3DES',
            'RC2',
            'RC4',
            'MD5',
            'SHA1',
            'DHE-RSA-AES128-SHA',
            'DHE-RSA-AES256-SHA',
            'ADH',
            'AECDH',
            'ANULL',
        ]
    
    def _get_server_certificate(self):
        """
        Get the server's SSL certificate.
        
        Returns:
            dict: Certificate information or None if error
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    if not cert:
                        return None
                    
                    # Extract certificate version (index 0 is the dict version)
                    version = ssl.OPENSSL_VERSION_INFO[0]
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': version,
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'serialNumber': cert.get('serialNumber', 'Unknown'),
                        'cipher': cipher
                    }
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error getting server certificate: {str(e)}")
            return None
    
    def _test_protocol_support(self, protocol_name, protocol_const):
        """
        Test if the server supports a specific SSL/TLS protocol.
        
        Args:
            protocol_name (str): Name of the protocol
            protocol_const: SSL protocol constant
            
        Returns:
            bool: True if protocol is supported, False otherwise
        """
        try:
            context = ssl.SSLContext(protocol_const)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # For older protocols, we need to set specific options
            if protocol_name == 'SSLv2':
                # Try to enable SSLv2 (will likely fail on modern Python)
                try:
                    context.options &= ~ssl.OP_NO_SSLv2
                except:
                    pass
            elif protocol_name == 'SSLv3':
                # Try to enable SSLv3
                try:
                    context.options &= ~ssl.OP_NO_SSLv3
                except:
                    pass
            
            # Disable newer protocols based on what we're testing
            if protocol_name == 'SSLv3' or protocol_name == 'SSLv2':
                context.options |= ssl.OP_NO_TLSv1
                context.options |= ssl.OP_NO_TLSv1_1
                context.options |= ssl.OP_NO_TLSv1_2
                if hasattr(ssl, 'OP_NO_TLSv1_3'):
                    context.options |= ssl.OP_NO_TLSv1_3
            elif protocol_name == 'TLSv1.0':
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_TLSv1_1
                context.options |= ssl.OP_NO_TLSv1_2
                if hasattr(ssl, 'OP_NO_TLSv1_3'):
                    context.options |= ssl.OP_NO_TLSv1_3
            elif protocol_name == 'TLSv1.1':
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_TLSv1
                context.options |= ssl.OP_NO_TLSv1_2
                if hasattr(ssl, 'OP_NO_TLSv1_3'):
                    context.options |= ssl.OP_NO_TLSv1_3
            elif protocol_name == 'TLSv1.2':
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_TLSv1
                context.options |= ssl.OP_NO_TLSv1_1
                if hasattr(ssl, 'OP_NO_TLSv1_3'):
                    context.options |= ssl.OP_NO_TLSv1_3
            elif protocol_name == 'TLSv1.3':
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_TLSv1
                context.options |= ssl.OP_NO_TLSv1_1
                context.options |= ssl.OP_NO_TLSv1_2
            
            with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cipher = ssock.cipher()
                    if self.verbose and self.logger:
                        self.logger.info(f"Protocol {protocol_name} is supported. Cipher: {cipher}")
                    return True
        
        except Exception as e:
            if self.verbose and self.logger:
                self.logger.info(f"Protocol {protocol_name} is not supported: {str(e)}")
            return False
    
    def _check_heartbleed(self):
        """
        Simplified check for Heartbleed vulnerability.
        This is a placeholder - a real Heartbleed check would need more sophisticated testing.
        
        Returns:
            bool: True if potentially vulnerable to Heartbleed, False otherwise
        """
        # This is a simplified detection method that checks for OpenSSL versions
        # known to be vulnerable to Heartbleed
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Get server's chosen cipher
                    cipher = ssock.cipher()
                    
                    # This is an oversimplified check
                    # A real check would send a crafted heartbeat request
                    # but that would be potentially harmful to the target
                    
                    # If OpenSSL is used and protocol is TLSv1.1 or TLSv1.2,
                    # there might be a risk of Heartbleed
                    if self._test_protocol_support('TLSv1.1', ssl.PROTOCOL_TLSv1_1) or \
                       self._test_protocol_support('TLSv1.2', ssl.PROTOCOL_TLSv1_2):
                        # This is just an indicator, not a confirmation
                        # We'd need to know the exact OpenSSL version to be sure
                        return True
                    
                    return False
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking for Heartbleed: {str(e)}")
            return False
    
    def _check_certificate_validity(self, cert):
        """
        Check certificate validity dates.
        
        Args:
            cert (dict): Certificate information
            
        Returns:
            tuple: (is_valid, issue_description)
        """
        import datetime
        import time
        
        # Parse certificate dates
        try:
            not_before = cert['notBefore']
            not_after = cert['notAfter']
            
            # OpenSSL date format: 'May  9 00:00:00 2018 GMT'
            time_format = r'%b %d %H:%M:%S %Y GMT'
            
            # Fix the format to handle single-digit days
            not_before = re.sub(r' (\d) ', r' 0\1 ', not_before)
            not_after = re.sub(r' (\d) ', r' 0\1 ', not_after)
            
            not_before_date = datetime.datetime.strptime(not_before, time_format)
            not_after_date = datetime.datetime.strptime(not_after, time_format)
            current_date = datetime.datetime.utcnow()
            
            # Check if certificate is not yet valid
            if current_date < not_before_date:
                return (False, "Certificate is not yet valid")
            
            # Check if certificate has expired
            if current_date > not_after_date:
                return (False, "Certificate has expired")
            
            # Check if certificate is about to expire (within 30 days)
            thirty_days = datetime.timedelta(days=30)
            if current_date + thirty_days > not_after_date:
                return (True, "Certificate will expire soon (within 30 days)")
            
            return (True, "Certificate is valid")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking certificate validity: {str(e)}")
            return (False, "Unable to verify certificate validity")
    
    def _check_weak_ciphers(self):
        """
        Check if the server supports weak ciphers.
        
        Returns:
            list: List of supported weak ciphers
        """
        supported_weak_ciphers = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to set cipher list to include weak ciphers
            # Note: This is limited by what Python's SSL library supports
            # A full check would need a tool like OpenSSL command line
            
            with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Get current cipher
                    current_cipher = ssock.cipher()
                    if current_cipher:
                        cipher_name = current_cipher[0]
                        # Check if the current cipher is considered weak
                        for weak_cipher in self.weak_ciphers:
                            if weak_cipher in cipher_name:
                                supported_weak_ciphers.append(cipher_name)
            
            return supported_weak_ciphers
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking weak ciphers: {str(e)}")
            return []
    
    def _check_certificate_chain(self):
        """
        Check certificate chain for issues.
        This is a simplified check that merely verifies if the chain is complete.
        
        Returns:
            tuple: (is_valid, issue_description)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        # If we reach here, certificate chain is valid
                        return (True, "Certificate chain is valid")
                except ssl.SSLError as e:
                    error_msg = str(e)
                    if "certificate verify failed" in error_msg:
                        return (False, "Certificate chain validation failed")
                    elif "hostname doesn't match" in error_msg:
                        return (False, "Certificate hostname verification failed")
                    else:
                        return (False, f"SSL error: {error_msg}")
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking certificate chain: {str(e)}")
            return (False, f"Unable to verify certificate chain: {str(e)}")
    
    def scan(self):
        """
        Start the SSL/TLS vulnerability scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting SSL/TLS scan on {self.hostname}:{self.port}")
        
        # Skip SSL/TLS scan for non-HTTPS URLs
        if urlparse(self.target_url).scheme != "https":
            if self.logger:
                self.logger.info(f"Skipping SSL/TLS scan as the URL is not HTTPS")
            return vulnerabilities
        
        # Test protocol support
        for protocol_name, protocol_const in self.protocols:
            try:
                is_supported = self._test_protocol_support(protocol_name, protocol_const)
                
                # Report vulnerabilities for outdated protocols
                if is_supported and protocol_name in ['SSLv2', 'SSLv3', 'TLSv1.0']:
                    severity = 'Critical' if protocol_name in ['SSLv2', 'SSLv3'] else 'High'
                    vulnerability = {
                        'type': 'Insecure Protocol',
                        'url': self.target_url,
                        'protocol': protocol_name,
                        'details': f"Server supports insecure protocol: {protocol_name}",
                        'severity': severity,
                        'recommendation': f"Disable support for {protocol_name} on the server."
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Insecure protocol found: {protocol_name}")
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error testing protocol {protocol_name}: {str(e)}")
        
        # Get server certificate
        cert = self._get_server_certificate()
        if cert:
            # Check certificate validity
            is_valid, validity_issue = self._check_certificate_validity(cert)
            if not is_valid or "expire soon" in validity_issue:
                severity = 'High' if not is_valid else 'Medium'
                vulnerability = {
                    'type': 'Certificate Issue',
                    'url': self.target_url,
                    'details': f"Certificate validity issue: {validity_issue}",
                    'severity': severity,
                    'recommendation': "Update the SSL certificate to a valid one."
                }
                
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Certificate issue found: {validity_issue}")
            
            # Check certificate chain
            chain_valid, chain_issue = self._check_certificate_chain()
            if not chain_valid:
                vulnerability = {
                    'type': 'Certificate Chain Issue',
                    'url': self.target_url,
                    'details': chain_issue,
                    'severity': 'Medium',
                    'recommendation': "Ensure the complete certificate chain is properly installed."
                }
                
                vulnerabilities.append(vulnerability)
                
                if self.logger:
                    self.logger.warning(f"Certificate chain issue found: {chain_issue}")
        
        # Check for weak ciphers
        weak_ciphers = self._check_weak_ciphers()
        for cipher in weak_ciphers:
            vulnerability = {
                'type': 'Weak Cipher',
                'url': self.target_url,
                'cipher': cipher,
                'details': f"Server supports weak cipher: {cipher}",
                'severity': 'Medium',
                'recommendation': "Disable support for weak ciphers on the server."
            }
            
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning(f"Weak cipher found: {cipher}")
        
        # Check for Heartbleed vulnerability
        # Note: This is a simplified check
        if self._check_heartbleed():
            vulnerability = {
                'type': 'Potential Heartbleed Vulnerability',
                'url': self.target_url,
                'details': "Server might be vulnerable to Heartbleed (CVE-2014-0160).",
                'severity': 'Critical',
                'recommendation': "Update OpenSSL to a version not vulnerable to Heartbleed."
            }
            
            vulnerabilities.append(vulnerability)
            
            if self.logger:
                self.logger.warning("Potential Heartbleed vulnerability detected")
        
        if self.logger:
            self.logger.info(f"SSL/TLS scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        
        return vulnerabilities
