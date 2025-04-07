"""
SSL/TLS scanner module.

Tests for SSL/TLS configuration issues, weak ciphers, and known vulnerabilities.
"""

import socket
import ssl
import re
import os
import time
import datetime
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
        
        # Check for TLSv1.3 support (Python 3.7+)
        # Since TLSv1.3 might be available through different means in various Python versions
        try:
            if hasattr(ssl, 'PROTOCOL_TLS'):  # Use the most modern approach
                # In newer Python versions, PROTOCOL_TLS includes TLSv1.3 support
                self.protocols.append(('TLSv1.3', ssl.PROTOCOL_TLS))
            # We don't use PROTOCOL_TLSv1_3 directly as it's not consistently available
        except Exception as e:
            if self.logger and self.verbose:
                self.logger.debug(f"TLSv1.3 protocol not available: {str(e)}")
        
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
                    
                    # Process the certificate fields safely
                    cert_dict = {}
                    try:
                        # Process subject
                        if 'subject' in cert:
                            # Process the RDNs manually without using a dictionary comprehension
                            subject_dict = {}
                            for rdn in cert['subject']:
                                if rdn and len(rdn) > 0:
                                    for item in rdn:
                                        if isinstance(item, tuple) and len(item) >= 2:
                                            k, v = item[0], item[1]
                                            subject_dict[k] = v
                            cert_dict['subject'] = subject_dict
                        else:
                            cert_dict['subject'] = {}
                            
                        # Process issuer
                        if 'issuer' in cert:
                            # Process the RDNs manually without using a dictionary comprehension
                            issuer_dict = {}
                            for rdn in cert['issuer']:
                                if rdn and len(rdn) > 0:
                                    for item in rdn:
                                        if isinstance(item, tuple) and len(item) >= 2:
                                            k, v = item[0], item[1]
                                            issuer_dict[k] = v
                            cert_dict['issuer'] = issuer_dict
                        else:
                            cert_dict['issuer'] = {}
                    except (TypeError, ValueError, IndexError) as e:
                        if self.logger and self.verbose:
                            self.logger.warning(f"Error extracting certificate fields: {str(e)}")
                        # Use a simple approach if the above fails
                        cert_dict['subject'] = str(cert.get('subject', ''))
                        cert_dict['issuer'] = str(cert.get('issuer', ''))
                        
                    return {
                        'subject': cert_dict['subject'],
                        'issuer': cert_dict['issuer'],
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
        More sophisticated check for Heartbleed vulnerability (CVE-2014-0160).
        
        This implementation sends a crafted TLS heartbeat request to the server
        and checks if it responds with more data than was sent, which would 
        indicate the Heartbleed vulnerability.
        
        Returns:
            bool: True if potentially vulnerable to Heartbleed, False otherwise
        """
        import struct
        import binascii
        
        # Warning: This function sends specially crafted packets to check for Heartbleed.
        # While this implementation should be safe, use it responsibly and only on systems
        # you are authorized to test.
        
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.hostname, self.port))
            
            # Craft a TLS handshake packet
            # Send a Client Hello message
            client_hello = b"".join([
                b"\x16",                  # Content Type: Handshake
                b"\x03\x01",              # Version: TLS 1.0 
                b"\x00\x9a",              # Length: 154
                b"\x01",                  # Handshake Type: Client Hello
                b"\x00\x00\x96",          # Length: 150
                b"\x03\x03",              # Version: TLS 1.2
                os.urandom(32),           # Random (32 bytes)
                b"\x00",                  # Session ID Length: 0
                b"\x00\x2e",              # Cipher Suites Length: 46
                # List of cipher suites (23 suites, 2 bytes each)
                b"\x00\x33\x00\x39\x00\x2f\x00\x35\x00\x0a\x00\x05\x00\x04\xc0\x13\xc0\x09\xc0\x1f\xc0\x14\xc0\x0a",
                # More cipher suites
                b"\x00\x32\x00\x38\x00\x13\x00\x12\x00\x0d\x00\x0c\x00\x07\x00\x16\x00\x15\x00\x03\x00\x02\x00\x01",
                b"\x01",                  # Compression Method Length: 1
                b"\x00",                  # Compression Method: null
                b"\x00\x41",              # Extensions Length: 65
                # Extension: heartbeat (RFC 6520)
                b"\x00\x0f\x00\x01\x01"
            ])
            
            sock.send(client_hello)
            
            # Wait for Server Hello response and complete the handshake
            # This is a simplified handshake just to reach the heartbeat stage
            try:
                while True:
                    record_header = sock.recv(5)
                    if not record_header or len(record_header) < 5:
                        break
                        
                    content_type, version, length = struct.unpack('>BHH', record_header)
                    payload = sock.recv(length)
                    
                    # Looking for Server Hello Done (content_type=22, handshake_type=14)
                    if content_type == 22 and payload and payload[0] == 14:
                        break
            except socket.timeout:
                return False
                
            # Now send the heartbeat request with a small payload but large request length
            heartbeat = b"".join([
                b"\x18",          # Content Type: Heartbeat
                b"\x03\x03",      # Version: TLS 1.2
                b"\x00\x03",      # Length: 3
                b"\x01",          # Heartbeat Request Type
                b"\x40\x00"       # Length: 16384 (way too large, a vulnerable server will return 16KB)
            ])
            
            sock.send(heartbeat)
            
            # Try to read the response - vulnerable servers will return more data than sent
            try:
                response = b""
                start_time = time.time()
                
                while time.time() - start_time < self.timeout:
                    try:
                        chunk = sock.recv(16384)  # Try to receive a large amount of data
                        if not chunk:
                            break
                        response += chunk
                        
                        # If we get back significantly more data than we sent in the heartbeat,
                        # the server is likely vulnerable to Heartbleed
                        if len(response) > 20:  # Simple threshold for demonstration
                            sock.close()
                            return True
                    except socket.timeout:
                        break
            
            except Exception as e:
                if self.logger and self.verbose:
                    self.logger.debug(f"Exception during heartbeat response: {str(e)}")
            
            sock.close()
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
        Check if the server supports weak ciphers by actively testing multiple cipher suites.
        
        Returns:
            list: List of supported weak ciphers
        """
        supported_weak_ciphers = []
        
        # Define weak cipher strings for testing
        weak_cipher_suites = [
            'NULL', 'aNULL', 'eNULL', 'ADH', 'EXP', 'DES', 'RC4', 'MD5', 'PSK', 
            '3DES', 'IDEA', 'SEED', 'SHA1', 'SHA', 'TLS_RSA_WITH_DES_CBC_SHA',
            'TLS_DHE_RSA_WITH_DES_CBC_SHA', 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
            'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_MD5'
        ]
        
        try:
            # Test each weak cipher individually
            for weak_cipher in weak_cipher_suites:
                try:
                    # Create context with specific cipher
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Try to set specific cipher (may not work in all Python versions)
                    try:
                        context.set_ciphers(weak_cipher)
                    except ssl.SSLError:
                        # If setting this cipher fails, it's likely not supported by Python
                        continue
                    
                    with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                        try:
                            with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                                cipher_info = ssock.cipher()
                                if cipher_info:
                                    cipher_name = cipher_info[0]
                                    if self.verbose and self.logger:
                                        self.logger.info(f"Server accepted weak cipher: {cipher_name}")
                                    supported_weak_ciphers.append(cipher_name)
                        except ssl.SSLError as ssle:
                            # This likely means the server rejected this cipher
                            if self.verbose and self.logger:
                                self.logger.debug(f"Server rejected cipher {weak_cipher}: {str(ssle)}")
                except Exception as e:
                    if self.verbose and self.logger:
                        self.logger.debug(f"Error testing cipher {weak_cipher}: {str(e)}")
                    continue
            
            # Fallback method: check the default cipher as well
            if not supported_weak_ciphers:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        # Get current cipher
                        current_cipher = ssock.cipher()
                        if current_cipher:
                            cipher_name = current_cipher[0]
                            # Check if the current cipher contains any weak patterns
                            for weak_cipher in weak_cipher_suites:
                                if weak_cipher in cipher_name.upper():
                                    supported_weak_ciphers.append(cipher_name)
            
            # Use direct OpenSSL command if available
            if not supported_weak_ciphers and self.verbose and self.logger:
                self.logger.info("No weak ciphers detected through Python SSL. For a more comprehensive test, consider using OpenSSL directly.")
            
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
        
        # Use a set to deduplicate the ciphers before reporting them
        unique_weak_ciphers = set(weak_ciphers)
        
        for cipher in unique_weak_ciphers:
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
        
        # Check for Heartbleed vulnerability (CVE-2014-0160)
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
