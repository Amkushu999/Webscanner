"""
Sensitive Files scanner module.

Tests for the presence of sensitive or backup files that
might expose confidential information.
"""

import requests
from urllib.parse import urljoin, urlparse
import concurrent.futures

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
        
        # Parse the target URL
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Common sensitive file patterns
        self.sensitive_files = [
            # Version control
            ".git/HEAD",
            ".git/config",
            ".git/index",
            ".gitignore",
            ".svn/entries",
            ".svn/wc.db",
            ".hg/store/00manifest.i",
            ".hg/dirstate",
            "CVS/Entries",
            "CVS/Root",
            ".bzr/checkout/dirstate",
            
            # Backup files
            "backup/",
            "backup.zip",
            "backup.tar",
            "backup.tar.gz",
            "backup.tgz",
            "backup.rar",
            "backup.sql",
            "backup.sql.gz",
            "backup.bak",
            "bak/",
            "old/",
            "temp/",
            "tmp/",
            
            # Configuration files
            "config.php",
            "config.inc.php",
            "configuration.php",
            "settings.php",
            "settings.inc.php",
            "settings.ini",
            "database.php",
            "db.php",
            "db.inc.php",
            "db_config.php",
            "conf.php",
            "config.json",
            "config.yaml",
            "config.yml",
            
            # WordPress files
            "wp-config.php",
            "wp-config.php.bak",
            "wp-config.php~",
            "wp-config.php.save",
            ".wp-config.php.swp",
            
            # Content Management Systems
            "joomla.xml",
            "configuration.php",
            "administrator/",
            "administrator/index.php",
            "administrator/manifests/files/joomla.xml",
            "drupal/CHANGELOG.txt",
            "CHANGELOG.txt",  # Drupal
            "sites/default/settings.php",  # Drupal
            "sites/default/private/files/",  # Drupal
            "admin/config.php",
            "typo3conf/",
            "typo3conf/LocalConfiguration.php",
            
            # Log files
            "logs/",
            "log/",
            "logs/access.log",
            "logs/error.log",
            "log/access.log",
            "log/error.log",
            "error.log",
            "access.log",
            "access_log",
            "error_log",
            
            # Server configuration
            ".htaccess",
            ".htpasswd",
            "httpd.conf",
            "apache.conf",
            "web.config",
            "nginx.conf",
            "php.ini",
            
            # Readme and debug files
            "README",
            "README.md",
            "README.txt",
            "INSTALL",
            "INSTALL.md",
            "INSTALL.txt",
            "CHANGELOG",
            "CHANGELOG.md",
            "CHANGELOG.txt",
            "debug.php",
            "debug.asp",
            "debug.aspx",
            "debug.jsp",
            "debug/",
            "test.php",
            "test.asp",
            "test.aspx",
            "test.jsp",
            "phpinfo.php",
            "info.php",
            
            # Development files
            ".env",
            ".npmrc",
            ".dockerignore",
            "Dockerfile",
            "docker-compose.yml",
            "Gemfile",
            "Gruntfile.js",
            "gulpfile.js",
            "package.json",
            "composer.json",
            "bower.json",
            
            # Server-side includes
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            
            # Common exposed administrative interfaces
            "admin/",
            "admin.php",
            "administrator/",
            "administration/",
            "phpmyadmin/",
            "phpmyadmin/index.php",
            "phpMyAdmin/",
            "myadmin/",
            "manager/",
            "manage/",
            "user/",
            "users/",
            "login/",
            "login.php",
            "login.asp",
            "login.aspx",
            "wp-login.php",
            
            # Common file backups by editors
            "index.php~",
            "index.php.bak",
            "index.php.old",
            ".index.php.swp",
            "index.php.save"
        ]
        
        # Extend list for higher depth levels
        if depth >= 2:
            self.sensitive_files.extend([
                # Additional backup patterns
                "backup.old",
                "backup.1",
                "backup.2",
                "site.bak",
                "site.old",
                "website.bak",
                "www.tar.gz",
                "www.zip",
                "data.sql",
                "database.sql",
                "users.sql",
                
                # Additional configuration files
                "config.txt",
                "config.old",
                ".config",
                ".config.php.swp",
                "system.config",
                "settings.bak",
                
                # Additional log files
                "server.log",
                "php_error.log",
                "mysql.log",
                "mysql_error.log",
                "debug.log",
                
                # Additional CMS files
                "administrator/logs/",
                "wp-content/debug.log",
                "typo3/install.php",
                "config/database.yml"
            ])
        
        # Even more files for higher depth
        if depth >= 3:
            self.sensitive_files.extend([
                # Additional backup patterns with more variation
                "site.tar.gz",
                "backup_[0-9].zip",
                "backup_[0-9][0-9].zip",
                "backup.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].zip",
                "www.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].tar.gz",
                
                # Additional development files
                ".babelrc",
                ".eslintrc",
                ".travis.yml",
                "webpack.config.js",
                "yarn.lock",
                "pom.xml",
                "build.gradle",
                "requirements.txt",
                "Pipfile",
                "Pipfile.lock",
                
                # Additional server configuration
                ".bash_history",
                ".ssh/id_rsa",
                ".ssh/id_rsa.pub",
                ".ssh/authorized_keys",
                ".mysql_history",
                ".DS_Store",
                "Thumbs.db",
                
                # Various additional interesting files
                "credentials.txt",
                "users.txt",
                "passwords.txt",
                "email.txt",
                "customer.csv",
                "customers.csv",
                "users.csv",
                "passwords.csv",
                "secret.txt",
                "secret_key.txt",
                "keys.txt",
                "api_keys.txt",
                "oauth.txt",
                "oauth_keys.txt"
            ])
    
    def _construct_file_paths(self):
        """
        Construct file paths to test based on the target URL.
        
        Returns:
            list: List of file paths to check
        """
        file_paths = []
        
        # Add base URL paths
        for file_path in self.sensitive_files:
            file_paths.append(urljoin(self.base_url, file_path))
        
        # If the URL has a path, try that directory as well
        path = self.parsed_url.path
        if path and path != '/':
            # Remove trailing slash and filename if present
            if path.endswith('/'):
                directory_path = path
            else:
                if '.' in path.split('/')[-1]:  # Likely a file
                    directory_path = '/'.join(path.split('/')[:-1]) + '/'
                else:
                    directory_path = path
                    if not directory_path.endswith('/'):
                        directory_path += '/'
            
            for file_path in self.sensitive_files:
                file_paths.append(urljoin(self.base_url + directory_path, file_path))
        
        # Remove duplicates
        file_paths = list(set(file_paths))
        
        return file_paths
    
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
            
            # If HEAD request fails, try GET
            if response.status_code >= 400:
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True  # Use streaming to avoid downloading large files
                )
                
                # Read only the first chunk to determine if file exists
                for chunk in response.iter_content(chunk_size=1024):
                    break
                
                response.close()
            
            # Check if file exists (common success status codes)
            if response.status_code in [200, 201, 203, 206]:
                content_length = response.headers.get('Content-Length', 'unknown')
                content_type = response.headers.get('Content-Type', 'unknown')
                
                if self.verbose and self.logger:
                    self.logger.info(f"Found file: {url} (Status: {response.status_code}, Type: {content_type}, Length: {content_length})")
                
                return (url, response.status_code, content_length, content_type)
            
            return None
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error checking file {url}: {str(e)}")
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
        # Critical severity files
        if any(fp in file_path.lower() for fp in [
            '.git/', '.svn/', '.env', 'config.php', 'wp-config.php', 'settings.php', 
            'database.php', 'db.php', '.htpasswd', 'backup.sql', '.ssh/'
        ]):
            return 'Critical'
        
        # High severity files
        if any(fp in file_path.lower() for fp in [
            'backup', '.bak', '.old', 'passwords', 'credentials', 'users.sql',
            'admin', 'login', 'phpinfo.php', 'info.php', '.htaccess'
        ]):
            return 'High'
        
        # Medium severity files
        if any(fp in file_path.lower() for fp in [
            'log', 'error', 'debug', 'test.php', 'config', '.yml', '.yaml',
            'docker', 'dockerfile', 'compose', 'sitemap.xml'
        ]):
            return 'Medium'
        
        # Lower severity for everything else
        if 'text/plain' in content_type or 'text/html' in content_type:
            return 'Low'
        
        return 'Info'
    
    def scan(self):
        """
        Start the sensitive file scan.
        
        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        if self.logger:
            self.logger.info(f"Starting sensitive file scan on {self.target_url}")
        
        file_paths = self._construct_file_paths()
        
        if self.verbose and self.logger:
            self.logger.info(f"Testing {len(file_paths)} potential sensitive files")
        
        # Use multi-threading for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(file_paths))) as executor:
            future_to_url = {executor.submit(self._check_file_exists, url): url for url in file_paths}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                if result:
                    url, status_code, content_length, content_type = result
                    
                    # Determine the severity based on file type
                    severity = self._determine_severity(url, content_type)
                    
                    # Extract the relative path
                    relative_path = url.replace(self.base_url, '')
                    if not relative_path.startswith('/'):
                        relative_path = '/' + relative_path
                    
                    # Create vulnerability entry
                    vulnerability = {
                        'type': 'Sensitive File Exposure',
                        'url': url,
                        'file_path': relative_path,
                        'status_code': status_code,
                        'content_type': content_type,
                        'content_length': content_length,
                        'details': f"Sensitive file {relative_path} found on the server",
                        'severity': severity
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    if self.logger:
                        self.logger.warning(f"Sensitive file found: {relative_path} (Severity: {severity})")
        
        if self.logger:
            self.logger.info(f"Sensitive file scan completed. Found {len(vulnerabilities)} files.")
        
        return vulnerabilities
