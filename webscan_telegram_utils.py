#!/usr/bin/env python3
"""
Utility functions for the WebScan Telegram bot.
These functions provide additional functionality needed for the Telegram integration.
"""

# Define scan types and their descriptions
SCAN_TYPES = {
    'all': 'All scan types (comprehensive)',
    'sqli': 'SQL Injection (database vulnerabilities)',
    'xss': 'Cross-Site Scripting (injection attacks)',
    'port': 'Open Port Scanning (service detection)',
    'dir': 'Directory Traversal (path manipulation)',
    'files': 'Sensitive Files (configs, backups, logs)',
    'headers': 'HTTP Headers (security header issues)',
    'ssl': 'SSL/TLS (weak ciphers, protocols)',
    'info': 'Information Disclosure (metadata, paths)'
}

def get_scan_type_descriptions():
    """
    Get scan type descriptions for use in the Telegram bot.
    
    Returns:
        dict: A dictionary mapping scan type ids to their human-readable descriptions
    """
    return SCAN_TYPES