"""
HTTP utility functions for WebScan.

Provides common HTTP functions used by various scanner modules.
"""

import requests
from urllib.parse import urlparse

def is_url_accessible(url, timeout=10):
    """
    Check if a URL is accessible.
    
    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds
        
    Returns:
        bool: True if the URL is accessible, False otherwise
    """
    try:
        response = requests.head(
            url, 
            timeout=timeout, 
            allow_redirects=True
        )
        
        # If HEAD request fails, try GET
        if response.status_code >= 400:
            response = requests.get(
                url, 
                timeout=timeout, 
                allow_redirects=True,
                stream=True  # Use streaming to avoid downloading large content
            )
            
            # Read only a small part to check if site is up
            for chunk in response.iter_content(chunk_size=1024):
                break
            
            response.close()
        
        # Return True for successful status codes
        return response.status_code < 400
    
    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.TooManyRedirects:
        return False
    except requests.exceptions.RequestException:
        return False
    except Exception:
        return False

def normalize_url(url):
    """
    Normalize a URL to ensure consistent format.
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: Normalized URL
    """
    parsed_url = urlparse(url)
    
    # Ensure scheme is present
    if not parsed_url.scheme:
        url = 'http://' + url
        parsed_url = urlparse(url)
    
    # Remove trailing slash from domain
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if not parsed_url.path or parsed_url.path == '/':
        return base_url
    
    # Keep path and query
    return url

def extract_domain(url):
    """
    Extract the domain from a URL.
    
    Args:
        url (str): The URL to extract domain from
        
    Returns:
        str: Domain name
    """
    parsed_url = urlparse(url)
    return parsed_url.netloc

def generate_url_variations(base_url):
    """
    Generate variations of a URL for fuzzing.
    
    Args:
        base_url (str): The base URL
        
    Returns:
        list: List of URL variations
    """
    parsed_url = urlparse(base_url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # Generate variations
    variations = [
        base_url,
        f"{parsed_url.scheme}://{domain}/",
    ]
    
    # Add path variations
    if path and path != '/':
        path_parts = path.strip('/').split('/')
        
        # Add variations of the path by removing parts from the end
        for i in range(len(path_parts)):
            partial_path = '/'.join(path_parts[:len(path_parts)-i])
            variations.append(f"{parsed_url.scheme}://{domain}/{partial_path}")
    
    return list(set(variations))  # Remove duplicates
