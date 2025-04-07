"""
Logger utility for WebScan.

Configures and provides logging functionality throughout the application.
"""

import logging
import os
import sys
from datetime import datetime

def setup_logger(log_file='webscan.log', verbose=False):
    """
    Set up and configure the logger.
    
    Args:
        log_file (str): Path to the log file
        verbose (bool): Enable verbose logging
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logger
    logger = logging.getLogger('webscan')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Create file handler
    try:
        file_handler = logging.FileHandler(log_file, mode='a')
        file_level = logging.DEBUG if verbose else logging.INFO
        file_handler.setLevel(file_level)
        
        # Create formatter and add it to the handler
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Add handler to the logger
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not create log file: {str(e)}")
        print(f"Logging to console only")
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_level = logging.DEBUG if verbose else logging.WARNING
    console_handler.setLevel(console_level)
    
    # Create formatter and add it to the handler
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # Add handler to the logger
    logger.addHandler(console_handler)
    
    # Log startup information
    logger.info(f"WebScan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Verbose logging: {'Enabled' if verbose else 'Disabled'}")
    
    return logger

def get_logger():
    """
    Get the existing logger instance or create a new one.
    
    Returns:
        logging.Logger: Logger instance
    """
    logger = logging.getLogger('webscan')
    
    # If logger has no handlers, set up a default one
    if not logger.handlers:
        return setup_logger()
    
    return logger
