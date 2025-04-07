#!/usr/bin/env python3
"""
WebScan Telegram Bot - Run website vulnerability scans from Telegram

This bot allows users to run vulnerability scans remotely using the Telegram
messaging platform. It integrates with the WebScan standalone script to provide
security assessment capabilities from any device with Telegram.

Features:
- Run website vulnerability scans remotely
- Configure scan parameters through bot commands
- Receive notifications when scans are complete
- View scan summaries and download detailed reports
- Supports various scan types and configurations

Developed by AMKUSH
"""

import os
import logging
import asyncio
import re
import json
import time
import threading
import queue
import concurrent.futures
import functools
import gc
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Callable
import tempfile
from io import StringIO
import sys
from pathlib import Path
import argparse

# Telegram imports - for version 13.x
try:
    from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
    from telegram.ext import (
        Updater,
        CommandHandler,
        MessageHandler,
        Filters,
        CallbackQueryHandler,
        CallbackContext,
        ConversationHandler,
    )
except ImportError:
    print("Error importing telegram modules. Make sure you have python-telegram-bot version 13.15 installed.")
    print("Run: pip install python-telegram-bot==13.15")
    sys.exit(1)

# Import the webscan_standalone modules and utility functions
# Use a try/except to handle when imported vs. when run as a script
try:
    # pylint: disable=import-error
    from webscan_standalone import (
        VERSION,
        ScanArgs,
        setup_logger,
        run_scan_on_target,
        print_banner,
    )
    from webscan_telegram_utils import (
        SCAN_TYPES,
        get_scan_type_descriptions,
    )
except ImportError:
    # When run directly, the webscan_standalone module might not be in the path
    import importlib.util
    import sys
    
    # Load the webscan_standalone module dynamically
    try:
        spec = importlib.util.spec_from_file_location("webscan_standalone", "webscan_standalone.py")
        if spec and spec.loader:
            webscan_standalone = importlib.util.module_from_spec(spec)
            sys.modules["webscan_standalone"] = webscan_standalone
            spec.loader.exec_module(webscan_standalone)
        else:
            raise ImportError("Failed to load webscan_standalone module")
        
        # Load the telegram utils module dynamically
        spec_utils = importlib.util.spec_from_file_location("webscan_telegram_utils", "webscan_telegram_utils.py")
        if spec_utils and spec_utils.loader:
            webscan_telegram_utils = importlib.util.module_from_spec(spec_utils)
            sys.modules["webscan_telegram_utils"] = webscan_telegram_utils
            spec_utils.loader.exec_module(webscan_telegram_utils)
        else:
            raise ImportError("Failed to load webscan_telegram_utils module")
    except Exception as e:
        print(f"Error loading modules: {str(e)}")
        sys.exit(1)
    
    # Import required functions and classes
    VERSION = webscan_standalone.VERSION
    ScanArgs = webscan_standalone.ScanArgs
    setup_logger = webscan_standalone.setup_logger
    run_scan_on_target = webscan_standalone.run_scan_on_target
    print_banner = webscan_standalone.print_banner
    SCAN_TYPES = webscan_telegram_utils.SCAN_TYPES
    get_scan_type_descriptions = webscan_telegram_utils.get_scan_type_descriptions

# Setup logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("webscan_telegram")

# User session states for conversation handler
CHOOSING_SCAN_TYPE, ENTERING_URL, CONFIGURING_SCAN, RUNNING_SCAN = range(4)

# Store user scan configurations with automatic cleanup (using custom LRU cache)
class LRUCache:
    """Limited size cache that automatically removes least recently used items."""
    
    def __init__(self, max_size=10000):
        self.cache = {}
        self.max_size = max_size
        self.timestamps = {}
        self.lock = threading.RLock()  # Thread-safe operations
    
    def __getitem__(self, key):
        with self.lock:
            if key not in self.cache:
                raise KeyError(key)
            self.timestamps[key] = time.time()
            return self.cache[key]
    
    def __setitem__(self, key, value):
        with self.lock:
            self.cache[key] = value
            self.timestamps[key] = time.time()
            # Clean up if we're over the max size
            if len(self.cache) > self.max_size:
                self._cleanup()
    
    def __contains__(self, key):
        with self.lock:
            return key in self.cache
    
    def _cleanup(self):
        """Remove oldest 10% of items when cache is full."""
        items_to_remove = max(1, int(self.max_size * 0.1))
        # Sort by timestamp and keep only the newest
        items = sorted(self.timestamps.items(), key=lambda x: x[1])
        for key, _ in items[:items_to_remove]:
            del self.cache[key]
            del self.timestamps[key]
    
    def get(self, key, default=None):
        """Get item with default value if not found."""
        with self.lock:
            if key not in self.cache:
                return default
            self.timestamps[key] = time.time()
            return self.cache[key]
    
    def cleanup_older_than(self, seconds):
        """Remove items older than specified seconds."""
        with self.lock:
            current_time = time.time()
            keys_to_remove = []
            for key, timestamp in self.timestamps.items():
                if current_time - timestamp > seconds:
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del self.cache[key]
                del self.timestamps[key]

# Store user scan configurations and ongoing scans with high capacity
user_configs = LRUCache(max_size=1000000)  # Support up to 1 million users
active_scans = LRUCache(max_size=1000000)  # Support up to 1 million active scans

# Create a thread pool for running scans
scan_thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=100)

# Create a queue for processing results
result_queue = queue.Queue()

# Scan semaphore to limit concurrent scans (avoid overwhelming server)
# This allows up to 200 concurrent scans
scan_semaphore = threading.BoundedSemaphore(value=200)

# List of authorized users (if AUTHORIZED_USERS env var is set)
authorized_users = os.environ.get("AUTHORIZED_USERS", "").split(",")
if authorized_users and authorized_users[0]:
    authorized_users = [int(user_id.strip()) for user_id in authorized_users if user_id.strip()]
    logger.info(f"Authorized users configured: {authorized_users}")
else:
    authorized_users = []
    logger.info("No user restrictions configured. Anyone can use the bot.")

# Auth decorator
def restricted(func):
    """Decorator to restrict bot usage to authorized users only."""
    def wrapped(update: Update, context: CallbackContext, *args, **kwargs):
        user_id = update.effective_user.id
        if authorized_users and user_id not in authorized_users:
            logger.warning(f"Unauthorized access attempt by user {user_id}")
            update.message.reply_text(
                "⛔ You are not authorized to use this bot.\n"
                "Please contact the administrator if you need access."
            )
            return
        return func(update, context, *args, **kwargs)
    return wrapped

# Helper function to generate scan configuration keyboard
def get_scan_config_keyboard() -> InlineKeyboardMarkup:
    """Generate keyboard with scan configuration options."""
    keyboard = [
        [
            InlineKeyboardButton("Scan Types", callback_data="config_scan_types"),
            InlineKeyboardButton("Scan Depth", callback_data="config_depth"),
        ],
        [
            InlineKeyboardButton("Threads", callback_data="config_threads"),
            InlineKeyboardButton("Timeout", callback_data="config_timeout"),
        ],
        [
            InlineKeyboardButton("Verbose Mode", callback_data="config_verbose"),
            InlineKeyboardButton("Aggressive Mode", callback_data="config_aggressive"),
        ],
        [
            InlineKeyboardButton("✅ Run Scan", callback_data="run_scan"),
            InlineKeyboardButton("❌ Cancel", callback_data="cancel_scan"),
        ],
    ]
    return InlineKeyboardMarkup(keyboard)

# Helper function to generate scan types keyboard
def get_scan_types_keyboard() -> InlineKeyboardMarkup:
    """Generate keyboard with scan types options."""
    descriptions = get_scan_type_descriptions()
    keyboard = []
    
    # Add 'all' first
    keyboard.append([InlineKeyboardButton(f"All Types - {descriptions.get('all', '')}", callback_data="type_all")])
    
    # Add specific scan types (2 per row)
    specific_types = []
    for scan_type, description in descriptions.items():
        if scan_type != "all":
            specific_types.append(InlineKeyboardButton(f"{scan_type} - {description}", callback_data=f"type_{scan_type}"))
    
    # Group into pairs
    for i in range(0, len(specific_types), 2):
        if i + 1 < len(specific_types):
            keyboard.append([specific_types[i], specific_types[i + 1]])
        else:
            keyboard.append([specific_types[i]])
    
    # Add done button
    keyboard.append([InlineKeyboardButton("✅ Done", callback_data="types_done")])
    
    return InlineKeyboardMarkup(keyboard)

# Helper function to capture console output
class OutputCapture:
    """Class to capture stdout and stderr for sending to Telegram."""
    
    def __init__(self):
        self.captured_output = StringIO()
        self.original_stdout = None
        self.original_stderr = None
    
    def start_capture(self):
        """Start capturing stdout and stderr."""
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        sys.stdout = self.captured_output
        sys.stderr = self.captured_output
    
    def stop_capture(self) -> str:
        """Stop capturing and return the captured output."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        return self.captured_output.getvalue()

# The actual scan function that runs in a separate thread
def _run_scan_worker(args: ScanArgs, user_id: int, progress_message_id: int, bot, output_path: str, log_path: str):
    """Worker function that runs the scan in a separate thread."""
    
    # Setup a custom logger for the scan
    scan_logger = setup_logger(args.log_file, logging.DEBUG if args.verbose else logging.INFO, False)
    
    # Capture console output
    output_capture = OutputCapture()
    output_capture.start_capture()
    
    # Use semaphore to limit concurrent scans
    with scan_semaphore:
        try:
            # Run the scan
            run_scan_on_target(args, scan_logger, show_summary=True)
            
            # Get captured output
            console_output = output_capture.stop_capture()
            
            # Update scan status
            active_scans[user_id]["status"] = "completed"
            active_scans[user_id]["end_time"] = datetime.now()
            
            # Read the report
            try:
                with open(output_path, 'r') as f:
                    report_content = f.read()
                    
                # Extract summary (first 3500 characters, preserving line structure)
                report_summary = report_content[:3500]
                if len(report_content) > 3500:
                    report_summary += "\n...(truncated)...\n"
                    
                # Update progress message
                bot.edit_message_text(
                    chat_id=user_id,
                    message_id=progress_message_id,
                    text=f"✅ Scan completed for {args.url}\n\n"
                         f"Scan duration: {(active_scans[user_id]['end_time'] - active_scans[user_id]['start_time']).total_seconds():.1f} seconds\n\n"
                         "📋 Summary of findings:"
                )
                
                # Send the summary
                bot.send_message(
                    chat_id=user_id,
                    text=f"```\n{report_summary}\n```",
                    parse_mode="Markdown"
                )
                
                # Send the report as a file
                with open(output_path, 'rb') as f:
                    bot.send_document(
                        chat_id=user_id,
                        document=f,
                        filename=f"webscan_report_{args.url.replace('://', '_').replace('/', '_')}.txt",
                        caption=f"Full scan report for {args.url}"
                    )
                
                # Send the log file
                with open(log_path, 'rb') as f:
                    bot.send_document(
                        chat_id=user_id,
                        document=f,
                        filename=f"webscan_log_{args.url.replace('://', '_').replace('/', '_')}.log",
                        caption=f"Scan log for {args.url}"
                    )
                
                # Provide options to run another scan
                keyboard = [
                    [InlineKeyboardButton("🔄 Run Another Scan", callback_data="new_scan")],
                    [InlineKeyboardButton("📊 Show Detailed Report", callback_data=f"show_report_{args.url}")],
                ]
                bot.send_message(
                    chat_id=user_id,
                    text="What would you like to do next?",
                    reply_markup=InlineKeyboardMarkup(keyboard)
                )
                
            except Exception as e:
                logger.error(f"Error reading scan report: {str(e)}")
                bot.send_message(
                    chat_id=user_id,
                    text=f"⚠️ Scan completed but there was an error reading the report: {str(e)}"
                )
        
        except Exception as e:
            output_capture.stop_capture()
            logger.error(f"Error running scan: {str(e)}")
            
            active_scans[user_id]["status"] = "failed"
            active_scans[user_id]["error"] = str(e)
            
            try:
                bot.edit_message_text(
                    chat_id=user_id,
                    message_id=progress_message_id,
                    text=f"❌ Scan failed for {args.url}\n\nError: {str(e)}"
                )
            except Exception as msg_err:
                logger.error(f"Error updating message: {str(msg_err)}")
                try:
                    bot.send_message(
                        chat_id=user_id,
                        text=f"❌ Scan failed for {args.url}\n\nError: {str(e)}"
                    )
                except:
                    pass
        
        finally:
            # Clean up resources
            gc.collect()  # Force garbage collection to free memory

# Helper to run scan asynchronously
def run_scan_async(args: ScanArgs, update: Update, context: CallbackContext):
    """Run a scan asynchronously and send results to the user."""
    user_id = update.effective_user.id
    
    # Check if user already has a scan running
    existing_scan = active_scans.get(user_id)
    if existing_scan and existing_scan.get("status") == "running":
        update.message.reply_text(
            "⚠️ You already have a scan in progress. Please wait for it to complete or use /cancel to stop it."
        )
        return
    
    # Create a progress message
    progress_message = context.bot.send_message(
        chat_id=user_id,
        text="🔍 Starting scan...\n\n"
             f"Target: {args.url}\n"
             f"Scan types: {', '.join(args.scan_types)}\n\n"
             "This may take a while depending on the target and scan configuration."
    )
    
    # Set up temporary files for output
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as output_file:
        output_path = output_file.name
    
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as log_file:
        log_path = log_file.name
    
    # Configure the args for output
    args.output = output_path
    args.log_file = log_path
    
    # Store status info
    active_scans[user_id] = {
        "status": "running",
        "start_time": datetime.now(),
        "target": args.url,
        "output_path": output_path,
        "log_path": log_path,
        "message_id": progress_message.message_id,
    }
    
    # Submit the scan job to the thread pool
    try:
        scan_thread_pool.submit(
            _run_scan_worker, 
            args, 
            user_id, 
            progress_message.message_id, 
            context.bot,
            output_path, 
            log_path
        )
        logger.info(f"Submitted scan job for user {user_id}, target {args.url}")
    except Exception as e:
        logger.error(f"Error submitting scan job: {str(e)}")
        context.bot.edit_message_text(
            chat_id=user_id,
            message_id=progress_message.message_id,
            text=f"❌ Failed to start scan: {str(e)}"
        )
        
        # Update status
        active_scans[user_id]["status"] = "failed"
        active_scans[user_id]["error"] = str(e)

# Command handlers
@restricted
def start_command(update: Update, context: CallbackContext) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    
    # Skip the animation and directly display the welcome message
    # This avoids issues with empty messages during animation
    try:
        update.message.reply_text(
            f"👋 Hi {user.first_name}! Welcome to the WebScan Telegram Bot.\n\n"
            f"I can help you run security scans on websites directly from Telegram.\n\n"
            f"🔍 Use /scan to start a new vulnerability scan\n"
            f"❓ Use /help to see all available commands\n"
            f"ℹ️ Use /about to learn more about this bot\n\n"
            f"Version: WebScan v{VERSION}"
        )
    except Exception as e:
        logger.error(f"Error sending welcome message: {str(e)}")
        # If sending fails, try one more time with a simpler message
        try:
            update.message.reply_text(
                f"👋 Hi {user.first_name}! Welcome to WebScan.\n\n"
                f"Use /scan to start a scan, /help for commands."
            )
        except Exception as e2:
            logger.error(f"Failed to send fallback message: {str(e2)}")

@restricted
def help_command(update: Update, context: CallbackContext) -> None:
    """Send a message when the command /help is issued."""
    update.message.reply_text(
        "📋 Available Commands:\n\n"
        "/scan - Start a new vulnerability scan\n"
        "/status - Check status of ongoing scans\n"
        "/cancel - Cancel ongoing scan\n"
        "/config - View or modify your scan configuration\n"
        "/help - Show this help message\n"
        "/about - About this bot\n\n"
        "To scan a website, simply use the /scan command and follow the prompts."
    )

@restricted
def about_command(update: Update, context: CallbackContext) -> None:
    """Send information about the bot."""
    # Pink color for AMKUSH
    amkush_text = "Developed by \033[95mAMKUSH\033[0m"
    
    # First send a loading message
    loading_msg = update.message.reply_text("Loading WebScan information...")
    
    # Create the ASCII banner
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗  ║
║  ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║  ║
║  ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║  ║
║  ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║  ║
║  ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║  ║
║   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║
║                                                                  ║
║  Advanced Website Vulnerability Scanner                        ║
║  Version {version:8} Telegram Bot                            ║
║  Developed by AMKUSH                                           ║
╚══════════════════════════════════════════════════════════════════╝
    """.format(version=VERSION)
    
    # Animate the features
    features = [
        "➤ Multi-threaded scanning engine",
        "➤ Advanced detection for SQLi, XSS, and other vulnerabilities",
        "➤ SSL/TLS vulnerability detection",
        "➤ Information disclosure identification",
        "➤ Directory traversal testing",
        "➤ Sensitive file exposure checks"
    ]
    
    try:
        # Show the banner first
        context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=loading_msg.message_id,
            text=f"```\n{banner}\n```",
            parse_mode="Markdown"
        )
        
        time.sleep(1.0)  # Longer pause to appreciate the banner
        
        # Now animate the features one by one for dramatic effect
        current_text = f"```\n{banner}\n```\n\n"
        current_text += "WebScan is an advanced website vulnerability scanner with real-world exploitation techniques.\n\n"
        current_text += "Features:\n"
        
        # Update the message with features added one at a time
        for feature in features:
            current_text += f"{feature}\n"
            
            # Update the message with the new feature
            context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=loading_msg.message_id,
                text=current_text + "\nThis Telegram bot provides a convenient interface to run scans remotely.",
                parse_mode="Markdown"
            )
            time.sleep(0.6)  # Increased delay for slow motion effect
        
        # Final message
        context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=loading_msg.message_id,
            text=f"```\n{banner}\n```\n\n"
            "WebScan is an advanced website vulnerability scanner with real-world exploitation techniques.\n\n"
            "Features:\n"
            "➤ Multi-threaded scanning engine\n"
            "➤ Advanced detection for SQLi, XSS, and other vulnerabilities\n"
            "➤ SSL/TLS vulnerability detection\n"
            "➤ Information disclosure identification\n"
            "➤ Directory traversal testing\n"
            "➤ Sensitive file exposure checks\n\n"
            "This Telegram bot provides a convenient interface to run scans remotely.",
            parse_mode="Markdown"
        )
        
    except Exception as e:
        logger.error(f"Animation error in about_command: {str(e)}")
        # Fallback if animation fails
        update.message.reply_text(
            f"```\n{banner}\n```\n\n"
            "WebScan is an advanced website vulnerability scanner with real-world exploitation techniques.\n\n"
            "Features:\n"
            "➤ Multi-threaded scanning engine\n"
            "➤ Advanced detection for SQLi, XSS, and other vulnerabilities\n"
            "➤ SSL/TLS vulnerability detection\n"
            "➤ Information disclosure identification\n"
            "➤ Directory traversal testing\n"
            "➤ Sensitive file exposure checks\n\n"
            "This Telegram bot provides a convenient interface to run scans remotely.",
            parse_mode="Markdown"
        )

@restricted
def scan_command(update: Update, context: CallbackContext) -> int:
    """Start the scan process by asking for the target URL."""
    user_id = update.effective_user.id
    
    # Initialize new scan configuration for this user
    user_configs[user_id] = ScanArgs()
    user_configs[user_id].scan_types = ["info", "headers", "ssl"]  # Default to safer scan types
    user_configs[user_id].verbose = True
    user_configs[user_id].show_progress = True
    user_configs[user_id].threads = 3
    user_configs[user_id].depth = 1
    user_configs[user_id].timeout = 10
    
    update.message.reply_text(
        "🔍 Let's start a website vulnerability scan.\n\n"
        "Please enter the URL you want to scan (e.g., https://example.com):\n\n"
        "Make sure to include the full URL with http:// or https://"
    )
    
    return ENTERING_URL

@restricted
def url_entered(update: Update, context: CallbackContext) -> int:
    """Process the URL provided by the user."""
    user_id = update.effective_user.id
    url = update.message.text.strip()
    
    # Validate URL format
    url_pattern = re.compile(r'^(http|https)://[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}(:[0-9]{1,5})?(/.*)?$')
    
    if not url_pattern.match(url):
        update.message.reply_text(
            "⚠️ Invalid URL format. Please enter a valid URL including http:// or https://\n\n"
            "Example: https://example.com"
        )
        return ENTERING_URL
    
    # Store the URL in user configuration
    user_configs[user_id].url = url
    
    # Show scan configuration options
    update.message.reply_text(
        f"🎯 Target: {url}\n\n"
        "Now, let's configure your scan. Choose from the options below:",
        reply_markup=get_scan_config_keyboard()
    )
    
    return CONFIGURING_SCAN

@restricted
def handle_scan_config(update: Update, context: CallbackContext) -> int:
    """Handle scan configuration options."""
    query = update.callback_query
    user_id = update.effective_user.id
    
    # Ensure the notification is answered
    query.answer()
    
    if query.data == "run_scan":
        # Show scan preview and confirmation
        config = user_configs[user_id]
        query.edit_message_text(
            f"📋 Scan Configuration Preview:\n\n"
            f"🎯 Target: {config.url}\n"
            f"🔍 Scan Types: {', '.join(config.scan_types)}\n"
            f"🔄 Threads: {config.threads}\n"
            f"🕸️ Depth: {config.depth}\n"
            f"⏱️ Timeout: {config.timeout}s\n"
            f"🔊 Verbose: {'Yes' if config.verbose else 'No'}\n"
            f"⚡ Aggressive: {'Yes' if config.aggressive else 'No'}\n\n"
            f"Confirm to start the scan?",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Confirm", callback_data="confirm_scan")],
                [InlineKeyboardButton("🔙 Back to Config", callback_data="back_to_config")],
                [InlineKeyboardButton("❌ Cancel", callback_data="cancel_scan")],
            ])
        )
        return CONFIGURING_SCAN
    
    elif query.data == "confirm_scan":
        # Start the actual scan
        query.edit_message_text("🚀 Initializing scan...")
        
        # Get user's scan configuration
        args = user_configs[user_id]
        
        # Run the scan in a separate thread to not block the bot
        import threading
        thread = threading.Thread(target=run_scan_async, args=(args, update, context))
        thread.daemon = True
        thread.start()
        
        return ConversationHandler.END
    
    elif query.data == "back_to_config":
        # Go back to configuration menu
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n\n"
            "Configure your scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "config_scan_types":
        # Show scan types selection
        query.edit_message_text(
            "Select the scan types you want to run:",
            reply_markup=get_scan_types_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data.startswith("type_"):
        # Handle scan type selection
        scan_type = query.data.replace("type_", "")
        
        if scan_type == "all":
            # Set to all scan types
            user_configs[user_id].scan_types = ["all"]
        else:
            # Add specific scan type if not already in the list
            if "all" in user_configs[user_id].scan_types:
                user_configs[user_id].scan_types = [scan_type]
            elif scan_type not in user_configs[user_id].scan_types:
                user_configs[user_id].scan_types.append(scan_type)
            
        # Update the message to show current selection
        types_str = ", ".join(user_configs[user_id].scan_types)
        query.answer(f"Added: {scan_type}")
        
        # Re-display the keyboard with updated selection
        query.edit_message_text(
            f"Current selection: {types_str}\n\nSelect scan types:",
            reply_markup=get_scan_types_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "types_done":
        # Return to main config menu
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n"
            f"🔍 Scan Types: {', '.join(user_configs[user_id].scan_types)}\n\n"
            "Configure other scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "config_depth":
        # Show depth configuration options
        keyboard = [
            [
                InlineKeyboardButton("1 (Fastest)", callback_data="depth_1"),
                InlineKeyboardButton("2", callback_data="depth_2"),
                InlineKeyboardButton("3 (Thorough)", callback_data="depth_3"),
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_config")],
        ]
        query.edit_message_text(
            f"Current depth: {user_configs[user_id].depth}\n\n"
            "Select scan depth (higher values scan more pages but take longer):",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return CONFIGURING_SCAN
    
    elif query.data.startswith("depth_"):
        # Set scan depth
        depth = int(query.data.replace("depth_", ""))
        user_configs[user_id].depth = depth
        query.answer(f"Depth set to {depth}")
        
        # Return to main config
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n"
            f"🔍 Scan Types: {', '.join(user_configs[user_id].scan_types)}\n"
            f"🕸️ Depth: {depth}\n\n"
            "Configure other scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "config_threads":
        # Show thread configuration options
        keyboard = [
            [
                InlineKeyboardButton("1 (Slowest)", callback_data="threads_1"),
                InlineKeyboardButton("3", callback_data="threads_3"),
                InlineKeyboardButton("5 (Faster)", callback_data="threads_5"),
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_config")],
        ]
        query.edit_message_text(
            f"Current threads: {user_configs[user_id].threads}\n\n"
            "Select number of threads (higher values are faster but may trigger rate limiting):",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return CONFIGURING_SCAN
    
    elif query.data.startswith("threads_"):
        # Set threads
        threads = int(query.data.replace("threads_", ""))
        user_configs[user_id].threads = threads
        query.answer(f"Threads set to {threads}")
        
        # Return to main config
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n"
            f"🔍 Scan Types: {', '.join(user_configs[user_id].scan_types)}\n"
            f"🕸️ Depth: {user_configs[user_id].depth}\n"
            f"🔄 Threads: {threads}\n\n"
            "Configure other scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "config_timeout":
        # Show timeout configuration options
        keyboard = [
            [
                InlineKeyboardButton("5s (Fast)", callback_data="timeout_5"),
                InlineKeyboardButton("10s", callback_data="timeout_10"),
                InlineKeyboardButton("20s (Thorough)", callback_data="timeout_20"),
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_config")],
        ]
        query.edit_message_text(
            f"Current timeout: {user_configs[user_id].timeout}s\n\n"
            "Select request timeout in seconds:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return CONFIGURING_SCAN
    
    elif query.data.startswith("timeout_"):
        # Set timeout
        timeout = int(query.data.replace("timeout_", ""))
        user_configs[user_id].timeout = timeout
        query.answer(f"Timeout set to {timeout}s")
        
        # Return to main config
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n"
            f"🔍 Scan Types: {', '.join(user_configs[user_id].scan_types)}\n"
            f"🕸️ Depth: {user_configs[user_id].depth}\n"
            f"🔄 Threads: {user_configs[user_id].threads}\n"
            f"⏱️ Timeout: {timeout}s\n\n"
            "Configure other scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "config_verbose":
        # Toggle verbose mode
        user_configs[user_id].verbose = not user_configs[user_id].verbose
        status = "enabled" if user_configs[user_id].verbose else "disabled"
        query.answer(f"Verbose mode {status}")
        
        # Return to main config
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n"
            f"🔍 Scan Types: {', '.join(user_configs[user_id].scan_types)}\n"
            f"🕸️ Depth: {user_configs[user_id].depth}\n"
            f"🔄 Threads: {user_configs[user_id].threads}\n"
            f"⏱️ Timeout: {user_configs[user_id].timeout}s\n"
            f"🔊 Verbose: {status}\n\n"
            "Configure other scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "config_aggressive":
        # Toggle aggressive mode
        user_configs[user_id].aggressive = not user_configs[user_id].aggressive
        status = "enabled" if user_configs[user_id].aggressive else "disabled"
        query.answer(f"Aggressive mode {status}")
        
        # Return to main config
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n"
            f"🔍 Scan Types: {', '.join(user_configs[user_id].scan_types)}\n"
            f"🕸️ Depth: {user_configs[user_id].depth}\n"
            f"🔄 Threads: {user_configs[user_id].threads}\n"
            f"⏱️ Timeout: {user_configs[user_id].timeout}s\n"
            f"🔊 Verbose: {'enabled' if user_configs[user_id].verbose else 'disabled'}\n"
            f"⚡ Aggressive: {status}\n\n"
            "Configure other scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN
    
    elif query.data == "cancel_scan":
        # Cancel the scan
        query.edit_message_text("❌ Scan cancelled.")
        return ConversationHandler.END
    
    elif query.data == "new_scan":
        # Start a new scan
        query.edit_message_text("Starting a new scan...")
        
        # Initialize new scan configuration for this user
        user_configs[user_id] = ScanArgs()
        user_configs[user_id].scan_types = ["info", "headers", "ssl"]  # Default to safer scan types
        user_configs[user_id].verbose = True
        user_configs[user_id].show_progress = True
        user_configs[user_id].threads = 3
        user_configs[user_id].depth = 1
        user_configs[user_id].timeout = 10
        
        context.bot.send_message(
            chat_id=user_id,
            text="🔍 Let's start a new website vulnerability scan.\n\n"
                "Please enter the URL you want to scan (e.g., https://example.com):\n\n"
                "Make sure to include the full URL with http:// or https://"
        )
        
        return ENTERING_URL
    
    else:
        # Unknown callback data
        query.edit_message_text(
            f"🎯 Target: {user_configs[user_id].url}\n\n"
            "Configure your scan options:",
            reply_markup=get_scan_config_keyboard()
        )
        return CONFIGURING_SCAN

@restricted
def status_command(update: Update, context: CallbackContext) -> None:
    """Check the status of ongoing scans."""
    user_id = update.effective_user.id
    
    if user_id in active_scans:
        scan_info = active_scans[user_id]
        status = scan_info["status"]
        target = scan_info["target"]
        start_time = scan_info["start_time"]
        
        if status == "running":
            duration = (datetime.now() - start_time).total_seconds()
            update.message.reply_text(
                f"🔄 Scan in progress for {target}\n\n"
                f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Duration: {duration:.1f} seconds\n\n"
                "Use /cancel to stop the scan"
            )
        elif status == "completed":
            end_time = scan_info["end_time"]
            duration = (end_time - start_time).total_seconds()
            update.message.reply_text(
                f"✅ Scan completed for {target}\n\n"
                f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Duration: {duration:.1f} seconds"
            )
        elif status == "failed":
            duration = (datetime.now() - start_time).total_seconds()
            error = scan_info.get("error", "Unknown error")
            update.message.reply_text(
                f"❌ Scan failed for {target}\n\n"
                f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Duration: {duration:.1f} seconds\n"
                f"Error: {error}"
            )
    else:
        update.message.reply_text(
            "No recent scans found. Use /scan to start a new scan."
        )

@restricted
def cancel_command(update: Update, context: CallbackContext) -> None:
    """Cancel an ongoing scan."""
    user_id = update.effective_user.id
    
    if user_id in active_scans and active_scans[user_id]["status"] == "running":
        # Mark the scan as cancelled
        active_scans[user_id]["status"] = "cancelled"
        target = active_scans[user_id]["target"]
        update.message.reply_text(
            f"⚠️ Attempting to cancel scan for {target}...\n\n"
            "Note: The scan process may take a moment to fully terminate."
        )
    else:
        update.message.reply_text(
            "No active scans to cancel. Use /status to check scan status."
        )

@restricted
def cancel_conversation(update: Update, context: CallbackContext) -> int:
    """Cancel the current conversation."""
    update.message.reply_text(
        "⚠️ Operation cancelled. Use /scan to start a new scan."
    )
    return ConversationHandler.END

def error_handler(update, context):
    """Handle errors in the dispatcher."""
    logger.error(f"Exception while handling an update: {context.error}")
    
    # Send error message to the user if possible
    if update and isinstance(update, Update) and update.effective_chat:
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ An error occurred: {context.error}"
        )

def cleanup_job(context):
    """Periodic job to cleanup old resources and inactive users."""
    logger.info("Running scheduled cleanup of inactive resources")
    
    # Clean up user configurations older than 24 hours
    user_configs.cleanup_older_than(86400)  # 24 hours
    
    # Clean up completed or failed scans older than 6 hours
    active_scans.cleanup_older_than(21600)  # 6 hours
    
    # Log memory usage for monitoring
    try:
        import psutil
        process = psutil.Process(os.getpid())
        memory_usage = process.memory_info().rss / 1024 / 1024  # Convert to MB
        logger.info(f"Current memory usage: {memory_usage:.2f} MB")
    except ImportError:
        logger.info("psutil not available, memory usage monitoring disabled")
    
    logger.info(f"Active users in cache: {len(user_configs.cache)}")
    logger.info(f"Active scans in cache: {len(active_scans.cache)}")

def main():
    """Run the bot."""
    # Get the bot token from environment variable
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("⚠️ No TELEGRAM_BOT_TOKEN environment variable found.")
        print("Please set your Telegram bot token using:")
        print("export TELEGRAM_BOT_TOKEN=your_token_here")
        return 1
    
    # Get configuration from environment variables
    max_users = int(os.environ.get("MAX_USERS", "1000000"))
    max_scans = int(os.environ.get("MAX_SCANS", "1000000"))
    max_threads = int(os.environ.get("MAX_THREADS", "100"))
    optimization_level = int(os.environ.get("OPTIMIZATION_LEVEL", "2"))
    
    # Configure memory optimization based on level
    if optimization_level >= 3:
        # Aggressive optimization
        gc.set_threshold(100, 5, 5)  # More frequent garbage collection
    elif optimization_level >= 2:
        # Medium optimization
        gc.set_threshold(700, 10, 10)
    
    # Set up thread pool size based on configuration
    global scan_thread_pool
    scan_thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
    
    # Set up cache sizes based on configuration
    global user_configs, active_scans
    user_configs = LRUCache(max_size=max_users)
    active_scans = LRUCache(max_size=max_scans)
    
    print(f"🚀 Starting WebScan Telegram Bot v{VERSION}")
    logger.info(f"Bot configured to support up to {max_users:,} users and {max_scans:,} concurrent scans")
    logger.info(f"Using thread pool with {max_threads} workers and optimization level {optimization_level}")
    
    # Create the updater and pass it your bot's token
    updater = Updater(token)
    dispatcher = updater.dispatcher
    
    # Add periodic job to clean up resources (run every 30 minutes)
    job_queue = updater.job_queue
    job_queue.run_repeating(cleanup_job, interval=1800, first=300)  # First run after 5 minutes
    
    # Add scheduled garbage collection for high demand scenario
    if optimization_level >= 2:
        job_queue.run_repeating(lambda _: gc.collect(), interval=300, first=60)  # Run GC every 5 minutes
    
    # Create conversation handler for scanning flow
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("scan", scan_command)],
        states={
            ENTERING_URL: [
                MessageHandler(Filters.text & ~Filters.command, url_entered)
            ],
            CONFIGURING_SCAN: [
                CallbackQueryHandler(handle_scan_config)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_conversation)],
    )
    
    # Add command handlers
    dispatcher.add_handler(CommandHandler("start", start_command))
    dispatcher.add_handler(CommandHandler("help", help_command))
    dispatcher.add_handler(CommandHandler("about", about_command))
    dispatcher.add_handler(CommandHandler("status", status_command))
    dispatcher.add_handler(CommandHandler("cancel", cancel_command))
    dispatcher.add_handler(conv_handler)
    
    # Add error handler
    dispatcher.add_error_handler(error_handler)
    
    # Run the bot until the user presses Ctrl-C
    print(f"🚀 Starting WebScan Telegram Bot v{VERSION}")
    
    # Clean up any temporary files from previous runs
    try:
        temp_dir = tempfile.gettempdir()
        for file in os.listdir(temp_dir):
            if file.endswith(".webscan_temp"):
                os.remove(os.path.join(temp_dir, file))
    except Exception as e:
        logger.error(f"Error cleaning up temporary files: {str(e)}")
    
    # Start the Bot
    updater.start_polling()
    updater.idle()
    
    return 0

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description=f"WebScan Telegram Bot v{VERSION}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--token", 
        help="Telegram Bot token (can also be set via TELEGRAM_BOT_TOKEN env var)"
    )
    parser.add_argument(
        "--authorized-users",
        help="Comma-separated list of authorized user IDs (can also be set via AUTHORIZED_USERS env var)"
    )
    
    args = parser.parse_args()
    
    # Set environment variables from command line args if provided
    if args.token:
        os.environ["TELEGRAM_BOT_TOKEN"] = args.token
    if args.authorized_users:
        os.environ["AUTHORIZED_USERS"] = args.authorized_users
    
    sys.exit(main())