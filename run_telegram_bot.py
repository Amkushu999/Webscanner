#!/usr/bin/env python3
"""
WebScan Telegram Bot Launcher

This script runs the WebScan Telegram bot by setting up the required environment
variables and launching the bot script.

Usage:
    python run_telegram_bot.py --token YOUR_TELEGRAM_BOT_TOKEN --users USER_ID1,USER_ID2
    
Or set environment variables before running:
    export TELEGRAM_BOT_TOKEN=your_bot_token
    export AUTHORIZED_USERS=123456789,987654321
    python run_telegram_bot.py
"""

import os
import sys
import argparse
from webscan_telegram_bot import main as bot_main

def main():
    """Run the WebScan Telegram bot."""
    parser = argparse.ArgumentParser(description="WebScan Telegram Bot Launcher")
    
    parser.add_argument(
        "--token",
        help="Telegram Bot Token (can also be set via TELEGRAM_BOT_TOKEN env var)"
    )
    
    parser.add_argument(
        "--users",
        help="Comma-separated list of authorized user IDs (can also be set via AUTHORIZED_USERS env var)"
    )
    
    args = parser.parse_args()
    
    # Set environment variables if provided
    if args.token:
        os.environ["TELEGRAM_BOT_TOKEN"] = args.token
    if args.users:
        os.environ["AUTHORIZED_USERS"] = args.users
    
    # Check if token is available
    if "TELEGRAM_BOT_TOKEN" not in os.environ:
        print("⚠️ No TELEGRAM_BOT_TOKEN found. Please provide it using --token or set the environment variable.")
        print("To create a Telegram bot and get a token:")
        print("1. Open Telegram and search for BotFather")
        print("2. Send /newbot to BotFather and follow the instructions")
        print("3. Copy the token BotFather gives you and use it here")
        return 1
    
    print("🚀 Starting WebScan Telegram Bot...")
    
    try:
        return bot_main()
    except KeyboardInterrupt:
        print("\n⚠️ Bot stopped by user")
        return 0
    except Exception as e:
        print(f"❌ Error starting bot: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())