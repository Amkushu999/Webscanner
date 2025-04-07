<<<<<<< HEAD
# WebScan - Advanced Website Vulnerability Scanner

An advanced Python-powered website vulnerability scanning tool that provides comprehensive security assessments with intelligent detection and reporting capabilities.

## Key Features

- **Python-based Scanning Framework**: Multi-threaded scanning engine for efficient analysis
- **Real-world Vulnerability Detection**: Uses genuine exploitation techniques for reliable results
- **Comprehensive Security Testing**: Multiple scan modules for different vulnerability types
- **Detailed Reporting**: Risk-based reporting with actionable insights
- **Telegram Bot Integration**: Run scans remotely and receive notifications
- **High-Performance Architecture**: Designed to handle over 1 million concurrent instances

## Available Scan Types

- **SQL Injection**: Detects database vulnerabilities with advanced payloads
- **Cross-Site Scripting (XSS)**: Identifies script injection vulnerabilities
- **Directory Traversal**: Tests for unauthorized file access vulnerabilities
- **Sensitive File Exposure**: Scans for configuration files, backups, and logs
- **Port Scanning**: Identifies open ports and services
- **SSL/TLS Analysis**: Detects weak ciphers and protocol vulnerabilities
- **HTTP Header Analysis**: Examines security headers and configurations
- **Information Disclosure**: Identifies leaked information and metadata

## Installation

No special installation required. Simply clone or download the repository.

## Dependencies

- Python 3.7+
- requests
- beautifulsoup4
- colorama
- python-telegram-bot (for Telegram integration)
- trafilatura (optional, for better content extraction)
- dnspython (optional, for enhanced DNS reconnaissance)

Install dependencies with pip.

## Usage

### Command Line Usage

Run the standalone scanner against a target website:

```
python webscan_standalone.py https://example.com --scan-type all -v
```

Common options:
- --scan-type TYPE: Specify scan types (sqli,xss,port,dir,files,headers,ssl,info)
- -v/--verbose: Enable verbose output
- -t/--threads NUM: Set number of threads (default: 5)
- -d/--depth NUM: Set scan depth (default: 2)
- --aggressive: Enable more aggressive scanning techniques

### Telegram Bot Integration

The Telegram bot allows you to run scans remotely and receive notifications when scans are complete. The interactive interface allows full configuration of scan parameters through a conversation-like experience.

#### Setup

1. Create a new Telegram bot by talking to @BotFather on Telegram and get your bot token
2. (Optional) Find your Telegram user ID by talking to @userinfobot
3. Run the Telegram bot:

```
# Run for anyone to use
python run_telegram_bot.py --token YOUR_BOT_TOKEN

# Run with restricted access (recommended)
python run_telegram_bot.py --token YOUR_BOT_TOKEN --users USER_ID1,USER_ID2
```

Alternatively, set environment variables:

```
export TELEGRAM_BOT_TOKEN=your_bot_token
export AUTHORIZED_USERS=12345678,87654321
python run_telegram_bot.py
```

#### Advanced Performance Options

For high-scale deployments, the following options are available:

```
python run_telegram_bot.py --max-users 1000000 --max-scans 1000000 --max-threads 100 --optimization-level 2
```

- `--max-users`: Maximum number of users to support (default: 1,000,000)
- `--max-scans`: Maximum number of concurrent scans (default: 1,000,000)
- `--max-threads`: Maximum number of concurrent scan threads (default: 100)
- `--optimization-level`: Memory optimization level (1=low, 2=medium, 3=aggressive)

#### Using the Bot

1. Start a conversation with your bot on Telegram by sending the `/start` command
2. Use the `/scan` command to start a new vulnerability scan
3. Enter the target URL when prompted (e.g., https://example.com)
4. Configure your scan through the interactive menu:
   - Select scan types (SQL injection, XSS, port scanning, SSL analysis, etc.)
   - Set scan depth, thread count, timeout values
   - Enable/disable verbose or aggressive mode
5. Review and confirm your scan configuration
6. The bot will run the scan and send you a summary of findings
7. Choose to view a detailed report or run another scan

#### Bot Commands

- `/start` - Initialize the bot and display welcome message
- `/scan` - Start a new website vulnerability scan
- `/help` - Display available commands and usage information
- `/about` - Show information about the bot and its capabilities
- `/status` - Check status of current scans (if any are running)
- `/cancel` - Cancel an ongoing scan

#### Interactive Scan Configuration

The bot provides an interactive menu system for configuring scans:

1. **Scan Types**: Choose from various vulnerability scans:
   - All scan types (comprehensive)
   - SQL Injection (database vulnerabilities)
   - Cross-Site Scripting (injection attacks)
   - Open Port Scanning (service detection)
   - Directory Traversal (path manipulation)
   - Sensitive Files (configs, backups, logs)
   - HTTP Headers (security header issues)
   - SSL/TLS (weak ciphers, protocols)
   - Information Disclosure (metadata, paths)

2. **Scan Parameters**:
   - Configure scan depth (how many levels deep to crawl)
   - Set thread count (for performance)
   - Adjust timeout values
   - Enable/disable verbose mode
   - Toggle aggressive scanning techniques

3. **Reporting**:
   - Receive summary reports directly in Telegram
   - View vulnerability details with severity ratings
   - Get recommendations for remediation

## Warning

This tool is designed for security testing with permission. Using it against targets without explicit permission may be illegal. Always have proper authorization before scanning any website.

## Author

Developed by AMKUSH

## License

This project is available for educational purposes only.
=======
# Webscanner
>>>>>>> da96f37a3ee2a73d7ce8e8aa2b6ac3c6fbb2b855
