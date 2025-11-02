# Web Technology Fingerprinter

A passive + optional active web technology detection tool.

## Author
- **Name**: T4z4r
- **Date**: November 02, 2025
- **Country**: TZ
- **License**: MIT

## Description
This tool analyzes web technologies used by a target website through passive detection (headers, HTML content, cookies) and optional active probing (common paths and files). It detects web servers, frameworks, CMS, databases, JavaScript libraries, programming languages, and other technologies.

## Features
- **Passive Detection**: Analyzes HTTP headers, HTML content, meta tags, scripts, and cookies
- **Active Probing**: Optional mode to probe common paths for additional insights (requires user confirmation)
- **Comprehensive Database**: Supports detection of 50+ technologies across multiple categories
- **JSON/Pretty Output**: Choose between human-readable or machine-readable output
- **Customizable**: Configurable timeout and user-agent

## Installation
1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
```bash
python web_technology_fingerprinter.py [OPTIONS] URL

Options:
  -t, --timeout TIMEOUT    Request timeout in seconds (default: 10)
  -o, --output {pretty,json}  Output format (default: pretty)
  --active                 Enable active probing mode (requires confirmation)
  --no-banner              Hide the tool banner
```

### Examples
```bash
# Basic passive scan
python web_technology_fingerprinter.py https://example.com

# Active scanning with JSON output
python web_technology_fingerprinter.py --active --output json https://example.com

# Custom timeout
python web_technology_fingerprinter.py -t 15 https://example.com
```

## Detected Technologies
- **Web Servers**: Apache, nginx, IIS, Cloudflare, OpenResty, LiteSpeed, etc.
- **Frameworks/CMS**: Django, Laravel, Express, WordPress, Joomla, Drupal, etc.
- **Databases**: MySQL, PostgreSQL, MongoDB, Redis, etc.
- **JavaScript Libraries**: jQuery, React, Vue.js, Angular, Bootstrap, etc.
- **Programming Languages**: PHP, Node.js, Python, Ruby, Java, etc.
- **Analytics/Other**: Google Analytics, Facebook Pixel, Stripe, etc.

## Warning
Active probing mode sends multiple requests to the target. Only use this mode with explicit permission to test the system.

## License
This project is licensed under the MIT License - see the license file for details.