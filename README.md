# SQLcrack v1.2.0

**Advanced SQL Injection Vulnerability Scanner & DBMS Fingerprinting Tool**

SQLcrack is a powerful, feature-rich command-line tool designed for security professionals and penetration testers to identify SQL injection vulnerabilities in web applications. With support for multiple injection techniques, DBMS fingerprinting, and advanced payload customization, SQLcrack provides comprehensive SQL injection assessment capabilities.

---

## Features

✅ **Multiple Injection Techniques**
- UNION-based SQL Injection
- Time-based Blind SQL Injection
- Error-based SQL Injection
- Stacked Queries Injection
- Boolean-based Blind SQL Injection

✅ **DBMS Fingerprinting & Detection**
- Automatic database identification (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- DBMS characteristics analysis
- Version detection

✅ **Advanced Payload Management**
- 5 configurable payload categories
- Multi-level testing (Level 1-5)
- Risk assessment (Risk 1-3)
- Custom payload injection techniques

✅ **Session & State Management**
- Session persistence
- Scan history tracking
- Flush and reset capabilities

✅ **Flexible Configuration**
- Support for GET/POST/PUT/DELETE methods
- Custom headers and cookies
- POST data manipulation
- Cookie-based authentication

✅ **Verbosity & Debugging**
- 4-level verbosity output (0-3)
- Real-time payload logging
- Detailed scan reports
- Batch mode for automation

✅ **Cross-Platform Compatibility**
- Linux/Ubuntu
- Termux (Android)
- Windows (CMD/PowerShell)
- macOS

---

## Installation

### Prerequisites
- Python 3.6+
- pip package manager

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/azkalangga1-netizen/SQLCRACK.git
   cd sqlcrack
   ```

2. **Install dependencies**
   ```bash
   pip install requests
   ```

3. **Make executable (Linux/macOS)**
   ```bash
   chmod +x sqlcrack.py
   ```

4. **Run the tool**
   ```bash
   python3 sqlcrack.py -a
   ```

---

## Usage

### Basic Syntax
```bash
python3 sqlcrack.py -f <TARGET_URL> [OPTIONS]
```

### Quick Start Examples

**Simple GET parameter scan:**
```bash
python3 sqlcrack.py -f "http://target.com/page.php?id=1"
```

**POST form submission:**
```bash
python3 sqlcrack.py -f "http://target.com/login" \
  --method POST \
  --data "username=admin&password=123"
```

**DBMS fingerprinting:**
```bash
python3 sqlcrack.py -f "http://target.com/search?q=test" \
  --fingerprint --level 3
```

**Custom technique with authentication:**
```bash
python3 sqlcrack.py -f "http://target.com/api/users" \
  --technique union,time-based \
  --cookie "session=abc123def456" \
  --level 2 --risk 1
```

**Verbose debug mode:**
```bash
python3 sqlcrack.py -f "http://target.com/product?id=5" \
  -v 2 --batch
```

**Read HTTP request from file:**
```bash
python3 sqlcrack.py -r request.txt --batch
```

**View version information:**
```bash
python3 sqlcrack.py --version
```

**Clear session data:**
```bash
python3 sqlcrack.py --flush-session
```

---

## Parameters Reference

### Primary Parameters
| Parameter | Description | Example |
|-----------|-------------|---------|
| `-f, --file URL` | Target URL for testing (REQUIRED) | `-f "http://target.com/page?id=1"` |
| `-r, --request FILE` | Read HTTP request from file | `-r request.txt` |
| `-v, --verbose LEVEL` | Output verbosity (0-3, default: 1) | `-v 2` |

### Payload Configuration
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--data DATA` | POST data to send | `--data "user=admin&pass=123"` |
| `--method METHOD` | HTTP method (GET/POST/PUT/DELETE) | `--method POST` |
| `--headers HEADERS` | Custom headers (JSON format) | `--headers '{"X-Custom": "value"}'` |
| `--cookie COOKIE` | Authentication cookie | `--cookie "session=abc123"` |

### Testing Options
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--level LEVEL` | Test level (1-5, default: 1) | `--level 3` |
| `--risk RISK` | Risk level (1-3, default: 1) | `--risk 2` |
| `--technique TECH` | Techniques (comma-separated) | `--technique union,time-based` |
| `--fingerprint` | Identify DBMS type | `--fingerprint` |

### Optimization
| Parameter | Description |
|-----------|-------------|
| `--batch` | Use default answers automatically |
| `--flush-session` | Clear stored session data |

### Information
| Parameter | Description |
|-----------|-------------|
| `-a, --help` | Show detailed help menu |
| `--version` | Show version & update info |

---

## Test Levels Explained

| Level | Description | Speed | Coverage |
|-------|-------------|-------|----------|
| **Level 1** | Basic payloads (fast) | ⚡⚡⚡⚡⚡ | Basic targets |
| **Level 2** | Medium payloads (character modifications) | ⚡⚡⚡⚡ | Standard targets |
| **Level 3** | Advanced payloads (WAF bypass) | ⚡⚡⚡ | Protected systems |
| **Level 4** | Extreme payloads (fuzzing, multi-encoding) | ⚡⚡ | Hardened targets |
| **Level 5** | Maximum payloads (all variations) | ⚡ | Comprehensive scan |

---

## Risk Levels Explained

| Risk | Type | Payloads |
|-----|------|----------|
| **Risk 1** | Safe (Read-only) | SELECT queries only |
| **Risk 2** | Moderate | INSERT, UPDATE statements |
| **Risk 3** | Dangerous | DROP, DELETE, command execution |

---

## Injection Techniques

### UNION-Based
Extracts data by appending UNION SELECT statements. Most reliable when column count matches.

### Time-Based Blind
Uses SLEEP/BENCHMARK functions to detect boolean responses through timing delays.

### Error-Based
Leverages database error messages to extract information from error responses.

### Stacked Queries
Executes multiple SQL statements sequentially (semicolon-separated).

### Boolean-Based
Determines true/false conditions to extract data bit-by-bit from responses.

---

## Output Examples

### Successful Scan
```
[+] [12:34:56] Connection OK - Status: 200
[+] [12:34:57] DBMS Detected: MySQL
[*] [12:34:58] Testing UNION-based technique...
[+] [12:34:59] VULNERABLE! Technique: union
[+] [12:35:00] Payload: ' UNION SELECT database(),user(),version(),NULL--

============================================================
SCAN RESULTS
============================================================

[!] TARGET VULNERABLE TO SQL INJECTION

Vulnerabilities Found:

  [1] Technique: UNION
      Payload: ' UNION SELECT database(),user(),version(),NULL--
      Time: 2026-10-11T12:35:00
```

### No Vulnerabilities Found
```
[+] No SQL Injection Vulnerabilities Detected
```

---

## Real-World Use Cases

1. **Web Application Security Audit**
   ```bash
   python3 sqlcrack.py -f "http://webapp.com/search" --level 2 --fingerprint
   ```

2. **Penetration Testing with Authentication**
   ```bash
   python3 sqlcrack.py -f "http://internal.app/api" \
     --cookie "auth_token=xyz123" --technique union --level 3
   ```

3. **WAF Bypass Testing**
   ```bash
   python3 sqlcrack.py -f "http://protected.site/query" \
     --level 5 --risk 1 --verbose 2
   ```

4. **Batch Scanning Multiple Endpoints**
   ```bash
   for url in $(cat urls.txt); do
     python3 sqlcrack.py -f "$url" --batch --level 1
   done
   ```

---

## Platform-Specific Instructions

### Linux/Ubuntu
```bash
python3 sqlcrack.py -f "http://target.com/page?id=1"
```

### Termux (Android)
```bash
# Install Python if not already installed
pkg install python3

# Clone and run
git clone https://github.com/azkalangga1-netizen/SQLCRACK.git
cd sqlcrack
pip install requests
python3 sqlcrack.py -f "http://target.com/page?id=1"
```

### Windows (CMD/PowerShell)
```batch
python sqlcrack.py -f "http://target.com/page.php?id=1"
```

### macOS
```bash
python3 sqlcrack.py -f "http://target.com/page?id=1"
```

---

## Important Notes

### Session Management
- Session data is automatically saved to `~/.sqlcrack_session`
- Use `--flush-session` to clear session history
- Session data persists across scans for reference

### Rate Limiting
- Tool implements 0.5-second delays between requests
- Prevents server overload and detection
- Can be modified in source code if needed

### Custom Headers
Headers must be valid JSON format:
```bash
python3 sqlcrack.py -f "http://target.com/api" \
  --headers '{"X-API-Key": "secret123", "User-Agent": "Custom"}'
```

### POST Data Format
Data should be URL-encoded:
```bash
--data "param1=value1&param2=value2&param3=value3"
```

---

## Disclaimer

⚠️ **LEGAL WARNING**

SQLcrack is intended **exclusively for authorized security testing** on systems you own or have explicit written permission to test.

**Unauthorized access to computer systems is ILLEGAL** under laws including:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

**User Responsibilities:**
- Obtain written authorization before testing
- Only test on systems you own or have permission to assess
- Do not use for malicious purposes
- Comply with all applicable laws and regulations

**The authors and contributors are NOT responsible for:**
- Unauthorized system access
- Data loss or corruption
- Legal consequences of misuse
- Any damages resulting from this tool

By using SQLcrack, you acknowledge and accept these terms.

---

## Technical Requirements

### System Requirements
- 512MB RAM (minimum)
- 50MB disk space
- Network connectivity

### Python Packages
- `requests` - HTTP library for making requests
- Built-in Python libraries (sys, argparse, urllib, json, re, os, datetime)

### Network Requirements
- Outbound HTTP/HTTPS access
- No firewall restrictions on target communication

---

## Troubleshooting

### Connection Timeout
```bash
# Increase timeout by modifying timeout parameter in code
# Default: 10 seconds
```

### Target Not Responding
- Verify target URL is accessible
- Check network connectivity
- Confirm target is not blocking Python requests

### No Vulnerabilities Found
- Target may have proper input validation
- Try different levels (1-5)
- Try different techniques
- Verify target is actually vulnerable

### Permission Denied Error
```bash
chmod +x sqlcrack.py
```

---

## Performance Tips

1. **Start with Level 1** for faster initial scan
2. **Use specific techniques** if you know the type
3. **Enable --batch mode** to skip confirmations
4. **Use -v 0** for silent mode (production)
5. **Run in tmux/screen** for long scans

---

## Future Enhancements

- [ ] SQLi UNION column auto-detection
- [ ] WAF detection and evasion
- [ ] Proxy support (Burp, ZAP integration)
- [ ] Output formats (JSON, XML, HTML reports)
- [ ] API mode for programmatic access
- [ ] GUI interface
- [ ] Database payload export

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed descriptions

---

## License

This project is licensed under the **MIT License** - see LICENSE file for details.

---

## Support & Documentation

- **GitHub Issues**: https://github.com/AZzykJa/sqlcrack/issues
- **Documentation**: https://github.com/AZzykJa/sqlcrack/wiki
- **Bug Reports**: GitHub Issues tab

---

## Version History

### v1.2.0 (Latest)
- ASCII art banner
- Full DBMS fingerprinting
- All 15 parameters implemented
- Session persistence
- Real SQL injection testing

### v1.1.0
- Multiple technique support
- Level and risk configuration

### v1.0.0
- Initial release
- Basic SQL injection testing

---

## Author

**AZzykJa** - Independent Security Researcher & Developer

---

## Disclaimer Note

SQLcrack is provided "as-is" without warranty of any kind. Users assume all responsibility for compliance with laws and regulations. The tool is designed for ethical security testing only.

**Happy Testing! 🔐**

---

*Last Updated: 2026-10-11*
*For updates, visit:https://github.com/azkalangga1-netizen/SQLCRACK.git
