# ofCORS
"Of course I tested CORS!", or ofCORS for short, is a comprehensive automated CORS tester for highlighting potential CORS vulnerabilities in web applications.

## Features

- **Comprehensive Testing**: Tests against 20+ carefully crafted malicious origin variations
- **Multi-Method Support**: Tests CORS with different HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
- **PoC Generation**: Creates ready-to-use HTML exploit files for discovered vulnerabilities
- **Batch Processing**: Multi-threaded testing of multiple URLs from file input
- **Detailed Reporting**: Comprehensive reports in text or JSON format

## Installation

### Prereqs

- Python 3.6 or higher
- pip (Python package installer)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/ofCORS.git
cd ofCORS

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x ofcors.py
```

### Manual Installation

```bash
pip install requests colorama
```

## Usage

### Quick Start

```bash
# Test a single URL
python ofcors.py -u https://api.example.com/data

# Test with authentication
python ofcors.py -u https://api.example.com/user -H "Authorization: Bearer token123"

# Generate comprehensive report with PoCs
python ofcors.py -u https://example.com/api -o report.txt --generate-poc
```

### Advanced Usage

```bash
# Batch test multiple URLs with 10 threads
python ofcors.py -f urls.txt -t 10 --vulnerable-only

# Include cookies and custom headers
python ofcors.py -u https://app.example.com/api \
  --cookies "session=abc123; csrf=xyz789" \
  -H "X-API-Key: secret123" \
  --format json -o results.json

# Verbose output with PoC generation
python ofcors.py -u https://example.com/endpoint \
  -v --generate-poc --sensitive -o detailed_report.txt

# Custom timeout and thread settings
python ofcors.py -f targets.txt -t 15 --timeout 30 --vulnerable-only
```

## Helper

```
usage: ofcors.py [-h] (-u URL | -f FILE) [-o OUTPUT] [--format {text,json}] 
                 [-v] [-t THREADS] [--cookies COOKIES] [-H HEADERS] 
                 [--vulnerable-only] [--generate-poc] [--sensitive] 
                 [--timeout TIMEOUT] [--version]

ofCORS - Advanced CORS Vulnerability Scanner

required arguments:
  -u, --url URL          Target URL to test
  -f, --file FILE        File containing URLs (one per line, # for comments)

optional arguments:
  -o, --output OUTPUT    Output file for results
  --format {text,json}   Output format (default: text)
  -v, --verbose          Show detailed output including headers
  -t, --threads THREADS  Number of concurrent threads (default: 5)
  --cookies COOKIES      Cookies: 'name1=value1; name2=value2'
  -H, --headers HEADERS  Additional headers: 'Name: Value'
  --vulnerable-only      Show only vulnerable configurations
  --generate-poc         Generate HTML proof-of-concept files
  --sensitive            Include tests for sensitive data scenarios
  --timeout TIMEOUT      Request timeout in seconds (default: 10)
  --version              Show program's version number and exit
```

### Example Usage

```bash
# Basic scan
ofcors.py -u https://api.example.com/users

# Authenticated scan with custom headers
ofcors.py -u https://app.example.com/api/data \
  --cookies "sessionid=abc123; csrftoken=xyz789" \
  -H "Authorization: Bearer eyJ0eXAi..." \
  -H "X-Requested-With: XMLHttpRequest"

# Batch testing with custom settings
ofcors.py -f urls.txt -t 10 --timeout 15 --vulnerable-only -o results.txt

# Generate full report with PoCs
ofcors.py -u https://example.com/api --generate-poc -v -o full_report.txt

# JSON output for automation
ofcors.py -f targets.txt --format json -o results.json --vulnerable-only
```

## Vulnerability Detection

ofCORS identifies several types of CORS misconfigurations with detailed severity analysis:

### Critical Severity
**Wildcard with Credentials**
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
- **Impact**: Complete bypass of Same-Origin Policy
- **Risk**: Any malicious site can access authenticated data
- **Note**: Violates CORS specification

### High Severity  
**External Origin Reflection with Credentials**
```http
Origin: https://evil.com
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```
- **Impact**: Account takeover, sensitive data theft
- **Risk**: Attackers can access user accounts from malicious domains

### Medium Severity
**Origin Reflection without Credentials**
```http
Origin: https://attacker.com
Access-Control-Allow-Origin: https://attacker.com
```
- **Impact**: Limited data exposure
- **Risk**: Public data accessible from unauthorized domains

### Low Severity
**Wildcard Origin**
```http
Access-Control-Allow-Origin: *
```
- **Impact**: Minimal (no credentials)
- **Risk**: Poor configuration practice

## Examples

### Vulnerable Configuration Found
```
[HIGH] Testing https://api.example.com/user with Origin: https://evil.com
  GET: Status 200
    VULNERABLE - HIGH
    - Origin 'https://evil.com' is reflected in Access-Control-Allow-Origin
    - HIGH RISK: External origin reflection with credentials=true

  POST: Status 200
    VULNERABLE - HIGH
    - Origin 'https://evil.com' is reflected in Access-Control-Allow-Origin
    - HIGH RISK: External origin reflection with credentials=true

  OPTIONS: Status 200
    CORS Headers:
    - access-control-allow-origin: https://evil.com
    - access-control-allow-credentials: true
    - access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
```

### Generated PoC Files
When `--generate-poc` is used, ofCORS creates professional HTML files that:
- **Test Vulnerability**: Interactive button to verify CORS misconfiguration
- **Extract Data**: Functional data extraction from vulnerable endpoints  
- **Technical Details**: Complete vulnerability information for reporting
- **Remediation Advice**: Clear guidance on fixing the vulnerability

## Testing Methodology

ofCORS uses a comprehensive testing approach:

### Origin Generation Strategy
1. **Base Malicious Origins**: Standard attack domains (`evil.com`, `attacker.com`, etc.)
2. **Domain Variations**: Subdomain manipulation, TLD changes, character additions
3. **Protocol Switching**: HTTP/HTTPS variations
4. **Bypass Techniques**: Path confusion, userinfo attacks, encoding tricks
5. **Case Variations**: Uppercase/lowercase domain testing

### HTTP Method Testing
- **GET**: Standard data retrieval
- **POST**: Data submission with JSON payload
- **PUT**: Resource updates
- **DELETE**: Resource deletion
- **OPTIONS**: Preflight request analysis

### Advanced Detection
- **Subdomain Analysis**: Intelligent same-site vs cross-site determination
- **Credential Handling**: Proper detection of credential-enabled vulnerabilities

## File Structure

### URL Input File Format
```
# Target URLs for CORS testing
https://api.example.com/users
https://app.example.com/data
https://portal.example.com/admin

# Lines starting with # are ignored
# https://disabled.example.com/test
```

### Report Output
```
ofCORS - CORS Vulnerability Scan Report
========================================

Tool: ofCORS v1.0.0
Date: 20250104_143022
Target URL: https://api.example.com/data

Summary:
- Total Origins Tested: 25
- Vulnerable Origins Found: 3
- Critical Severity Issues: 0
- High Severity Issues: 2
- Medium Severity Issues: 1
- Low Severity Issues: 0

Detailed Results:
================
[Full detailed findings...]

Proof-of-Concept Files:
Generated 3 PoC file(s) in: report_poc/
```

## Responsible Disclosure

**⚠️ IMPORTANT**: This tool is intended for authorized security testing only!!!

### Authorized Use Cases
- Security testing of applications you own
- Bug bounty programs with proper authorization  
- Penetration testing with signed agreements
- Educational purposes and security research

### Legal Considerations
- **Never test systems without explicit permission**
- **Unauthorized testing may violate laws and terms of service**
- **Always obtain written authorization before testing**

### Responsible Reporting
1. **Document findings** with ofCORS reports and PoCs
2. **Report to appropriate contacts** (security teams, bug bounty programs)
3. **Allow reasonable time** for fixes before public disclosure
4. **Follow disclosure policies** of target organizations

## Advanced Config

### Custom Origin Lists
Modify `BASE_MALICIOUS_ORIGINS` in the script to add custom test origins:

```python
BASE_MALICIOUS_ORIGINS = [
    'https://evil.com',
    'https://your-custom-domain.com',
    'https://attacker.example.org'
]
```

### Timeout Tuning
- **Default**: 10 seconds
- **Fast Networks**: 5-7 seconds
- **Slow Targets**: 15-30 seconds
- **Unstable Connections**: 30+ seconds

### Thread Optimization
- **Single Target**: 1 thread
- **Small Batch (< 10 URLs)**: 3-5 threads  
- **Large Batch**: 10-15 threads
- **Powerful Systems**: Up to 20 threads

## Troubleshooting

### Common Issues

**Connection Errors**
```bash
# Increase timeout for slow connections
ofcors.py -u https://slow-site.com --timeout 30
```

**SSL Certificate Issues**
```bash
# The tool handles SSL issues automatically
# No additional configuration needed
```

**Rate Limiting**
```bash
# Reduce threads and increase timeout
ofcors.py -f urls.txt -t 2 --timeout 15
```

**False Positives**
```bash
# Use verbose mode to investigate
ofcors.py -u https://example.com -v
```

## Resources

### CORS Security Resources
- [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger CORS Vulnerabilities](https://portswigger.net/web-security/cors)

### Inspired from:
- [CORScanner](https://github.com/chenjj/CORScanner) - Another CORS vulnerability scanner
- [Corsy](https://github.com/s0md3v/Corsy) - CORS misconfiguration scanner


---

**Disclaimer**: This tool is for authorized security testing only. The authors are not responsible for any misuse or illegal activities. Always ensure you have proper authorization before testing any systems.

---
