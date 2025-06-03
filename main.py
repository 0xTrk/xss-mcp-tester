from mcp.server.fastmcp import FastMCP
from playwright.async_api import async_playwright
import asyncio
import urllib.request
import urllib.parse
import urllib.error
import ssl

# Create an MCP server
mcp = FastMCP("XSS Vulnerability Tester")

def create_ssl_context():
    """Create SSL context that ignores certificate errors"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

def make_http_request(url: str, method: str = "GET", custom_headers: dict = None):
    """Make simple HTTP request with error handling and custom headers support"""
    ssl_context = create_ssl_context()
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    }
    
    # Add custom headers if provided
    if custom_headers:
        headers.update(custom_headers)
    
    req = urllib.request.Request(url, headers=headers, method=method.upper())
    
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
            content = response.read().decode('utf-8', errors='replace')
            response_headers = dict(response.headers)
            status_code = response.getcode()
            return content, response_headers, status_code, None
    except urllib.error.HTTPError as e:
        try:
            error_content = e.read().decode('utf-8', errors='replace')
            error_headers = dict(e.headers) if hasattr(e, 'headers') else {}
            return error_content, error_headers, e.code, None
        except:
            return "", {}, e.code, f"HTTP Error {e.code}: {e.reason}"
    except Exception as e:
        return "", {}, 0, str(e)

async def test_xss_vulnerability(url: str) -> bool:
    """
    Test if a URL is vulnerable to XSS by checking for any JavaScript execution.
    
    Parameters:
    url (str): The URL to test for XSS vulnerability
    
    Returns:
    bool: True if any JavaScript execution was detected, False otherwise
    """
    js_executed = False
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        # Handle dialogs (alert, confirm, prompt)
        async def handle_dialog(dialog):
            nonlocal js_executed
            js_executed = True
            await dialog.dismiss()
        
        page.on("dialog", handle_dialog)
        
        # Inject detection script to catch ANY JavaScript execution
        await page.add_init_script("""
            // Flag to detect if our XSS payload executed
            window.xssExecuted = false;
            
            // Override common functions used in XSS proofs
            const originalAlert = window.alert;
            window.alert = function(...args) {
                window.xssExecuted = true;
                return originalAlert.apply(this, args);
            };
            
            const originalConfirm = window.confirm;
            window.confirm = function(...args) {
                window.xssExecuted = true;
                return originalConfirm.apply(this, args);
            };
            
            const originalPrompt = window.prompt;
            window.prompt = function(...args) {
                window.xssExecuted = true;
                return originalPrompt.apply(this, args);
            };
            
            const originalConsoleLog = console.log;
            console.log = function(...args) {
                window.xssExecuted = true;
                return originalConsoleLog.apply(this, args);
            };
            
            const originalWrite = document.write;
            document.write = function(...args) {
                window.xssExecuted = true;
                return originalWrite.apply(this, args);
            };
            
            const originalWriteln = document.writeln;
            document.writeln = function(...args) {
                window.xssExecuted = true;
                return originalWriteln.apply(this, args);
            };
            
            // Detect dynamic script creation
            const originalCreateElement = document.createElement;
            document.createElement = function(tagName) {
                const element = originalCreateElement.call(this, tagName);
                if (tagName.toLowerCase() === 'script') {
                    window.xssExecuted = true;
                }
                return element;
            };
        """)
        try:
            # Navigate to the URL
            await page.goto(url, timeout=10000)
            
            # Wait for potential JavaScript execution
            await page.wait_for_timeout(2000)
            
            # Check if any JavaScript was executed
            execution_detected = await page.evaluate("window.xssExecuted || false")
            
            if execution_detected:
                js_executed = True
            
        except Exception as e:
            print(f"Error testing URL {url}: {e}")
        finally:
            await browser.close()
    
    return js_executed

@mcp.tool()
async def test_xss_url(url: str) -> str:
    """
    Test a URL for XSS vulnerabilities by checking if any JavaScript execution is triggered.
    
    This tool accepts a URL (with XSS payloads) and tests if it triggers
    any JavaScript execution including alerts, console.log, document.write, or script creation.
    
    Parameters:
    url (str): The URL to test with XSS payloads in parameters
                Example: "https://example.com/search?q=<script>alert(1)</script>"
                       "https://example.com/search?q=<script>console.log('XSS')</script>"
    
    Returns:
    str: A message indicating whether XSS vulnerability was detected or not
    """
    try:
        result = await test_xss_vulnerability(url)
        
        if result:
            return f"⚠️  XSS VULNERABILITY DETECTED! JavaScript execution triggered on URL: {url}"
        else:
            return f"✅ No XSS vulnerability detected on URL: {url}"
            
    except Exception as e:
        return f"❌ Error testing URL {url}: {str(e)}"

@mcp.tool()
async def get_raw_html_response(url: str, max_length: int = 10000) -> str:
    """
    Get the RAW HTML response using urllib.
    
    Parameters:
    url (str): The URL to fetch raw HTML from
    max_length (int): Maximum length of response to return (default: 10000, set to -1 for full response)
    
    Returns:
    str: Raw HTTP response body exactly as sent by the server
    """
    try:
        content, headers, status_code, error = make_http_request(url)
        
        if error:
            return f"❌ Error fetching raw HTML: {error}"
        
        # Handle truncation based on max_length
        if max_length == -1:
            return f"RAW Response from {url} (FULL RESPONSE - {len(content)} chars):\n{'='*60}\n{content}"
        elif len(content) > max_length:
            truncated = content[:max_length] + f"\n\n... (TRUNCATED! Full length: {len(content)} chars)\n💡 Use max_length=-1 to get full response"
        else:
            truncated = content
            
        return f"RAW Response from {url} ({len(truncated)} chars):\n{'='*60}\n{truncated}"
        
    except Exception as e:
        return f"❌ Error fetching raw HTML: {str(e)}"

@mcp.tool()
async def search_in_html_response(url: str, search_term: str) -> str:
    """
    Search for specific content in HTML response.
    
    Parameters:
    url (str): The URL to fetch and search
    search_term (str): The term to search for in the HTML response
    
    Returns:
    str: Search results with context around matches
    """
    try:
        content, headers, status_code, error = make_http_request(url)
        
        if error:
            return f"❌ Error searching HTML: {error}"
        
        if search_term not in content:
            return f"❌ '{search_term}' NOT found in response from {url}\nTotal response length: {len(content)} chars"
        
        # Find all occurrences with context
        lines = content.split('\n')
        matches = []
        
        for i, line in enumerate(lines):
            if search_term in line:
                # Get context (3 lines before and after)
                start = max(0, i-3)
                end = min(len(lines), i+4)
                context_lines = []
                
                for j in range(start, end):
                    if j == i:
                        context_lines.append(f">>> LINE {j+1}: {lines[j]}")
                    else:
                        context_lines.append(f"    LINE {j+1}: {lines[j]}")
                
                matches.append(f"MATCH #{len(matches)+1}:\n" + "\n".join(context_lines))
        
        result_text = f"🎯 Found '{search_term}' {len(matches)} time(s) in response from {url}\n"
        result_text += f"📄 Total response length: {len(content)} chars\n"
        result_text += "=" * 60 + "\n"
        result_text += "\n\n".join(matches)
        
        return result_text
        
    except Exception as e:
        return f"❌ Error searching HTML: {str(e)}"

@mcp.tool()
async def get_javascript_file(js_url: str) -> str:
    """
    Fetch a JavaScript file for manual analysis.
    
    This tool fetches JavaScript files that the AI finds in HTML source code.
    The AI can then analyze the code for potential vulnerabilities like DOM XSS.
    
    Parameters:
    js_url (str): The URL of the JavaScript file to fetch
                  Example: "https://example.com/assets/script.js"
    
    Returns:
    str: The JavaScript source code for AI analysis
    """
    try:
        content, headers, status_code, error = make_http_request(js_url)
        
        if error:
            return f"❌ Error fetching JavaScript file: {error}"
        
        # Check if it looks like JavaScript
        if not any(keyword in content.lower() for keyword in ['function', 'var ', 'let ', 'const ', 'jquery', '$(']):
            return f"⚠️  Warning: File doesn't appear to contain JavaScript code.\n\nContent from {js_url}:\n{'='*60}\n{content}"
        
        return f"JavaScript file from {js_url} ({len(content)} chars):\n{'='*60}\n{content}"
        
    except Exception as e:
        return f"❌ Error fetching JavaScript file: {str(e)}"

@mcp.tool()
async def get_http_headers(url: str) -> str:
    """
    Get HTTP response headers from a URL for security analysis.
    
    This tool fetches HTTP response headers to analyze security protections
    like CSP (Content-Security-Policy), X-Frame-Options, etc.
    
    Parameters:
    url (str): The URL to get headers from
    
    Returns:
    str: HTTP response headers for security analysis
    """
    try:
        content, response_headers, status_code, error = make_http_request(url)
        
        if error:
            return f"❌ Error fetching headers: {error}"
        
        # Format headers for analysis
        result = f"HTTP Response Headers from {url} (Status: {status_code}):\n{'='*60}\n"
        
        for header_name, header_value in response_headers.items():
            result += f"{header_name}: {header_value}\n"
        
        return result
        
    except Exception as e:
        return f"❌ Error fetching headers: {str(e)}"

@mcp.tool()
async def make_custom_http_request(url: str, method: str = "GET", headers: str = "", max_length: int = 10000) -> str:
    """
    Make HTTP request with custom headers (useful for authenticated requests with cookies/sessions).
    
    Parameters:
    url (str): The URL to request
    method (str): HTTP method (GET, POST, etc.)
    headers (str): Custom headers in format "Header1: Value1\\nHeader2: Value2\\nCookie: session=abc123"
    max_length (int): Maximum length of response to return (default: 10000, set to -1 for full response)
    
    Returns:
    str: HTTP response with status and headers
    """
    try:
        # Parse custom headers
        custom_headers = {}
        if headers.strip():
            for line in headers.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    custom_headers[key.strip()] = value.strip()
        
        content, response_headers, status_code, error = make_http_request(url, method, custom_headers)
        
        if error:
            return f"❌ Error making custom request: {error}"
        
        # Format response
        result = f"Custom HTTP {method.upper()} Response from {url} (Status: {status_code}):\n"
        result += f"Request Headers Used:\n"
        for k, v in custom_headers.items():
            result += f"  {k}: {v}\n"
        result += f"\nResponse Headers:\n"
        for k, v in response_headers.items():
            result += f"  {k}: {v}\n"
        result += f"\nResponse Body ({len(content)} chars):\n{'='*60}\n"
        
        # Handle truncation
        if max_length == -1:
            result += content
        elif len(content) > max_length:
            result += content[:max_length] + f"\n\n... (TRUNCATED! Full length: {len(content)} chars)\n💡 Use max_length=-1 to get full response"
        else:
            result += content
            
        return result
        
    except Exception as e:
        return f"❌ Error making custom request: {str(e)}"

if __name__ == "__main__":
    mcp.run()