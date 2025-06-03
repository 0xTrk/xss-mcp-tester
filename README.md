# xss-mcp-tester
For an explanation and POC of what this mcp server does, please visit my article on medium : [LINK]. But globally, it's an MCP server for performing XSS tests with AI.  

## Installation (for Vscode but overall it's the same thing)

### Prerequisites
- Python 3.8+
- [uv](https://github.com/astral-sh/uv) package manager

#### Install uv (if not already installed)
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/xss-tester-mcp.git
cd xss-tester-mcp
```

2. **Initialize the project**
```bash
# Initialize uv project
uv init

# Install dependencies
uv add mcp playwright fastmcp

# Install Playwright browsers
uv run playwright install chromium
```

3. **Verify installation**
```bash
uv pip list
```

### Configuration

Add the following to your MCP client configuration file:

```json
{
  "mcpServers": {
    "XSS tester": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp[cli]",
        "--with",
        "playwright", 
        "mcp",
        "run",
        "/path/to/your/project/main.py"
      ]
    }
  }
}
```

### Testing
Start the MCP server in VSCode:

Press Ctrl+Shift+P (or Cmd+Shift+P on Mac)
Type "MCP: List Server" and select it
Choose your XSS tester server from the list and run it 

=> Go to chat, set AI as agent, and let's go



## Available Tools

### 🔍 `test_xss_url`
Tests a URL for XSS vulnerabilities by checking if JavaScript execution is triggered.
- **Input**: URL with XSS payloads (e.g., `https://example.com/search?q=<script>alert(1)</script>`)
- **Output**: Detects if any JavaScript execution occurs (alerts, console.log, document.write, etc.)

### 📄 `get_raw_html_response`
Fetches the raw HTML response from a URL using urllib.
- **Input**: URL and optional max_length parameter
- **Output**: Raw HTTP response body as sent by the server
- **Features**: Truncation control, full response option

### 🔎 `search_in_html_response`
Searches for specific content within HTML responses.
- **Input**: URL and search term
- **Output**: Search results with context (3 lines before/after matches)
- **Use case**: Finding specific strings, tokens, or patterns in responses

### 📜 `get_javascript_file`
Fetches JavaScript files for manual vulnerability analysis.
- **Input**: JavaScript file URL
- **Output**: JavaScript source code for AI analysis
- **Use case**: Analyzing JS files for DOM XSS vulnerabilities

### 🔧 `get_http_headers`
Retrieves HTTP response headers for security analysis.
- **Input**: URL
- **Output**: All HTTP response headers
- **Use case**: Analyzing security protections (CSP, X-Frame-Options, etc.)

### 🎯 `make_custom_http_request`
Makes HTTP requests with custom headers (authentication, cookies, sessions).
- **Input**: URL, method, custom headers string, max_length
- **Headers format**: `"Header1: Value1\nHeader2: Value2\nCookie: session=abc123"`
- **Output**: Full HTTP response with request/response headers
- **Use case**: Testing authenticated endpoints, session-based vulnerabilities
